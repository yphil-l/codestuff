from __future__ import annotations

import ipaddress
import os
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterable, List, Optional

from ..context import ScanContext
from ..models import ArtifactCategory, Finding, Severity
from ..utils import detect_keywords, filetime_to_datetime, path_is_suspicious
from .base import ArtifactScanner

CHEAT_HOST_TOKENS = (
    "aimware",
    "unknowncheats",
    "interwebz",
    "skinchanger",
    "spoof",
    "loader",
    "ragebot",
    "synapse",
    "scriptware",
    "mythic",
    "hydra",
    "cheatengine",
    "cleaner",
)

KNOWN_C2_IPS = {
    "185.193.127.66",
    "45.67.229.220",
    "94.142.241.111",
    "37.120.234.85",
    "23.94.37.211",
}

CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class BrowserArtifactScanner(ArtifactScanner):
    category = ArtifactCategory.BROWSER
    name = "Browser Activity"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            return findings
        findings.extend(self._scan_chrome(context))
        findings.extend(self._scan_firefox(context))
        return findings

    def _scan_chrome(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        local_appdata = os.environ.get("LOCALAPPDATA")
        if not local_appdata:
            return findings
        profile_root = Path(local_appdata) / "Google" / "Chrome" / "User Data"
        if not profile_root.exists():
            return findings
        for history_path in sorted(profile_root.glob("*/History")):
            findings.extend(self._inspect_chrome_history(history_path, history_path.parent.name, context))
        return findings

    def _inspect_chrome_history(self, db_path: Path, profile: str, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        tmp_path = _copy_locked_db(db_path)
        if not tmp_path:
            return findings
        conn: Optional[sqlite3.Connection] = None
        try:
            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 200"
                )
                for url, title, last_visit in cursor.fetchall():
                    timestamp = _chrome_timestamp(last_visit)
                    if not context.within_lookback(timestamp):
                        continue
                    text = f"{url or ''} {title or ''}"
                    if not _matches_indicator(text, context):
                        continue
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category=self.category,
                            title="Suspicious Chrome browsing",
                            location=url or "chrome-history",
                            timestamp=timestamp,
                            description=f"Chrome profile {profile} visited {url or 'unknown URL'}",
                            evidence={
                                "browser": "Chrome",
                                "profile": profile,
                                "title": title or "",
                                "url": url or "",
                            },
                        )
                    )
            except sqlite3.Error:
                pass
            try:
                cursor.execute(
                    "SELECT target_path, tab_url, start_time FROM downloads ORDER BY start_time DESC LIMIT 120"
                )
                for target_path, tab_url, start_time in cursor.fetchall():
                    timestamp = _chrome_timestamp(start_time)
                    if not context.within_lookback(timestamp):
                        continue
                    descriptor = f"{target_path or ''} {tab_url or ''}"
                    if not _matches_indicator(descriptor, context):
                        continue
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category=self.category,
                            title="Suspicious Chrome download",
                            location=target_path or "chrome-download",
                            timestamp=timestamp,
                            description=(
                                f"Chrome profile {profile} downloaded {(Path(target_path).name if target_path else 'a file')}"
                            ),
                            evidence={
                                "browser": "Chrome",
                                "profile": profile,
                                "url": tab_url or "",
                                "target": target_path or "",
                            },
                        )
                    )
            except sqlite3.Error:
                pass
        except sqlite3.Error:
            pass
        finally:
            if conn:
                conn.close()
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return findings

    def _scan_firefox(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        appdata = os.environ.get("APPDATA")
        if not appdata:
            return findings
        profile_root = Path(appdata) / "Mozilla" / "Firefox" / "Profiles"
        if not profile_root.exists():
            return findings
        for profile_dir in profile_root.glob("*"):
            if not profile_dir.is_dir():
                continue
            places_db = profile_dir / "places.sqlite"
            downloads_db = profile_dir / "downloads.sqlite"
            if places_db.exists():
                findings.extend(self._inspect_firefox_places(places_db, profile_dir.name, context))
            if downloads_db.exists():
                findings.extend(self._inspect_firefox_downloads(downloads_db, profile_dir.name, context))
        return findings

    def _inspect_firefox_places(self, db_path: Path, profile: str, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        tmp_path = _copy_locked_db(db_path)
        if not tmp_path:
            return findings
        conn: Optional[sqlite3.Connection] = None
        try:
            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT url, title, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 200"
                )
                for url, title, last_visit in cursor.fetchall():
                    timestamp = _firefox_timestamp(last_visit)
                    if not context.within_lookback(timestamp):
                        continue
                    text = f"{url or ''} {title or ''}"
                    if not _matches_indicator(text, context):
                        continue
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category=self.category,
                            title="Suspicious Firefox browsing",
                            location=url or "firefox-history",
                            timestamp=timestamp,
                            description=f"Firefox profile {profile} visited {url or 'unknown URL'}",
                            evidence={
                                "browser": "Firefox",
                                "profile": profile,
                                "title": title or "",
                                "url": url or "",
                            },
                        )
                    )
            except sqlite3.Error:
                pass
        except sqlite3.Error:
            pass
        finally:
            if conn:
                conn.close()
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return findings

    def _inspect_firefox_downloads(self, db_path: Path, profile: str, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        tmp_path = _copy_locked_db(db_path)
        if not tmp_path:
            return findings
        conn: Optional[sqlite3.Connection] = None
        try:
            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT target, source, endTime FROM moz_downloads ORDER BY endTime DESC LIMIT 150"
                )
                for target, source, end_time in cursor.fetchall():
                    timestamp = _firefox_timestamp(end_time)
                    if not context.within_lookback(timestamp):
                        continue
                    descriptor = f"{target or ''} {source or ''}"
                    if not _matches_indicator(descriptor, context):
                        continue
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category=self.category,
                            title="Suspicious Firefox download",
                            location=target or "firefox-download",
                            timestamp=timestamp,
                            description=(
                                f"Firefox profile {profile} downloaded {(Path(target).name if target else 'a file')}"
                            ),
                            evidence={
                                "browser": "Firefox",
                                "profile": profile,
                                "url": source or "",
                                "target": target or "",
                            },
                        )
                    )
            except sqlite3.Error:
                pass
        except sqlite3.Error:
            pass
        finally:
            if conn:
                conn.close()
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return findings


class WerScanner(ArtifactScanner):
    category = ArtifactCategory.WER
    name = "Windows Error Reporting"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            return findings
        users_root = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        if not users_root.exists():
            return findings
        for user_dir in users_root.iterdir():
            if not user_dir.is_dir():
                continue
            wer_root = user_dir / "AppData" / "Local" / "Microsoft" / "Windows" / "WER"
            findings.extend(self._scan_user_reports(wer_root, user_dir.name, context))
        return findings

    def _scan_user_reports(self, wer_root: Path, username: str, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        for bucket in ("ReportArchive", "ReportQueue"):
            bucket_path = wer_root / bucket
            if not bucket_path.exists():
                continue
            try:
                report_dirs = sorted(
                    (child for child in bucket_path.iterdir() if child.is_dir()),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
            except OSError:
                continue
            for report_dir in report_dirs[:80]:
                report_file = report_dir / "Report.wer"
                if not report_file.exists():
                    continue
                data = _parse_wer_report(report_file)
                if not data:
                    continue
                finding = self._build_finding_from_report(data, username, bucket, report_file, context)
                if finding:
                    findings.append(finding)
        return findings

    def _build_finding_from_report(
        self,
        data: dict[str, str],
        username: str,
        bucket: str,
        report_file: Path,
        context: ScanContext,
    ) -> Optional[Finding]:
        app_name = data.get("AppName") or data.get("FriendlyAppName") or data.get("NsAppName")
        app_path = data.get("AppPath")
        module_path = data.get("ModulePath") or data.get("FaultModulePath") or data.get("Module")
        signature = (data.get("ModuleSignature") or data.get("SigningStatus") or "").lower()
        indicator_hit = _matches_indicator(" ".join(filter(None, [app_name, app_path, module_path])), context)
        suspicious_path = path_is_suspicious(app_path or "") or path_is_suspicious(module_path or "")
        unsigned_module = any(token in signature for token in ("unsigned", "unknown", "invalid"))
        if not (indicator_hit or suspicious_path or unsigned_module):
            return None
        timestamp = (
            _parse_wer_time(data.get("EventTime"))
            or _parse_wer_time(data.get("ReportTimestamp"))
            or datetime.fromtimestamp(report_file.stat().st_mtime, tz=timezone.utc)
        )
        module_name = Path(module_path).name if module_path else (data.get("Module") or "unknown module")
        severity = Severity.HIGH if (indicator_hit or suspicious_path) else Severity.MEDIUM
        description = f"{app_name or 'Application'} crashed with module {module_name}"
        if unsigned_module:
            description += " (unsigned module)"
        evidence = {
            "user": username,
            "app": app_name or "",
            "app_path": app_path or "",
            "module": module_path or "",
            "signature": data.get("ModuleSignature") or signature or "",
            "bucket": bucket,
        }
        return Finding(
            severity=severity,
            category=self.category,
            title="WER crash implicating cheat loader",
            location=f"{username}\\{bucket}",
            timestamp=timestamp,
            description=description,
            evidence=evidence,
        )


class NetworkCacheScanner(ArtifactScanner):
    category = ArtifactCategory.NETWORK_CACHE
    name = "DNS & Network Cache"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            return findings
        dns_output = context.run_command(["ipconfig", "/displaydns"], timeout=90)
        dns_entries = _parse_dns_cache(dns_output.stdout)
        findings.extend(self._analyze_dns_entries(dns_entries, context))
        if not dns_entries and _dns_cache_flushed(dns_output.stdout):
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category=self.category,
                    title="DNS cache appears flushed",
                    location="ipconfig /displaydns",
                    timestamp=datetime.now(timezone.utc),
                    description="DNS resolver cache returned no records and reported it was flushed.",
                )
            )
        arp_output = context.run_command(["arp", "-a"], timeout=45)
        arp_entries = _parse_arp_table(arp_output.stdout)
        findings.extend(self._analyze_arp_entries(arp_entries))
        if not arp_entries and _arp_cache_flushed(arp_output.stdout):
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category=self.category,
                    title="ARP cache appears flushed",
                    location="arp -a",
                    timestamp=datetime.now(timezone.utc),
                    description="ARP cache returned no neighbor entries; cache may have been cleared.",
                )
            )
        return findings

    def _analyze_dns_entries(self, entries: List[dict[str, str]], context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        for entry in entries[:120]:
            name = entry.get("name")
            if not name:
                continue
            address = entry.get("address", "")
            indicator_hit = _matches_indicator(name, context)
            ip_hit = address in KNOWN_C2_IPS
            if not (indicator_hit or ip_hit):
                continue
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category=self.category,
                    title="High-risk DNS cache entry",
                    location=name,
                    timestamp=datetime.now(timezone.utc),
                    description=f"Resolver cache shows {name} -> {address or 'unknown'}",
                    evidence={
                        "address": address or "",
                        "ttl": entry.get("ttl", ""),
                        "source": "DNS",
                    },
                )
            )
        return findings

    def _analyze_arp_entries(self, entries: List[dict[str, str]]) -> List[Finding]:
        findings: List[Finding] = []
        for entry in entries[:80]:
            ip = entry.get("ip")
            if not ip:
                continue
            severity: Optional[Severity] = None
            description = ""
            if ip in KNOWN_C2_IPS:
                severity = Severity.HIGH
                description = "ARP cache contains known cheat/C2 host"
            elif not _is_private_ip(ip):
                severity = Severity.MEDIUM
                description = "ARP cache shows remote peer outside local network"
            if not severity:
                continue
            findings.append(
                Finding(
                    severity=severity,
                    category=self.category,
                    title="Suspicious network cache entry",
                    location=ip,
                    timestamp=datetime.now(timezone.utc),
                    description=description,
                    evidence={
                        "mac": entry.get("mac", ""),
                        "interface": entry.get("interface", ""),
                        "type": entry.get("type", ""),
                        "source": "ARP",
                    },
                )
            )
        return findings


def _matches_indicator(text: str | None, context: ScanContext) -> bool:
    if not text:
        return False
    lowered = str(text).lower()
    if detect_keywords(lowered, context.options.keyword_indicators):
        return True
    return any(token in lowered for token in CHEAT_HOST_TOKENS)


def _copy_locked_db(path: Path) -> Optional[str]:
    try:
        with NamedTemporaryFile(delete=False) as tmp:
            shutil.copyfile(path, tmp.name)
            return tmp.name
    except OSError:
        return None


def _chrome_timestamp(raw) -> datetime:
    try:
        microseconds = int(raw)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
    if microseconds <= 0:
        return datetime.now(timezone.utc)
    return CHROME_EPOCH + timedelta(microseconds=microseconds)


def _firefox_timestamp(raw) -> datetime:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
    if value <= 0:
        return datetime.now(timezone.utc)
    if value > 1_000_000_000_000:
        return datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)
    if value > 1_000_000_000:
        return datetime.fromtimestamp(value / 1_000, tz=timezone.utc)
    return datetime.fromtimestamp(value, tz=timezone.utc)


def _parse_wer_report(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        for line in path.read_text(errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("["):
                continue
            if "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            data[key.strip()] = value.strip()
    except OSError:
        return {}
    return data


def _parse_wer_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    raw = value.strip()
    try:
        base = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    except ValueError:
        return None
    if base > 1_000_000_000_000:
        # Treat as FILETIME (100-ns intervals)
        try:
            return filetime_to_datetime(base)
        except Exception:
            return None
    if base > 1_000_000_000:
        return datetime.fromtimestamp(base / 1_000, tz=timezone.utc)
    if base > 0:
        return datetime.fromtimestamp(base, tz=timezone.utc)
    return None


def _normalize_dns_label(label: str) -> str:
    lowered = label.lower().replace(".", " ")
    return " ".join(lowered.split())


def _parse_dns_cache(output: str) -> List[dict[str, str]]:
    entries: List[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            if current.get("name"):
                entries.append(current)
            current = {}
            continue
        if ":" not in stripped:
            continue
        label, value = stripped.split(":", 1)
        normalized = _normalize_dns_label(label)
        value = value.strip()
        if normalized.startswith("record name"):
            if current.get("name"):
                entries.append(current)
                current = {}
            current["name"] = value
        elif normalized.startswith("record type"):
            current["type"] = value
        elif normalized.startswith("time to live"):
            current["ttl"] = value
        elif "(host) record" in normalized:
            current.setdefault("address", value)
    if current.get("name"):
        entries.append(current)
    return entries


def _parse_arp_table(output: str) -> List[dict[str, str]]:
    entries: List[dict[str, str]] = []
    interface = ""
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if lower.startswith("interface:"):
            interface = stripped.split(":", 1)[1].strip()
            continue
        if lower.startswith("internet address"):
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        candidate = parts[0]
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        entries.append(
            {
                "ip": candidate,
                "mac": parts[1],
                "type": parts[2],
                "interface": interface,
            }
        )
    return entries


def _dns_cache_flushed(output: str) -> bool:
    lowered = output.lower()
    indicators = (
        "could not display the dns resolver cache",
        "could not obtain host information",
        "there are no entries in the dns resolver cache",
        "dns resolver cache is empty",
        "function failed during execution",
    )
    return any(token in lowered for token in indicators)


def _arp_cache_flushed(output: str) -> bool:
    lowered = output.lower()
    return "no arp entries found" in lowered or not output.strip()


def _is_private_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local
