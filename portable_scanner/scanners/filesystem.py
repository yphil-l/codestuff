from __future__ import annotations

import json
import os
import shutil
import sqlite3
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterable, List

from ..context import ScanContext
from ..models import ArtifactCategory, Finding, Severity
from ..utils import detect_keywords, filetime_to_datetime, path_is_suspicious
from .base import ArtifactScanner


class PrefetchAmcacheScanner(ArtifactScanner):
    category = ArtifactCategory.PREFETCH
    name = "Prefetch & Amcache"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            context.log("Prefetch/Amcache collection requires Windows")
            return findings

        findings.extend(self._inspect_prefetch(context))
        findings.extend(self._inspect_amcache(context))
        return findings

    def _inspect_prefetch(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        prefetch_dir = Path(os.environ.get("WINDIR", r"C:\\Windows")) / "Prefetch"
        if not prefetch_dir.exists():
            return [
                Finding(
                    severity=Severity.HIGH,
                    category=self.category,
                    title="Prefetch directory missing",
                    location=str(prefetch_dir),
                    timestamp=datetime.now(timezone.utc),
                    description="Prefetch folder not present; potential anti-forensic action",
                )
            ]

        files = sorted(prefetch_dir.glob("*.pf"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not files:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category=self.category,
                    title="Prefetch cache empty",
                    location=str(prefetch_dir),
                    timestamp=datetime.now(timezone.utc),
                    description="No Prefetch files detected; cache may have been cleared",
                )
            )
            return findings

        suspicious_names = ("JAVA", "POWERSHELL", "CMD", "RUNDLL32", "MSHTA", "REGSVR", "REGASM")
        for pf in files[:120]:
            name = pf.name.upper()
            if any(token in name for token in suspicious_names):
                mtime = datetime.fromtimestamp(pf.stat().st_mtime, tz=timezone.utc)
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category=self.category,
                        title="Suspicious Prefetch entry",
                        location=name,
                        timestamp=mtime,
                        description=f"Prefetch recorded for {name}",
                        evidence={"path": str(pf)},
                    )
                )
        return findings

    def _inspect_amcache(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        amcache_path = Path(os.environ.get("WINDIR", r"C:\\Windows")) / "AppCompat" / "Programs" / "Amcache.hve"
        if not amcache_path.exists():
            return findings

        hive_key = f"TempAmcache_{os.getpid()}"
        loaded = False
        try:
            load = context.run_command(["reg", "load", f"HKLM\\{hive_key}", str(amcache_path)], timeout=60)
            if load.returncode != 0:
                context.log("Unable to load Amcache hive")
                return findings
            loaded = True
            script = textwrap.dedent(
                f"""
                $root = 'Registry::HKEY_LOCAL_MACHINE\\{hive_key}\\Root\\File';
                if (Test-Path $root) {{
                    Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue |
                        ForEach-Object {{
                            try {{
                                $path = $_.GetValue('LowerCaseLongPath')
                                if ($null -ne $path -and $path -is [string]) {{
                                    [PSCustomObject]@{{
                                        Path = $path
                                        LastWriteTime = $_.GetValue('LastWriteTime')
                                    }}
                                }}
                            }} catch {{ }}
                        }} |
                        Select-Object -First 200 |
                        ConvertTo-Json -Compress
                }}
                """
            )
            result = context.run_powershell(script, timeout=300)
            data = _parse_json(result.stdout)
            for entry in data:
                target = entry.get("Path", "")
                last_write_raw = entry.get("LastWriteTime")
                timestamp = _safe_filetime(last_write_raw)
                if not target:
                    continue
                if not Path(target).exists():
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category=self.category,
                            title="Amcache references missing file",
                            location=target,
                            timestamp=timestamp,
                            description="Executable recorded in Amcache is no longer on disk",
                        )
                    )
                elif detect_keywords(target, context.options.keyword_indicators) or path_is_suspicious(target):
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category=self.category,
                            title="Amcache contains high-risk executable",
                            location=target,
                            timestamp=timestamp,
                            description="Matched cheat indicator keyword",
                        )
                    )
        finally:
            if loaded:
                context.run_command(["reg", "unload", f"HKLM\\{hive_key}"], timeout=30)
        return findings


class USNJournalScanner(ArtifactScanner):
    category = ArtifactCategory.USN
    name = "USN Journal"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            return findings

        severity_map = {
            142: (Severity.CRITICAL, "USN journal deleted"),
            98: (Severity.HIGH, "USN journal truncated"),
            2003: (Severity.HIGH, "fsutil delete journal command"),
            2045: (Severity.MEDIUM, "Mass deletion detected"),
        }
        script = textwrap.dedent(
            f"""
            $start = (Get-Date).AddHours(-{context.options.lookback_hours});
            $ids = @(142,98,2003,2045);
            try {{
                Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Ntfs/Operational'; Id=$ids; StartTime=$start}} -MaxEvents 120 |
                    Select-Object Id, TimeCreated, Message |
                    ConvertTo-Json -Compress
            }} catch {{ }}
            """
        )
        result = context.run_powershell(script, timeout=240)
        events = _parse_json(result.stdout)
        for evt in events:
            event_id = evt.get("Id")
            severity, title = severity_map.get(event_id, (Severity.LOW, "USN activity"))
            findings.append(
                Finding(
                    severity=severity,
                    category=self.category,
                    title=title,
                    location=f"Event {event_id}",
                    timestamp=_parse_iso(evt.get("TimeCreated")),
                    description=evt.get("Message", ""),
                )
            )
        return findings


class TaskSchedulerScanner(ArtifactScanner):
    category = ArtifactCategory.TASK_SCHEDULER
    name = "Task Scheduler"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            return findings
        task_root = Path(os.environ.get("WINDIR", r"C:\\Windows")) / "System32" / "Tasks"
        suspicious_tokens = (
            "powershell",
            "-encodedcommand",
            "cmd.exe",
            "clean",
            "del ",
            "rmdir",
            "schtasks",
        )
        for task_file in task_root.rglob("*"):
            if not task_file.is_file():
                continue
            try:
                content = task_file.read_text(errors="ignore")
            except OSError:
                continue
            lowered = content.lower()
            if any(token in lowered for token in suspicious_tokens):
                mtime = datetime.fromtimestamp(task_file.stat().st_mtime, tz=timezone.utc)
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category=self.category,
                        title="Suspicious scheduled task",
                        location=str(task_file.relative_to(task_root)),
                        timestamp=mtime,
                        description="Task definition references high-risk command",
                    )
                )
            elif context.within_lookback(datetime.fromtimestamp(task_file.stat().st_mtime, tz=timezone.utc)):
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category=self.category,
                        title="Task modified within lookback window",
                        location=str(task_file.relative_to(task_root)),
                        timestamp=datetime.fromtimestamp(task_file.stat().st_mtime, tz=timezone.utc),
                        description="File timestamp indicates recent change",
                    )
                )
        return findings


class ActivitiesTimelineScanner(ArtifactScanner):
    category = ArtifactCategory.ACTIVITIES
    name = "Activities Timeline"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        local_appdata = os.environ.get("LOCALAPPDATA")
        if not local_appdata:
            return findings
        root = Path(local_appdata) / "ConnectedDevicesPlatform"
        if not root.exists():
            return findings
        for tenant in root.iterdir():
            db_path = tenant / "ActivitiesCache.db"
            if not db_path.exists():
                continue
            try:
                with NamedTemporaryFile(delete=False) as tmp:
                    shutil.copyfile(db_path, tmp.name)
                    tmp_path = tmp.name
            except OSError:
                continue
            try:
                conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT AppId, ActivityType, StartTime, EndTime, Payload FROM Activity ORDER BY StartTime DESC LIMIT 100"
                )
                rows = cursor.fetchall()
                for app_id, activity_type, start_time, end_time, payload in rows:
                    start = _convert_activity_time(start_time)
                    description = _extract_activity_desc(payload)
                    if detect_keywords(description + str(app_id), context.options.keyword_indicators):
                        findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                category=self.category,
                                title=f"Activity: {app_id}",
                                location=str(tenant.name),
                                timestamp=start,
                                description=description or "Timeline entry",
                                evidence={"activity_type": str(activity_type)},
                            )
                        )
            except sqlite3.Error:
                continue
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        return findings


class RecentJumpListScanner(ArtifactScanner):
    category = ArtifactCategory.RECENT
    name = "Recent & Jump Lists"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            return findings
        script = textwrap.dedent(
            """
            $recentPath = Join-Path $env:APPDATA 'Microsoft\Windows\Recent';
            if (Test-Path $recentPath) {
                $shell = New-Object -ComObject WScript.Shell;
                $items = Get-ChildItem -Path $recentPath -Filter *.lnk -ErrorAction SilentlyContinue | Select-Object -First 80;
                $results = @();
                foreach ($item in $items) {
                    try {
                        $shortcut = $shell.CreateShortcut($item.FullName);
                        $results += [PSCustomObject]@{
                            Name = $item.Name;
                            Target = $shortcut.TargetPath;
                            Created = $item.CreationTimeUtc;
                            Accessed = $item.LastAccessTimeUtc;
                            Path = $item.FullName
                        };
                    } catch {}
                }
                $results | ConvertTo-Json -Compress
            }
            """
        )
        result = context.run_powershell(script, timeout=120)
        entries = _parse_json(result.stdout)
        for entry in entries:
            target = entry.get("Target") or ""
            created = _parse_iso(entry.get("Created"))
            if not target:
                continue
            severity = Severity.MEDIUM if path_is_suspicious(target) else Severity.LOW
            findings.append(
                Finding(
                    severity=severity,
                    category=self.category,
                    title="Recent file accessed",
                    location=target,
                    timestamp=created,
                    description=f"Shortcut: {entry.get('Name')}",
                )
            )
        return findings


class RecycleBinScanner(ArtifactScanner):
    category = ArtifactCategory.RECYCLE_BIN
    name = "Recycle Bin"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        recycle_root = Path("C:/") / "$Recycle.Bin"
        if not recycle_root.exists():
            return findings
        for sid_dir in recycle_root.iterdir():
            if not sid_dir.is_dir():
                continue
            for info_file in sid_dir.glob("$I*"):
                try:
                    with info_file.open("rb") as handle:
                        version = int.from_bytes(handle.read(8), "little")
                        original_size = int.from_bytes(handle.read(8), "little")
                        deletion_time = int.from_bytes(handle.read(8), "little")
                        remaining = handle.read().decode("utf-16-le", errors="ignore").rstrip("\x00")
                except OSError:
                    continue
                timestamp = _safe_filetime(deletion_time)
                severity = Severity.MEDIUM
                if any(ext in remaining.lower() for ext in (".exe", ".dll", ".jar", ".ps1", ".bat", ".tmp")):
                    severity = Severity.HIGH
                findings.append(
                    Finding(
                        severity=severity,
                        category=self.category,
                        title="File deleted to Recycle Bin",
                        location=remaining,
                        timestamp=timestamp,
                        description=f"Size {original_size} bytes | SID {sid_dir.name}",
                        evidence={"version": str(version)},
                    )
                )
        return findings


class ShadowCopyScanner(ArtifactScanner):
    category = ArtifactCategory.VSS
    name = "Volume Shadow Copies"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            return findings
        result = context.run_command(["vssadmin", "list", "shadows"], timeout=120)
        if result.returncode != 0:
            return findings
        blocks = result.stdout.split("\n\n")
        for block in blocks:
            if "Shadow Copy Volume" not in block:
                continue
            creation = _extract_between(block, "Creation Time:", "Originating")
            volume = _extract_between(block, "Shadow Copy Volume:", "Originating")
            timestamp = _parse_shadow_time(creation)
            severity = Severity.MEDIUM
            if timestamp and context.within_lookback(timestamp):
                severity = Severity.HIGH
            findings.append(
                Finding(
                    severity=severity,
                    category=self.category,
                    title="Shadow copy available",
                    location=volume.strip(),
                    timestamp=timestamp or datetime.now(timezone.utc),
                    description=block.strip(),
                )
            )
        if not findings:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category=self.category,
                    title="No shadow copies reported",
                    location="vssadmin",
                    timestamp=datetime.now(timezone.utc),
                    description="System reported zero volume shadow copies.",
                )
            )
        return findings


class AlternateDataStreamScanner(ArtifactScanner):
    category = ArtifactCategory.ADS
    name = "Alternate Data Streams"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            return findings
        user = os.environ.get("USERPROFILE")
        paths = [
            user,
            os.path.join(user, "Downloads") if user else None,
            os.path.join(user, "Desktop") if user else None,
            os.environ.get("TEMP"),
        ]
        unique = {p for p in paths if p}
        for path in unique:
            safe_path = path.replace("'", "''")
            script = textwrap.dedent(
                f"""
                $target = '{safe_path}';
                if (Test-Path $target) {{
                    Get-ChildItem -LiteralPath $target -Recurse -ErrorAction SilentlyContinue -Stream * |
                        Where-Object {{ $_.Stream -ne '::$DATA' }} |
                        Select-Object FileName, Stream, Length -First 80 |
                        ConvertTo-Json -Compress
                }}
                """
            )
            result = context.run_powershell(script, timeout=240)
            entries = _parse_json(result.stdout)
            for entry in entries:
                stream_name = entry.get("Stream")
                size = entry.get("Length")
                file_name = entry.get("FileName")
                if not stream_name:
                    continue
                severity = Severity.HIGH if (size and int(size) > 10_000) else Severity.MEDIUM
                findings.append(
                    Finding(
                        severity=severity,
                        category=self.category,
                        title="Alternate data stream found",
                        location=f"{file_name}:{stream_name}",
                        timestamp=datetime.now(timezone.utc),
                        description=f"ADS size {size} bytes",
                    )
                )
        return findings


class SpecialLocationsScanner(ArtifactScanner):
    category = ArtifactCategory.SPECIAL_LOCATIONS
    name = "Special Artifact Locations"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        targets = [
            os.environ.get("TEMP"),
            os.environ.get("LOCALAPPDATA"),
            os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
            os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
        ]
        suspicious_ext = {".exe", ".dll", ".jar", ".bat", ".ps1", ".tmp", ".zip", ".rar"}
        max_hits = 400 if context.options.deep_scan else 120
        for target in targets:
            if not target or not Path(target).exists():
                continue
            hit_count = 0
            for file in Path(target).glob("**/*"):
                if hit_count >= max_hits:
                    break
                if not file.is_file():
                    continue
                if file.suffix.lower() not in suspicious_ext:
                    continue
                mtime = datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc)
                if not context.within_lookback(mtime) and not context.options.deep_scan:
                    continue
                severity = Severity.MEDIUM
                if path_is_suspicious(str(file)) or detect_keywords(str(file), context.options.keyword_indicators):
                    severity = Severity.HIGH
                findings.append(
                    Finding(
                        severity=severity,
                        category=self.category,
                        title="Suspicious file in user-writable location",
                        location=str(file),
                        timestamp=mtime,
                        description=f"Size {file.stat().st_size} bytes",
                    )
                )
                hit_count += 1
        if not findings:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category=self.category,
                    title="No suspicious files detected",
                    location="Special locations",
                    timestamp=datetime.now(timezone.utc),
                    description="No risky files found in temp/downloads.",
                )
            )
        return findings


def _parse_json(payload: str) -> List[dict]:
    payload = payload.strip()
    if not payload:
        return []
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return data
    return [data]


def _safe_filetime(value) -> datetime:
    try:
        as_int = int(value)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
    if as_int <= 0:
        return datetime.now(timezone.utc)
    try:
        return filetime_to_datetime(as_int)
    except Exception:
        return datetime.now(timezone.utc)


def _parse_iso(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _extract_between(block: str, left: str, right: str) -> str:
    start = block.find(left)
    if start == -1:
        return ""
    start += len(left)
    end = block.find(right, start)
    if end == -1:
        return block[start:].strip()
    return block[start:end].strip()


def _parse_shadow_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%m/%d/%Y %I:%M:%S %p").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.fromisoformat(value).astimezone(timezone.utc)
        except ValueError:
            return None


def _convert_activity_time(raw) -> datetime:
    if raw is None:
        return datetime.now(timezone.utc)
    try:
        raw_int = int(raw)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
    if raw_int > 10_000_000_000:
        return filetime_to_datetime(raw_int)
    return datetime.fromtimestamp(raw_int, tz=timezone.utc)


def _extract_activity_desc(payload: str | None) -> str:
    if not payload:
        return ""
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return payload[:120]
    candidates = [
        data.get("displayText"),
        data.get("appDisplayName"),
        data.get("description"),
    ]
    return next((c for c in candidates if c), payload[:120])
