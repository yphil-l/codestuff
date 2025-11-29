from __future__ import annotations

"""Bypass & Evasion Analyzer Scanner.

This module implements dedicated counter-analysis for common bypass and evasion techniques:
- Spoofed file extensions (filename vs PE/JAR signature mismatch)
- Unicode homoglyph filenames (e.g., Cyrillic/Greek lookalikes)
- Obfuscated JAR/DLL class names (single-letter classes, cheat keywords)
- Timestamp tampering (NTFS timestamp anomalies)
- Enhanced ADS parsing with stream creation times
- Process hollowing indicators (Prefetch + blank executable paths)
- HWID spoofer and VM detection signatures

Multiple detections in a single session are aggregated and escalated to CRITICAL severity.
All findings include counter-bypass metadata (countermeasures, smoking gun flags, correlation IDs).
"""

import json
import os
import re
import textwrap
import unicodedata
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from ..context import ScanContext
from ..models import ArtifactCategory, Finding, Severity
from .base import ArtifactScanner


PE_SIGNATURE = b"MZ"
JAR_SIGNATURE = b"PK\x03\x04"


UNICODE_HOMOGLYPH_PATTERNS = [
    (r"[ο𝐨𝑜𝒐𝓸𝔬𝕠𝗈𝗼𝘰𝙤𝚘]", "o"),
    (r"[а𝐚𝑎𝒂𝓪𝔞𝕒𝖺𝗮𝘢𝙖𝚊]", "a"),
    (r"[е𝐞𝑒𝒆𝓮𝔢𝕖𝖾𝗲𝘦𝙚𝚎]", "e"),
    (r"[і𝐢𝑖𝒊𝓲𝔦𝕚𝗂𝗶𝘪𝙞𝚒ⅰ]", "i"),
    (r"[с𝐜𝑐𝒄𝓬𝔠𝕔𝖼𝗰𝘤𝙘𝚌]", "c"),
    (r"[р𝐩𝑝𝒑𝓹𝔭𝕡𝗉𝗽𝘱𝙥𝚙]", "p"),
    (r"[х𝐱𝑥𝒙𝔁𝕩𝖝𝗑𝘅𝘹𝙭𝚡]", "x"),
]

OBFUSCATED_CLASS_PATTERNS = [
    r"^[a-z]\.class$",
    r"^[A-Z][a-z]?\.class$",
    r"^_+\.class$",
    r"killaura",
    r"autoclicker",
    r"velocity",
    r"reach",
    r"aimbot",
    r"antiknockback",
    r"inject",
]

VM_DRIVER_INDICATORS = [
    "vboxdrv",
    "vboxguest",
    "vmmouse",
    "vmhgfs",
    "vmusbmouse",
    "vmci",
    "vmware",
]

VM_PROCESS_INDICATORS = [
    "vmtoolsd.exe",
    "vboxservice.exe",
    "vboxtray.exe",
    "vmwaretray.exe",
    "vmwareuser.exe",
]

HWID_SPOOFER_INDICATORS = [
    "hwid",
    "spoof",
    "serials",
    "changer",
    "macchanger",
    "volumeid",
]


class BypassAnalyzerScanner(ArtifactScanner):
    category = ArtifactCategory.BYPASS_ANALYSIS
    name = "Bypass & Evasion Analysis"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            context.log("Bypass analysis requires Windows")
            return findings

        technique_hits: Dict[str, int] = defaultdict(int)
        correlation_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

        spoofed = self._detect_spoofed_extensions(context)
        findings.extend(spoofed)
        technique_hits["spoofed_extensions"] = len(spoofed)

        homoglyphs = self._detect_homoglyph_filenames(context)
        findings.extend(homoglyphs)
        technique_hits["unicode_homoglyphs"] = len(homoglyphs)

        obfuscated = self._detect_obfuscated_classes(context)
        findings.extend(obfuscated)
        technique_hits["obfuscated_classes"] = len(obfuscated)

        tampered = self._detect_timestamp_tampering(context)
        findings.extend(tampered)
        technique_hits["timestamp_tampering"] = len(tampered)

        ads_enhanced = self._enhanced_ads_parsing(context)
        findings.extend(ads_enhanced)
        technique_hits["ads_abuse"] = len(ads_enhanced)

        hollowing = self._detect_process_hollowing(context)
        findings.extend(hollowing)
        technique_hits["process_hollowing"] = len(hollowing)

        vm_hwid = self._detect_vm_and_hwid_spoofers(context)
        findings.extend(vm_hwid)
        technique_hits["vm_hwid_spoofers"] = len(vm_hwid)

        total_techniques = sum(1 for count in technique_hits.values() if count > 0)
        total_hits = sum(technique_hits.values())

        for finding in findings:
            finding.evidence["correlation_id"] = correlation_id
            finding.evidence["total_techniques_detected"] = str(total_techniques)
            finding.evidence["total_hits"] = str(total_hits)

        if total_techniques >= 3 or total_hits >= 5:
            findings = self._escalate_findings(findings, technique_hits)

        if not findings:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category=self.category,
                    title="No bypass techniques detected",
                    location="Bypass analysis",
                    timestamp=datetime.now(timezone.utc),
                    description="No evasion or counter-analysis indicators found",
                    evidence={"correlation_id": correlation_id},
                )
            )

        return findings

    def _detect_spoofed_extensions(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        targets = self._get_scan_targets(context)

        for target_path in targets:
            if not Path(target_path).exists():
                continue
            try:
                for file in Path(target_path).rglob("*"):
                    if not file.is_file():
                        continue
                    if file.stat().st_size < 2 or file.stat().st_size > 100_000_000:
                        continue

                    actual_sig = self._read_file_signature(file)
                    if not actual_sig:
                        continue

                    expected_type = self._extension_to_type(file.suffix.lower())
                    actual_type = self._signature_to_type(actual_sig)

                    if actual_type and expected_type and actual_type != expected_type:
                        mtime = datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc)
                        if not context.within_lookback(mtime) and not context.options.deep_scan:
                            continue

                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                category=self.category,
                                title="Spoofed file extension detected",
                                location=str(file),
                                timestamp=mtime,
                                description=f"Extension suggests {expected_type} but signature indicates {actual_type}",
                                evidence={
                                    "expected_type": expected_type,
                                    "actual_type": actual_type,
                                    "countermeasures": "Signature-based detection",
                                    "smoking_gun": "true",
                                },
                            )
                        )
            except (OSError, PermissionError) as e:
                context.log(f"Permission error scanning {target_path}: {e}")
                continue

        return findings

    def _detect_homoglyph_filenames(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        targets = self._get_scan_targets(context)

        for target_path in targets:
            if not Path(target_path).exists():
                continue
            try:
                for file in Path(target_path).rglob("*"):
                    if not file.is_file():
                        continue

                    filename = file.name
                    if self._contains_homoglyphs(filename):
                        mtime = datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc)
                        if not context.within_lookback(mtime) and not context.options.deep_scan:
                            continue

                        normalized = self._normalize_homoglyphs(filename)
                        findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                category=self.category,
                                title="Unicode homoglyph filename detected",
                                location=str(file),
                                timestamp=mtime,
                                description=f"Filename uses confusable unicode characters: {filename} → {normalized}",
                                evidence={
                                    "original_filename": filename,
                                    "normalized_filename": normalized,
                                    "countermeasures": "Unicode normalization check",
                                    "smoking_gun": "true",
                                },
                            )
                        )
            except (OSError, PermissionError) as e:
                context.log(f"Permission error scanning {target_path}: {e}")
                continue

        return findings

    def _detect_obfuscated_classes(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        targets = self._get_scan_targets(context)

        for target_path in targets:
            if not Path(target_path).exists():
                continue
            try:
                for file in Path(target_path).rglob("*"):
                    if not file.is_file():
                        continue

                    if file.suffix.lower() in {".jar", ".zip"}:
                        findings.extend(self._scan_jar_for_obfuscation(context, file))
                    elif file.suffix.lower() == ".dll":
                        findings.extend(self._scan_dll_for_obfuscation(context, file))
                    elif file.suffix.lower() == ".class":
                        filename = file.name.lower()
                        for pattern in OBFUSCATED_CLASS_PATTERNS:
                            if re.search(pattern, filename):
                                mtime = datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc)
                                if not context.within_lookback(mtime) and not context.options.deep_scan:
                                    continue

                                findings.append(
                                    Finding(
                                        severity=Severity.HIGH,
                                        category=self.category,
                                        title="Obfuscated class file detected",
                                        location=str(file),
                                        timestamp=mtime,
                                        description=f"Suspicious class name pattern: {filename}",
                                        evidence={
                                            "pattern": pattern,
                                            "countermeasures": "Class naming convention analysis",
                                            "smoking_gun": "true",
                                        },
                                    )
                                )
                                break
            except (OSError, PermissionError) as e:
                context.log(f"Permission error scanning {target_path}: {e}")
                continue

        return findings

    def _detect_timestamp_tampering(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        if not context.is_admin:
            context.log("Timestamp tampering detection requires admin privileges")
            return findings

        targets = self._get_scan_targets(context)
        for target_path in targets:
            if not Path(target_path).exists():
                continue
            try:
                findings.extend(self._check_ntfs_timestamps(context, target_path))
            except (OSError, PermissionError) as e:
                context.log(f"Permission error checking timestamps in {target_path}: {e}")
                continue

        findings.extend(self._check_readonly_flips(context))
        return findings

    def _enhanced_ads_parsing(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        targets = self._get_scan_targets(context)

        for target_path in targets:
            if not Path(target_path).exists():
                continue
            try:
                safe_path = target_path.replace("'", "''")
                script = textwrap.dedent(
                    f"""
                    $target = '{safe_path}';
                    if (Test-Path $target) {{
                        Get-ChildItem -LiteralPath $target -Recurse -ErrorAction SilentlyContinue -Force |
                            Where-Object {{ !$_.PSIsContainer }} |
                            ForEach-Object {{
                                try {{
                                    $streams = Get-Item -LiteralPath $_.FullName -Stream * -ErrorAction SilentlyContinue |
                                        Where-Object {{ $_.Stream -ne ':$DATA' }}
                                    foreach ($stream in $streams) {{
                                        [PSCustomObject]@{{
                                            FileName = $_.FullName
                                            Stream = $stream.Stream
                                            Length = $stream.Length
                                            CreationTime = $_.CreationTimeUtc
                                            LastWriteTime = $_.LastWriteTimeUtc
                                        }}
                                    }}
                                }} catch {{ }}
                            }} |
                            Select-Object -First 50 |
                            ConvertTo-Json -Compress
                    }}
                    """
                )
                result = context.run_powershell(script, timeout=180)
                entries = _parse_json(result.stdout)

                for entry in entries:
                    stream_name = entry.get("Stream")
                    size = entry.get("Length")
                    file_name = entry.get("FileName")
                    creation_time = _parse_iso(entry.get("CreationTime"))
                    write_time = _parse_iso(entry.get("LastWriteTime"))

                    if not stream_name or stream_name == "::$DATA":
                        continue

                    severity = Severity.HIGH if (size and int(size) > 10_000) else Severity.MEDIUM
                    if context.within_lookback(write_time):
                        severity = Severity.HIGH

                    findings.append(
                        Finding(
                            severity=severity,
                            category=self.category,
                            title="Enhanced ADS detection",
                            location=f"{file_name}:{stream_name}",
                            timestamp=write_time,
                            description=f"ADS created at {creation_time}, size {size} bytes",
                            evidence={
                                "stream_name": stream_name,
                                "size_bytes": str(size),
                                "creation_time": str(creation_time),
                                "countermeasures": "Enhanced stream timestamp tracking",
                            },
                        )
                    )
            except (OSError, PermissionError) as e:
                context.log(f"Permission error scanning ADS in {target_path}: {e}")
                continue

        return findings

    def _detect_process_hollowing(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        script = textwrap.dedent(
            """
            try {
                Get-CimInstance Win32_Process |
                    Select-Object Name, ProcessId, ExecutablePath, CommandLine, CreationDate |
                    ConvertTo-Json -Compress
            } catch { }
            """
        )
        result = context.run_powershell(script, timeout=180)
        processes = _parse_json(result.stdout)

        blank_path_processes: List[Dict] = []
        for proc in processes:
            exe_path = proc.get("ExecutablePath")
            if not exe_path or exe_path.strip() == "":
                blank_path_processes.append(proc)

        if not blank_path_processes:
            return findings

        prefetch_dir = Path(os.environ.get("WINDIR", r"C:\\Windows")) / "Prefetch"
        if not prefetch_dir.exists():
            return findings

        prefetch_files = {pf.name.upper(): pf for pf in prefetch_dir.glob("*.pf")}

        for proc in blank_path_processes:
            name = proc.get("Name") or ""
            pid = proc.get("ProcessId")

            if name.upper().startswith("SYSTEM"):
                continue

            prefetch_match = any(name.upper() in pf_name for pf_name in prefetch_files)

            if prefetch_match:
                creation_date = proc.get("CreationDate")
                timestamp = _parse_cim_datetime(creation_date)

                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category=self.category,
                        title="Process hollowing indicator detected",
                        location=f"PID {pid}: {name}",
                        timestamp=timestamp,
                        description=f"Process has blank executable path but Prefetch entry exists",
                        evidence={
                            "process_name": name,
                            "pid": str(pid),
                            "executable_path": "BLANK",
                            "prefetch_exists": "true",
                            "command_line": proc.get("CommandLine", "")[:200],
                            "countermeasures": "Prefetch + process snapshot correlation",
                            "smoking_gun": "true",
                        },
                    )
                )

        return findings

    def _detect_vm_and_hwid_spoofers(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        findings.extend(self._detect_vm_indicators(context))
        findings.extend(self._detect_hwid_spoofers(context))

        return findings

    def _detect_vm_indicators(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        script = textwrap.dedent(
            """
            try {
                Get-CimInstance Win32_SystemDriver |
                    Where-Object { $_.State -eq 'Running' } |
                    Select-Object Name, DisplayName, PathName |
                    ConvertTo-Json -Compress
            } catch { }
            """
        )
        result = context.run_powershell(script, timeout=120)
        drivers = _parse_json(result.stdout)

        for driver in drivers:
            name = (driver.get("Name") or "").lower()
            display_name = (driver.get("DisplayName") or "").lower()
            path = (driver.get("PathName") or "").lower()

            for indicator in VM_DRIVER_INDICATORS:
                if indicator in name or indicator in display_name or indicator in path:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category=self.category,
                            title="VM driver detected",
                            location=driver.get("Name", "unknown"),
                            timestamp=datetime.now(timezone.utc),
                            description=f"Virtual machine driver running: {driver.get('DisplayName', 'unknown')}",
                            evidence={
                                "driver_name": driver.get("Name", ""),
                                "driver_path": driver.get("PathName", ""),
                                "indicator": indicator,
                                "countermeasures": "VM signature detection",
                            },
                        )
                    )
                    break

        script = textwrap.dedent(
            """
            try {
                Get-Process |
                    Select-Object Name, Id, Path |
                    ConvertTo-Json -Compress
            } catch { }
            """
        )
        result = context.run_powershell(script, timeout=120)
        processes = _parse_json(result.stdout)

        for proc in processes:
            name = (proc.get("Name") or "").lower()
            if any(indicator in name for indicator in VM_PROCESS_INDICATORS):
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category=self.category,
                        title="VM process detected",
                        location=proc.get("Path", "unknown"),
                        timestamp=datetime.now(timezone.utc),
                        description=f"Virtual machine process running: {proc.get('Name')} (PID {proc.get('Id')})",
                        evidence={
                            "process_name": proc.get("Name", ""),
                            "pid": str(proc.get("Id", "")),
                            "countermeasures": "VM process signature detection",
                        },
                    )
                )

        return findings

    def _detect_hwid_spoofers(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        script = textwrap.dedent(
            """
            try {
                Get-Process |
                    Select-Object Name, Id, Path, CommandLine |
                    ConvertTo-Json -Compress
            } catch { }
            """
        )
        result = context.run_powershell(script, timeout=120)
        processes = _parse_json(result.stdout)

        for proc in processes:
            name = (proc.get("Name") or "").lower()
            path = (proc.get("Path") or "").lower()
            cmdline = (proc.get("CommandLine") or "").lower()

            combined = f"{name} {path} {cmdline}"
            if any(indicator in combined for indicator in HWID_SPOOFER_INDICATORS):
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category=self.category,
                        title="HWID spoofer indicator detected",
                        location=proc.get("Path", "unknown"),
                        timestamp=datetime.now(timezone.utc),
                        description=f"Process with HWID spoofer signature: {proc.get('Name')} (PID {proc.get('Id')})",
                        evidence={
                            "process_name": proc.get("Name", ""),
                            "pid": str(proc.get("Id", "")),
                            "command_line": proc.get("CommandLine", "")[:200],
                            "countermeasures": "HWID spoofer signature detection",
                            "smoking_gun": "true",
                        },
                    )
                )
                break

        targets = self._get_scan_targets(context)
        for target_path in targets:
            if not Path(target_path).exists():
                continue
            try:
                for file in Path(target_path).rglob("*"):
                    if not file.is_file():
                        continue
                    filename = file.name.lower()
                    if any(indicator in filename for indicator in HWID_SPOOFER_INDICATORS):
                        mtime = datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc)
                        if not context.within_lookback(mtime) and not context.options.deep_scan:
                            continue

                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                category=self.category,
                                title="HWID spoofer file detected",
                                location=str(file),
                                timestamp=mtime,
                                description=f"File with HWID spoofer signature: {file.name}",
                                evidence={
                                    "filename": file.name,
                                    "countermeasures": "Keyword-based file detection",
                                    "smoking_gun": "true",
                                },
                            )
                        )
                        break
            except (OSError, PermissionError) as e:
                context.log(f"Permission error scanning {target_path}: {e}")
                continue

        return findings

    def _get_scan_targets(self, context: ScanContext) -> List[str]:
        user_profile = os.environ.get("USERPROFILE")
        targets = [
            os.environ.get("TEMP"),
            os.environ.get("LOCALAPPDATA"),
        ]
        if user_profile:
            targets.extend(
                [
                    os.path.join(user_profile, "Downloads"),
                    os.path.join(user_profile, "Desktop"),
                    os.path.join(user_profile, "Documents"),
                ]
            )
        return [t for t in targets if t]

    def _read_file_signature(self, file: Path) -> Optional[bytes]:
        try:
            with file.open("rb") as f:
                return f.read(4)
        except (OSError, PermissionError):
            return None

    def _extension_to_type(self, ext: str) -> Optional[str]:
        mapping = {
            ".exe": "PE",
            ".dll": "PE",
            ".sys": "PE",
            ".jar": "JAR",
            ".zip": "ZIP",
            ".png": "IMAGE",
            ".jpg": "IMAGE",
            ".jpeg": "IMAGE",
            ".gif": "IMAGE",
            ".txt": "TEXT",
            ".pdf": "PDF",
        }
        return mapping.get(ext)

    def _signature_to_type(self, sig: bytes) -> Optional[str]:
        if sig.startswith(PE_SIGNATURE):
            return "PE"
        elif sig.startswith(JAR_SIGNATURE):
            return "JAR"
        elif sig.startswith(b"\x89PNG"):
            return "IMAGE"
        elif sig.startswith(b"\xff\xd8\xff"):
            return "IMAGE"
        elif sig.startswith(b"GIF8"):
            return "IMAGE"
        elif sig.startswith(b"%PDF"):
            return "PDF"
        return None

    def _contains_homoglyphs(self, text: str) -> bool:
        for pattern, _ in UNICODE_HOMOGLYPH_PATTERNS:
            if re.search(pattern, text):
                return True
        for char in text:
            if ord(char) > 0x7F:
                category = unicodedata.category(char)
                if category in {"Ll", "Lu", "Lt"}:
                    return True
        return False

    def _normalize_homoglyphs(self, text: str) -> str:
        normalized = text
        for pattern, replacement in UNICODE_HOMOGLYPH_PATTERNS:
            normalized = re.sub(pattern, replacement, normalized)
        return normalized

    def _scan_jar_for_obfuscation(self, context: ScanContext, jar_file: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            import zipfile

            with zipfile.ZipFile(jar_file, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".class"):
                        basename = name.split("/")[-1]
                        for pattern in OBFUSCATED_CLASS_PATTERNS:
                            if re.search(pattern, basename.lower()):
                                mtime = datetime.fromtimestamp(jar_file.stat().st_mtime, tz=timezone.utc)
                                if not context.within_lookback(mtime) and not context.options.deep_scan:
                                    continue

                                findings.append(
                                    Finding(
                                        severity=Severity.HIGH,
                                        category=self.category,
                                        title="Obfuscated class in JAR detected",
                                        location=f"{jar_file}!{name}",
                                        timestamp=mtime,
                                        description=f"Suspicious class name in JAR: {basename}",
                                        evidence={
                                            "jar_file": str(jar_file),
                                            "class_name": basename,
                                            "pattern": pattern,
                                            "countermeasures": "JAR content analysis",
                                            "smoking_gun": "true",
                                        },
                                    )
                                )
                                break
        except Exception:
            pass
        return findings

    def _scan_dll_for_obfuscation(self, context: ScanContext, dll_file: Path) -> List[Finding]:
        findings: List[Finding] = []
        suspicious_tokens = ("killaura", "aimbot", "inject", "spoof", "hwid", "clean")
        reasons: List[str] = []

        try:
            stem = dll_file.stem.lower()
            if len(stem) <= 2:
                reasons.append("DLL name is extremely short")
            for token in suspicious_tokens:
                if token in stem:
                    reasons.append(f"Filename contains '{token}'")

            with dll_file.open("rb") as f:
                header = f.read(4)
                if not header.startswith(PE_SIGNATURE):
                    return findings
                chunk = f.read(512_000).lower()
                for token in suspicious_tokens:
                    if token.encode() in chunk:
                        reasons.append(f"Binary contains string '{token}'")
                        break

            if reasons:
                mtime = datetime.fromtimestamp(dll_file.stat().st_mtime, tz=timezone.utc)
                if not context.within_lookback(mtime) and not context.options.deep_scan:
                    return findings

                severity = Severity.HIGH if any("Binary contains" in reason for reason in reasons) else Severity.MEDIUM
                findings.append(
                    Finding(
                        severity=severity,
                        category=self.category,
                        title="Obfuscated DLL detected",
                        location=str(dll_file),
                        timestamp=mtime,
                        description="; ".join(reasons),
                        evidence={
                            "countermeasures": "DLL naming/content inspection",
                            "smoking_gun": "true" if severity == Severity.HIGH else "false",
                        },
                    )
                )
        except (OSError, PermissionError):
            return findings

        return findings

    def _check_ntfs_timestamps(self, context: ScanContext, target_path: str) -> List[Finding]:
        findings: List[Finding] = []

        script = textwrap.dedent(
            f"""
            $target = '{target_path.replace("'", "''")}';
            if (Test-Path $target) {{
                Get-ChildItem -LiteralPath $target -Recurse -File -ErrorAction SilentlyContinue |
                    Select-Object -First 30 FullName, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc |
                    ForEach-Object {{
                        $diff = ($_.LastWriteTimeUtc - $_.CreationTimeUtc).TotalSeconds
                        if ($diff -lt -60 -or ($_.LastWriteTimeUtc.Year -lt 2000)) {{
                            [PSCustomObject]@{{
                                Path = $_.FullName
                                Created = $_.CreationTimeUtc
                                Modified = $_.LastWriteTimeUtc
                                Accessed = $_.LastAccessTimeUtc
                            }}
                        }}
                    }} |
                    ConvertTo-Json -Compress
            }}
            """
        )
        result = context.run_powershell(script, timeout=180)
        entries = _parse_json(result.stdout)

        for entry in entries:
            path = entry.get("Path")
            created = _parse_iso(entry.get("Created"))
            modified = _parse_iso(entry.get("Modified"))

            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category=self.category,
                    title="Timestamp tampering detected",
                    location=path,
                    timestamp=modified,
                    description=f"Suspicious timestamps: Created={created}, Modified={modified}",
                    evidence={
                        "created": str(created),
                        "modified": str(modified),
                        "countermeasures": "NTFS timestamp analysis",
                        "smoking_gun": "true",
                    },
                )
            )

        return findings

    def _check_readonly_flips(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        targets = self._get_scan_targets(context)

        for target_path in targets:
            if not Path(target_path).exists():
                continue
            try:
                script = textwrap.dedent(
                    f"""
                    $target = '{target_path.replace("'", "''")}';
                    if (Test-Path $target) {{
                        Get-ChildItem -LiteralPath $target -Recurse -File -ErrorAction SilentlyContinue |
                            Where-Object {{ $_.IsReadOnly -eq $true }} |
                            Select-Object -First 20 FullName, CreationTimeUtc, LastWriteTimeUtc, Attributes |
                            ConvertTo-Json -Compress
                    }}
                    """
                )
                result = context.run_powershell(script, timeout=120)
                entries = _parse_json(result.stdout)

                for entry in entries:
                    path = entry.get("FullName")
                    write_time = _parse_iso(entry.get("LastWriteTimeUtc"))

                    if context.within_lookback(write_time):
                        findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                category=self.category,
                                title="Recent read-only attribute flip",
                                location=path,
                                timestamp=write_time,
                                description="File marked read-only within lookback window",
                                evidence={
                                    "attributes": entry.get("Attributes", ""),
                                    "countermeasures": "Attribute change monitoring",
                                },
                            )
                        )
            except Exception as e:
                context.log(f"Error checking readonly flips in {target_path}: {e}")
                continue

        return findings

    def _escalate_findings(self, findings: List[Finding], technique_hits: Dict[str, int]) -> List[Finding]:
        escalated = []
        for finding in findings:
            if finding.severity in {Severity.HIGH, Severity.MEDIUM}:
                finding.severity = Severity.CRITICAL
                finding.evidence["escalation_reason"] = "Multiple bypass techniques detected"
                finding.evidence["technique_summary"] = ", ".join(
                    f"{k}={v}" for k, v in technique_hits.items() if v > 0
                )
            escalated.append(finding)
        return escalated


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


def _parse_iso(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _parse_cim_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        date_part = value.split(".")[0]
        return datetime.strptime(date_part, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return datetime.now(timezone.utc)


def contains_homoglyphs(text: str) -> bool:
    """Helper function for testing: detect if text contains unicode homoglyphs."""
    for pattern, _ in UNICODE_HOMOGLYPH_PATTERNS:
        if re.search(pattern, text):
            return True
    for char in text:
        if ord(char) > 0x7F:
            category = unicodedata.category(char)
            if category in {"Ll", "Lu", "Lt"}:
                return True
    return False


def is_spoofed_signature(file_path: str, expected_extension: str) -> bool:
    """Helper function for testing: check if file signature doesn't match extension."""
    try:
        with open(file_path, "rb") as f:
            sig = f.read(4)

        if not sig:
            return False

        ext_lower = expected_extension.lower()
        ext_map = {
            ".exe": "PE",
            ".dll": "PE",
            ".sys": "PE",
            ".jar": "JAR",
            ".zip": "JAR",
            ".txt": "TEXT",
            ".png": "IMAGE",
            ".jpg": "IMAGE",
            ".jpeg": "IMAGE",
            ".gif": "IMAGE",
            ".pdf": "PDF",
        }
        expected_type = ext_map.get(ext_lower)
        if not expected_type:
            return False

        actual_type: Optional[str]
        if sig.startswith(PE_SIGNATURE):
            actual_type = "PE"
        elif sig.startswith(JAR_SIGNATURE):
            actual_type = "JAR"
        elif sig.startswith(b"\x89PNG") or sig.startswith(b"\xff\xd8\xff") or sig.startswith(b"GIF8"):
            actual_type = "IMAGE"
        elif sig.startswith(b"%PDF"):
            actual_type = "PDF"
        else:
            actual_type = None

        if not actual_type:
            return False

        return expected_type != actual_type
    except OSError:
        return False
