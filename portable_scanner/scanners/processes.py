from __future__ import annotations

import json
import os
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List

from ..context import ScanContext
from ..models import ArtifactCategory, Finding, Severity
from ..utils import detect_keywords, path_is_suspicious
from .base import ArtifactScanner


class ProcessMemoryScanner(ArtifactScanner):
    category = ArtifactCategory.PROCESSES
    name = "Process & Memory"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            return findings
        processes = self._collect_processes(context)
        connections = self._collect_connections(context)
        suspicious = {
            "javaw.exe",
            "powershell.exe",
            "wscript.exe",
            "cscript.exe",
            "explorer.exe",
            "svchost.exe",
            "mshta.exe",
            "rundll32.exe",
        }
        for proc in processes:
            name = (proc.get("Name") or "").lower()
            pid_raw = proc.get("ProcessId")
            try:
                pid = int(pid_raw)
            except (TypeError, ValueError):
                pid = None
            command = proc.get("CommandLine") or ""
            exe_path = proc.get("ExecutablePath") or ""
            timestamp = _parse_cim_datetime(proc.get("CreationDate"))
            severity = None
            reasons: List[str] = []
            if not exe_path:
                severity = Severity.MEDIUM
                reasons.append("Executable path missing")
            elif not Path(exe_path).exists():
                severity = Severity.HIGH
                reasons.append("Backing file missing on disk")
            if exe_path and path_is_suspicious(exe_path):
                severity = Severity.HIGH
                reasons.append("Process running from user-writable path")
            if detect_keywords(command, context.options.keyword_indicators) or "-enc" in command.lower():
                severity = Severity.CRITICAL
                reasons.append("Command line contains obfuscation/keyword")
            if name in suspicious:
                severity = severity or Severity.MEDIUM
                reasons.append("High-risk binary executing")
            if pid in connections:
                remote = connections[pid]
                if len(remote) >= 3:
                    severity = severity or Severity.MEDIUM
                    reasons.append(f"Multiple network connections ({len(remote)})")
                if any(addr not in {"127.0.0.1", "::1"} for addr, _ in remote):
                    severity = severity or Severity.HIGH
                    reasons.append("External network connection detected")
            if severity:
                findings.append(
                    Finding(
                        severity=severity,
                        category=self.category,
                        title=f"Suspicious process: {proc.get('Name')}",
                        location=f"PID {pid if pid is not None else 'unknown'}",
                        timestamp=timestamp,
                        description="; ".join(reasons) or command,
                        evidence={
                            "command": command[:200],
                            "path": exe_path,
                        },
                    )
                )
                if pid is not None:
                    findings.extend(self._inspect_modules(context, pid, exe_path))
        if not findings:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category=self.category,
                    title="No suspicious processes detected",
                    location="Process snapshot",
                    timestamp=datetime.now(timezone.utc),
                    description="Process inspection completed",
                )
            )
        return findings

    def _collect_processes(self, context: ScanContext) -> List[dict]:
        script = textwrap.dedent(
            """
            try {
                Get-CimInstance Win32_Process |
                    Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate |
                    ConvertTo-Json -Compress
            } catch { }
            """
        )
        result = context.run_powershell(script, timeout=240)
        return _parse_json(result.stdout)

    def _collect_connections(self, context: ScanContext) -> dict[int, List[tuple[str, str]]]:
        script = textwrap.dedent(
            """
            try {
                Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                    Select-Object OwningProcess, RemoteAddress, RemotePort |
                    ConvertTo-Json -Compress
            } catch { }
            """
        )
        result = context.run_powershell(script, timeout=180)
        data = _parse_json(result.stdout)
        mapping: dict[int, List[tuple[str, str]]] = {}
        for entry in data:
            pid_raw = entry.get("OwningProcess")
            addr = entry.get("RemoteAddress") or ""
            port = entry.get("RemotePort") or ""
            try:
                pid = int(pid_raw)
            except (TypeError, ValueError):
                continue
            if not addr:
                continue
            mapping.setdefault(pid, []).append((addr, str(port)))
        return mapping

    def _inspect_modules(self, context: ScanContext, pid: int | None, exe_path: str) -> List[Finding]:
        findings: List[Finding] = []
        if pid is None:
            return findings
        script = textwrap.dedent(
            f"""
            try {{
                (Get-Process -Id {pid} -ErrorAction Stop).Modules |
                    Select-Object FileName |
                    ConvertTo-Json -Compress
            }} catch {{ }}
            """
        )
        result = context.run_powershell(script, timeout=120)
        modules = _parse_json(result.stdout)
        for module in modules[:40]:
            path = module.get("FileName")
            if not path:
                continue
            if path_is_suspicious(path) and not path.lower().startswith(os.environ.get("WINDIR", "c:/windows").lower()):
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category=self.category,
                        title="Suspicious module injected",
                        location=path,
                        timestamp=datetime.now(timezone.utc),
                        description=f"Module loaded into PID {pid}",
                        evidence={"process_path": exe_path},
                    )
                )
        return findings


class EncryptedVolumeScanner(ArtifactScanner):
    category = ArtifactCategory.ENCRYPTED_VOLUMES
    name = "Encrypted Volumes"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            return findings
        findings.extend(self._bitlocker_status(context))
        findings.extend(self._detect_encrypted_process(context))
        if not findings:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category=self.category,
                    title="No encrypted volume indicators",
                    location="manage-bde",
                    timestamp=datetime.now(timezone.utc),
                    description="No BitLocker or encrypted container evidence detected",
                )
            )
        return findings

    def _bitlocker_status(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        result = context.run_command(["manage-bde", "-status"], timeout=120)
        output = result.stdout
        sections = [segment.strip() for segment in output.split("Volume ") if segment.strip()]
        for section in sections:
            volume = section.splitlines()[0].strip()
            protection = _extract_field(section, "Protection Status")
            status = _extract_field(section, "Conversion Status")
            percent = _extract_field(section, "Percentage Encrypted")
            severity = None
            if protection and "on" in protection.lower():
                severity = Severity.MEDIUM
            if status and "in progress" in status.lower():
                severity = Severity.HIGH
            if severity:
                findings.append(
                    Finding(
                        severity=severity,
                        category=self.category,
                        title=f"BitLocker volume {volume}",
                        location=volume,
                        timestamp=datetime.now(timezone.utc),
                        description=f"Protection={protection} | Status={status} | {percent}",
                    )
                )
        script = textwrap.dedent(
            """
            try {
                Get-BitLockerVolume |
                    Select-Object MountPoint, VolumeType, ProtectionStatus, VolumeStatus |
                    ConvertTo-Json -Compress
            } catch { }
            """
        )
        result = context.run_powershell(script, timeout=180)
        volumes = _parse_json(result.stdout)
        for volume in volumes:
            mount = volume.get("MountPoint") or volume.get("VolumeType")
            protection = volume.get("ProtectionStatus")
            status = volume.get("VolumeStatus")
            if str(status).lower() == "locked":
                severity = Severity.CRITICAL
            elif str(protection) == "On":
                severity = Severity.MEDIUM
            else:
                continue
            findings.append(
                Finding(
                    severity=severity,
                    category=self.category,
                    title="BitLocker status",
                    location=str(mount),
                    timestamp=datetime.now(timezone.utc),
                    description=f"Protection={protection} | Status={status}",
                )
            )
        return findings

    def _detect_encrypted_process(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        suspicious = ("veracrypt.exe", "truecrypt.exe", "diskcryptor.exe")
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
            if name in suspicious:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category=self.category,
                        title="Encrypted container tool running",
                        location=proc.get("Path", ""),
                        timestamp=datetime.now(timezone.utc),
                        description=f"Process {proc.get('Name')} PID {proc.get('Id')}",
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


def _parse_cim_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        date_part = value.split(".")[0]
        return datetime.strptime(date_part, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return datetime.now(timezone.utc)


def _extract_field(section: str, label: str) -> str:
    for line in section.splitlines():
        if label.lower() in line.lower():
            return line.split(":", 1)[-1].strip()
    return ""
