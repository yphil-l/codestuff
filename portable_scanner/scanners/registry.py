from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Sequence

from ..context import ScanContext
from ..models import ArtifactCategory, Finding, Severity
from ..utils import detect_keywords, filetime_to_datetime, looks_random, path_is_suspicious
from .base import ArtifactScanner

if sys.platform.startswith("win"):
    import winreg
else:  # pragma: no cover - not on Windows
    winreg = None  # type: ignore


@dataclass
class RegistryValue:
    name: str
    raw_data: str
    last_write: datetime
    path: str


class RegistryScanner(ArtifactScanner):
    category = ArtifactCategory.REGISTRY
    name = "Registry & Persistence"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows or not winreg:
            context.log("Registry analysis limited to Windows hosts.")
            return findings

        for root, subkey in RUN_KEYS:
            findings.extend(self._analyze_run_key(context, root, subkey))

        findings.extend(self._check_command_processor(context))
        findings.extend(self._check_prefetcher(context))
        findings.extend(self._check_policies(context))
        findings.extend(self._check_userassist(context))
        findings.extend(self._check_bam(context))

        return findings

    def _analyze_run_key(
        self, context: ScanContext, root: int, subkey: str
    ) -> List[Finding]:
        entries = self._read_values(root, subkey)
        findings: List[Finding] = []
        for entry in entries:
            path = entry.raw_data.strip().strip('"')
            expanded = os.path.expandvars(path)
            severity = None
            description = []
            if not path:
                continue
            if path_is_suspicious(expanded):
                severity = Severity.HIGH
                description.append("Autorun executes from user-writable path")
            if looks_random(entry.name):
                severity = Severity.HIGH
                description.append("Run entry name has high entropy")
            if not os.path.exists(expanded):
                severity = severity or Severity.MEDIUM
                description.append("Target file missing on disk")
            if detect_keywords(expanded, context.options.keyword_indicators):
                severity = Severity.CRITICAL
                description.append("Path contains cheat indicator keyword")
            if severity:
                findings.append(
                    Finding(
                        severity=severity,
                        category=self.category,
                        title="Suspicious autorun entry",
                        location=f"{subkey}\\{entry.name}",
                        timestamp=entry.last_write,
                        description="; ".join(description),
                        evidence={"target": expanded},
                    )
                )
        return findings

    def _check_command_processor(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        for hive, subkey in COMMAND_PROCESSOR_KEYS:
            entries = self._read_values(hive, subkey, value_filter=("autorun",))
            for entry in entries:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category=self.category,
                        title="Command processor autorun configured",
                        location=f"{subkey}",
                        timestamp=entry.last_write,
                        description=entry.raw_data,
                    )
                )
        return findings

    def _check_prefetcher(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        key = r"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters"
        entries = self._read_values(winreg.HKEY_LOCAL_MACHINE, key, value_filter=("EnablePrefetcher",))
        for entry in entries:
            try:
                value = int(entry.raw_data)
            except ValueError:
                continue
            if value == 0:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category=self.category,
                        title="Prefetch disabled",
                        location=f"{key}\\EnablePrefetcher",
                        timestamp=entry.last_write,
                        description="Prefetcher was disabled via registry",
                    )
                )
        return findings

    def _check_policies(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        key = r"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
        entries = self._read_values(winreg.HKEY_CURRENT_USER, key)
        for entry in entries:
            if entry.name.lower() in {"norun", "nodrives", "noviewondrive"}:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category=self.category,
                        title="Explorer policy hides functionality",
                        location=f"{key}\\{entry.name}",
                        timestamp=entry.last_write,
                        description=f"Policy {entry.name} set to {entry.raw_data}",
                    )
                )
        return findings

    def _check_userassist(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        base = r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as base_key:
                sub_count, _, _ = winreg.QueryInfoKey(base_key)
                for idx in range(sub_count):
                    guid = winreg.EnumKey(base_key, idx)
                    path = f"{base}\\{guid}\\Count"
                    entries = self._read_binary_values(winreg.HKEY_CURRENT_USER, path)
                    for entry in entries:
                        decoded = _rot13(entry.name)
                        if not decoded:
                            continue
                        if any(token in decoded.lower() for token in USERASSIST_TARGETS):
                            findings.append(
                                Finding(
                                    severity=Severity.HIGH,
                                    category=self.category,
                                    title="UserAssist captured suspicious program launch",
                                    location=decoded,
                                    timestamp=entry.last_write,
                                    description="Recent execution recorded in UserAssist",
                                )
                            )
        except OSError:
            pass
        return findings

    def _check_bam(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        path = r"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as root:
                sub_count, _, _ = winreg.QueryInfoKey(root)
                for idx in range(sub_count):
                    sid = winreg.EnumKey(root, idx)
                    with winreg.OpenKey(root, sid) as sid_key:
                        value_count = winreg.QueryInfoKey(sid_key)[1]
                        for value_idx in range(value_count):
                            name, _, _ = winreg.EnumValue(sid_key, value_idx)
                            lowered = name.lower()
                            if any(target in lowered for target in USERASSIST_TARGETS) or path_is_suspicious(name):
                                findings.append(
                                    Finding(
                                        severity=Severity.HIGH,
                                        category=self.category,
                                        title="BAM history references suspicious executable",
                                        location=name,
                                        timestamp=datetime.now(timezone.utc),
                                        description=f"SID {sid} executed {name}",
                                    )
                                )
        except OSError:
            pass
        return findings

    def _read_values(
        self,
        root: int,
        subkey: str,
        value_filter: Sequence[str] | None = None,
    ) -> List[RegistryValue]:
        entries: List[RegistryValue] = []
        if not winreg or not root:
            return entries
        try:
            with winreg.OpenKey(root, subkey) as key:
                info = winreg.QueryInfoKey(key)
                last_write = filetime_to_datetime(info[2])
                value_count = info[1]
                wanted = {name.lower() for name in value_filter} if value_filter else None
                for idx in range(value_count):
                    name, value, _ = winreg.EnumValue(key, idx)
                    if wanted and name.lower() not in wanted:
                        continue
                    entries.append(RegistryValue(name=name, raw_data=str(value), last_write=last_write, path=subkey))
        except OSError:
            return []
        return entries

    def _read_binary_values(self, root: int, subkey: str) -> List[RegistryValue]:
        entries: List[RegistryValue] = []
        if not winreg or not root:
            return entries
        try:
            with winreg.OpenKey(root, subkey) as key:
                info = winreg.QueryInfoKey(key)
                last_write = filetime_to_datetime(info[2])
                value_count = info[1]
                for idx in range(value_count):
                    name, value, _ = winreg.EnumValue(key, idx)
                    entries.append(RegistryValue(name=name, raw_data=value, last_write=last_write, path=subkey))
        except OSError:
            return []
        return entries


def _rot13(value: str) -> str:
    result = []
    for char in value:
        if "a" <= char <= "z":
            offset = ord("a")
            result.append(chr((ord(char) - offset + 13) % 26 + offset))
        elif "A" <= char <= "Z":
            offset = ord("A")
            result.append(chr((ord(char) - offset + 13) % 26 + offset))
        else:
            result.append(char)
    return "".join(result)


RUN_KEYS: Sequence[tuple[int, str]] = (
    (winreg.HKEY_LOCAL_MACHINE if winreg else 0, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    (winreg.HKEY_LOCAL_MACHINE if winreg else 0, r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    (winreg.HKEY_CURRENT_USER if winreg else 0, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    (winreg.HKEY_CURRENT_USER if winreg else 0, r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
)

COMMAND_PROCESSOR_KEYS: Sequence[tuple[int, str]] = (
    (winreg.HKEY_LOCAL_MACHINE if winreg else 0, r"Software\\Microsoft\\Command Processor"),
    (winreg.HKEY_CURRENT_USER if winreg else 0, r"Software\\Microsoft\\Command Processor"),
)

USERASSIST_TARGETS = (
    "powershell",
    "cmd.exe",
    "javaw",
    "rundll32",
    "mshta",
    "regsvr32",
)
