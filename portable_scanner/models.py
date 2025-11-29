from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def ordered(cls) -> List["Severity"]:
        return [cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW]

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "#ff0066",
            Severity.HIGH: "#ff7b00",
            Severity.MEDIUM: "#f6c344",
            Severity.LOW: "#7a8ea0",
        }[self]


class ArtifactCategory(str, enum.Enum):
    EVENT_LOGS = "Event Logs"
    REGISTRY = "Registry (Persistence)"
    PREFETCH = "Prefetch & Amcache"
    USN = "USN Journal"
    TASK_SCHEDULER = "Task Scheduler"
    ACTIVITIES = "Activities Timeline"
    RECENT = "Recent & Jump Lists"
    RECYCLE_BIN = "Recycle Bin"
    VSS = "Volume Shadow Copies"
    ADS = "Alternate Data Streams"
    PROCESSES = "Process & Memory"
    ENCRYPTED_VOLUMES = "Encrypted Volumes"
    SPECIAL_LOCATIONS = "Special Artifact Locations"
    BYPASS_ANALYSIS = "Bypass & Evasion"

    @property
    def short_name(self) -> str:
        return self.value


@dataclass
class Finding:
    severity: Severity
    category: ArtifactCategory
    title: str
    location: str
    timestamp: datetime
    description: str
    evidence: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, str]:
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "location": self.location,
            "timestamp": self.timestamp.replace(tzinfo=timezone.utc).isoformat(),
            "description": self.description,
            "evidence": self.evidence,
        }


@dataclass
class ScanOptions:
    lookback_hours: int = 4
    deep_scan: bool = False
    keyword_indicators: Iterable[str] = field(
        default_factory=lambda: (
            "cheat",
            "loader",
            "inject",
            "spoof",
            "clean",
            "obfusc",
            "macro",
        )
    )
    severity_threshold: Severity = Severity.LOW
    output_directory: Optional[str] = None
    auto_export: bool = False


@dataclass
class SystemInfo:
    hostname: str
    username: str
    os_version: str
    user_sid: str


@dataclass
class ScanSummary:
    findings: List[Finding] = field(default_factory=list)

    def severity_buckets(self) -> Dict[Severity, int]:
        buckets: Dict[Severity, int] = {severity: 0 for severity in Severity.ordered()}
        for finding in self.findings:
            buckets[finding.severity] += 1
        return buckets

    def to_table(self) -> List[Dict[str, str]]:
        return [finding.to_dict() for finding in self.findings]
