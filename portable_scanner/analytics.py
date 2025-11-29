from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List

from .models import ArtifactCategory, Finding, Severity


def _severity_template() -> Dict[Severity, int]:
    return {severity: 0 for severity in Severity}


@dataclass
class MinuteCategoryBreakdown:
    category: ArtifactCategory
    count: int = 0
    severity_counts: Dict[Severity, int] = field(default_factory=_severity_template)

    def increment(self, severity: Severity) -> None:
        self.count += 1
        self.severity_counts[severity] += 1

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "count": self.count,
            "severity": {severity.value: count for severity, count in self.severity_counts.items()},
        }


@dataclass
class MinuteCluster:
    minute: datetime
    findings: List[Finding]
    category_breakdown: Dict[ArtifactCategory, MinuteCategoryBreakdown]

    def to_dict(self) -> dict:
        return {
            "minute": _minute_key(self.minute),
            "total_findings": len(self.findings),
            "categories": [
                breakdown.to_dict()
                for breakdown in sorted(
                    self.category_breakdown.values(), key=lambda item: item.category.value
                )
            ],
            "findings": [
                {
                    "category": finding.category.value,
                    "severity": finding.severity.value,
                    "title": finding.title,
                    "location": finding.location,
                    "timestamp": finding.timestamp.isoformat().replace("+00:00", "Z"),
                }
                for finding in self.findings
            ],
        }


@dataclass
class CorrelationSummary:
    minute_clusters: List[MinuteCluster]
    category_heatmap: Dict[ArtifactCategory, Dict[str, int]]
    category_severity: Dict[ArtifactCategory, Dict[Severity, int]]

    def to_dict(self) -> dict:
        return {
            "timeline": [cluster.to_dict() for cluster in self.minute_clusters],
            "category_vs_time": {
                category.value: data for category, data in self.category_heatmap.items()
            },
            "category_severity": {
                category.value: {severity.value: count for severity, count in counts.items()}
                for category, counts in self.category_severity.items()
            },
        }

    def ordered_minutes(self) -> List[str]:
        minutes: set[str] = set()
        for heatmap in self.category_heatmap.values():
            minutes.update(heatmap.keys())
        return sorted(minutes)

    def top_clusters(self, limit: int | None = 10) -> List[MinuteCluster]:
        if limit is None:
            return list(self.minute_clusters)
        return list(self.minute_clusters[:limit])

    @property
    def is_empty(self) -> bool:
        return len(self.minute_clusters) == 0


def build_correlation_summary(findings: Iterable[Finding]) -> CorrelationSummary:
    items = list(findings)
    heatmap: Dict[ArtifactCategory, Dict[str, int]] = {category: {} for category in ArtifactCategory}
    category_severity: Dict[ArtifactCategory, Dict[Severity, int]] = {
        category: _severity_template() for category in ArtifactCategory
    }
    minute_map: Dict[datetime, List[Finding]] = {}

    for finding in items:
        minute = _minute_bucket(finding.timestamp)
        minute_key = _minute_key(minute)
        minute_map.setdefault(minute, []).append(finding)
        heatmap[finding.category][minute_key] = heatmap[finding.category].get(minute_key, 0) + 1
        category_severity[finding.category][finding.severity] += 1

    clusters: List[MinuteCluster] = []
    for minute in sorted(minute_map.keys()):
        bucket_findings = sorted(
            minute_map[minute], key=lambda f: (f.severity.value, f.category.value, f.title)
        )
        breakdown: Dict[ArtifactCategory, MinuteCategoryBreakdown] = {}
        for finding in bucket_findings:
            entry = breakdown.setdefault(
                finding.category, MinuteCategoryBreakdown(category=finding.category)
            )
            entry.increment(finding.severity)
        clusters.append(MinuteCluster(minute=minute, findings=bucket_findings, category_breakdown=breakdown))

    return CorrelationSummary(clusters, heatmap, category_severity)


def _minute_bucket(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.replace(second=0, microsecond=0)


def _minute_key(value: datetime) -> str:
    return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
