from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from .models import ArtifactCategory, Finding, ScanSummary, Severity

FILENAME_RE = re.compile(r"([A-Za-z0-9_\-\.]{4,}\.(?:exe|dll|jar|bat|cmd|ps1|zip|rar|msi|sys|lnk))", re.IGNORECASE)
BAN_KEYWORDS = ("spoof", "ban", "clean", "evade", "inject", "macro", "bypass", "hwid")
MINECRAFT_KEYWORDS = ("minecraft", "fabric", "forge", "lunar", "badlion", "feather", "schematica", "client")
SMOKING_KEYWORDS = ("fsutil", "clear", "inject", "encodedcommand", "spoof", "aimbot", "usn", "prefetch")
CONFIDENCE_MAP = {
    Severity.CRITICAL: 0.97,
    Severity.HIGH: 0.88,
    Severity.MEDIUM: 0.72,
    Severity.LOW: 0.55,
}
SEVERITY_WEIGHT = {
    Severity.CRITICAL: 14,
    Severity.HIGH: 9,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
}
SEVERITY_ORDER = {severity: index for index, severity in enumerate(Severity.ordered())}
COUNTER_SPECS: List[tuple[str, ArtifactCategory, Iterable[str]]] = [
    ("Event Log Integrity", ArtifactCategory.EVENT_LOGS, ("clear", "stopped", "1102", "104")),
    ("Prefetch Health", ArtifactCategory.PREFETCH, ("disabled", "missing", "empty")),
    ("USN Journal Health", ArtifactCategory.USN, ("delete", "truncate", "142", "3079")),
    ("Scheduled Cleanup Tasks", ArtifactCategory.TASK_SCHEDULER, ("clean", "delete", "encoded", "powershell")),
    ("USB / External Media", ArtifactCategory.EVENT_LOGS, ("usb", "removable", "mass storage", "device")),
    ("Shadow Copy Tampering", ArtifactCategory.VSS, ("delete", "removed", "missing")),
    ("Encrypted Containers", ArtifactCategory.ENCRYPTED_VOLUMES, ("locked", "bitlocker", "veracrypt", "truecrypt")),
    ("Hidden ADS Payloads", ArtifactCategory.ADS, ("stream", "hidden", "payload", "ads")),
]


@dataclass
class TimelineEvent:
    finding: Finding
    subject: str
    action: str
    timestamp: datetime


@dataclass
class EvidenceChain:
    chain_id: str
    subject: str
    steps: List[TimelineEvent]
    confidence: str
    smoking_gun: bool
    summary: str


@dataclass
class CounterMatrixEntry:
    label: str
    status: str
    detail: str
    severity: Severity


@dataclass
class HighlightCard:
    title: str
    subtitle: str
    severity: Severity
    emoji: str


@dataclass
class CorrelationResult:
    generated_at: datetime
    risk_score: int
    bypass_score: int
    clearing_patterns: List[str]
    timeline: List[TimelineEvent]
    risk_progression: List[int]
    evidence_chains: List[EvidenceChain]
    counter_matrix: List[CounterMatrixEntry]
    ban_evasion_summary: str
    highlight_cards: List[HighlightCard]


class CorrelationEngine:
    def __init__(self, summary: ScanSummary) -> None:
        self.summary = summary
        self.findings = summary.findings

    def correlate(self) -> CorrelationResult:
        timestamp = datetime.now(timezone.utc)
        if not self.findings:
            result = CorrelationResult(
                generated_at=timestamp,
                risk_score=0,
                bypass_score=0,
                clearing_patterns=[],
                timeline=[],
                risk_progression=[],
                evidence_chains=[],
                counter_matrix=[],
                ban_evasion_summary="No artifacts collected.",
                highlight_cards=[],
            )
            self.summary.correlation = result
            return result

        self._assign_base_metadata()
        timeline = self._build_timeline()
        evidence_chains = self._build_evidence_chains(timeline)
        counter_matrix = self._build_counter_matrix()
        clearing_patterns = self._extract_clearing_patterns(counter_matrix, evidence_chains)
        bypass_score = self._score_bypass(counter_matrix)
        highlight_cards = self._detect_highlights()
        ban_summary = self._build_ban_summary()
        risk_score, progression = self._score_risk(timeline, evidence_chains, bypass_score)

        result = CorrelationResult(
            generated_at=timestamp,
            risk_score=risk_score,
            bypass_score=bypass_score,
            clearing_patterns=clearing_patterns,
            timeline=timeline,
            risk_progression=progression,
            evidence_chains=evidence_chains,
            counter_matrix=counter_matrix,
            ban_evasion_summary=ban_summary,
            highlight_cards=highlight_cards,
        )
        self.summary.correlation = result
        return result

    def _assign_base_metadata(self) -> None:
        sorted_findings = sorted(self.findings, key=lambda f: f.timestamp)
        for index, finding in enumerate(sorted_findings, start=1):
            finding.correlation_id = f"F-{index:04d}"
            finding.confidence = CONFIDENCE_MAP.get(finding.severity, 0.5)
            finding.smoking_gun = self._is_smoking_gun(finding)
            if finding.smoking_gun and "SmokingGun" not in finding.tags:
                finding.tags.append("SmokingGun")

    def _build_timeline(self) -> List[TimelineEvent]:
        timeline: List[TimelineEvent] = []
        for finding in sorted(self.findings, key=lambda f: f.timestamp):
            subject = self._extract_subject(finding)
            action = self._classify_action(finding)
            event = TimelineEvent(
                finding=finding,
                subject=subject,
                action=action,
                timestamp=finding.timestamp,
            )
            if f"ACTION:{action}" not in finding.tags:
                finding.tags.append(f"ACTION:{action}")
            timeline.append(event)
        return timeline

    def _build_evidence_chains(self, timeline: List[TimelineEvent]) -> List[EvidenceChain]:
        subjects: Dict[str, List[TimelineEvent]] = defaultdict(list)
        for event in timeline:
            subjects[event.subject].append(event)

        chains: List[EvidenceChain] = []
        counter = 1
        for subject, events in subjects.items():
            actions = {event.action for event in events}
            ordered_events = sorted(events, key=lambda e: e.timestamp)

            if {"Download", "Execution", "Deletion"}.issubset(actions):
                steps = [event for event in ordered_events if event.action in {"Download", "Execution", "Deletion"}]
                duration = (steps[-1].timestamp - steps[0].timestamp).total_seconds() / 60
                summary = f"{subject} moved from download to deletion in {duration:.1f} min"
                chain_id = f"C-{counter:03d}"
                counter += 1
                chain = EvidenceChain(
                    chain_id=chain_id,
                    subject=subject,
                    steps=steps,
                    confidence="HIGH",
                    smoking_gun=any(step.finding.smoking_gun for step in steps) or duration <= 15,
                    summary=summary,
                )
                self._tag_chain(chain)
                chains.append(chain)
                continue

            if {"USB", "Execution"}.issubset(actions):
                steps = [event for event in ordered_events if event.action in {"USB", "Execution"}]
                chain_id = f"C-{counter:03d}"
                counter += 1
                chain = EvidenceChain(
                    chain_id=chain_id,
                    subject=subject,
                    steps=steps,
                    confidence="MEDIUM",
                    smoking_gun=any(step.finding.severity in {Severity.CRITICAL, Severity.HIGH} for step in steps),
                    summary=f"USB artifact for {subject} linked to live execution",
                )
                self._tag_chain(chain)
                chains.append(chain)

        return chains

    def _build_counter_matrix(self) -> List[CounterMatrixEntry]:
        entries: List[CounterMatrixEntry] = []
        for label, category, keywords in COUNTER_SPECS:
            matches = [finding for finding in self.findings if finding.category == category]
            keyword_matches = [finding for finding in matches if self._contains_any(finding, keywords)] if keywords else matches
            if keyword_matches:
                severity = max(keyword_matches, key=lambda f: SEVERITY_ORDER[f.severity]).severity
                detail = keyword_matches[0].title
                entries.append(
                    CounterMatrixEntry(
                        label=label,
                        status="BREACHED",
                        detail=detail,
                        severity=severity,
                    )
                )
            else:
                entries.append(
                    CounterMatrixEntry(
                        label=label,
                        status="Clean",
                        detail="No tampering observed",
                        severity=Severity.LOW,
                    )
                )
        return entries

    def _extract_clearing_patterns(
        self,
        counter_matrix: List[CounterMatrixEntry],
        chains: List[EvidenceChain],
    ) -> List[str]:
        patterns: List[str] = []
        matrix = {entry.label: entry for entry in counter_matrix}
        if (
            matrix.get("Event Log Integrity")
            and matrix["Event Log Integrity"].status == "BREACHED"
            and matrix.get("USN Journal Health")
            and matrix["USN Journal Health"].status == "BREACHED"
        ):
            patterns.append("Event logs and USN journal were cleared in tandem.")

        if matrix.get("Prefetch Health") and matrix["Prefetch Health"].status == "BREACHED":
            if matrix.get("Scheduled Cleanup Tasks") and matrix["Scheduled Cleanup Tasks"].status == "BREACHED":
                patterns.append("Prefetch tampering tied to scheduled cleanup tasks.")

        for chain in chains:
            if chain.smoking_gun and chain.confidence == "HIGH":
                patterns.append(f"{chain.subject} exhibits full download → execution → deletion sequence.")

        return patterns

    def _score_bypass(self, counter_matrix: List[CounterMatrixEntry]) -> int:
        score = 0
        for entry in counter_matrix:
            if entry.status != "Clean":
                score += {
                    Severity.CRITICAL: 10,
                    Severity.HIGH: 8,
                    Severity.MEDIUM: 5,
                    Severity.LOW: 3,
                }.get(entry.severity, 3)
        return min(40, score)

    def _detect_highlights(self) -> List[HighlightCard]:
        cards: List[HighlightCard] = []
        seen_subjects: set[str] = set()
        for finding in self.findings:
            text = self._combined_text(finding)
            if any(keyword in text for keyword in MINECRAFT_KEYWORDS):
                subject = self._extract_subject(finding)
                if subject in seen_subjects:
                    continue
                seen_subjects.add(subject)
                emoji = {
                    Severity.CRITICAL: "💥",
                    Severity.HIGH: "⚠️",
                    Severity.MEDIUM: "✨",
                    Severity.LOW: "🟢",
                }.get(finding.severity, "🟢")
                cards.append(
                    HighlightCard(
                        title=f"{subject} detected",
                        subtitle=f"{finding.category.value} @ {finding.timestamp.strftime('%H:%M:%S')}",
                        severity=finding.severity,
                        emoji=emoji,
                    )
                )
        return cards

    def _build_ban_summary(self) -> str:
        hits: List[str] = []
        for keyword in BAN_KEYWORDS:
            count = sum(1 for finding in self.findings if keyword in self._combined_text(finding))
            if count:
                hits.append(f"{keyword}×{count}")
        if hits:
            return "Ban-evasion cues: " + ", ".join(hits)
        return "No explicit ban-evasion keywords surfaced."

    def _score_risk(
        self,
        timeline: List[TimelineEvent],
        chains: List[EvidenceChain],
        bypass_score: int,
    ) -> tuple[int, List[int]]:
        score = 0
        progression: List[int] = []
        for event in timeline:
            increment = SEVERITY_WEIGHT.get(event.finding.severity, 1)
            if event.finding.smoking_gun:
                increment += 3
            score = min(100, score + increment)
            progression.append(score)
        chain_bonus = min(20, len(chains) * 4)
        score = min(100, score + chain_bonus + bypass_score)
        if progression:
            progression[-1] = score
        else:
            progression.append(score)
        return score, progression

    def _tag_chain(self, chain: EvidenceChain) -> None:
        for step in chain.steps:
            finding = step.finding
            finding.correlation_id = chain.chain_id
            if f"CHAIN:{chain.chain_id}" not in finding.tags:
                finding.tags.append(f"CHAIN:{chain.chain_id}")
            finding.confidence = min(0.99, finding.confidence + 0.1)
            if chain.smoking_gun:
                finding.smoking_gun = True

    def _classify_action(self, finding: Finding) -> str:
        text = self._combined_text(finding)
        category = finding.category
        if category == ArtifactCategory.SPECIAL_LOCATIONS or "download" in text or "http" in text:
            return "Download"
        if category in {ArtifactCategory.PREFETCH, ArtifactCategory.PROCESSES, ArtifactCategory.ACTIVITIES}:
            return "Execution"
        if category == ArtifactCategory.RECYCLE_BIN or "deleted" in text or "removed" in text:
            return "Deletion"
        if "usb" in text or "removable" in text:
            return "USB"
        if category in {ArtifactCategory.REGISTRY, ArtifactCategory.TASK_SCHEDULER}:
            return "Persistence"
        if category == ArtifactCategory.ADS:
            return "ADS"
        if category == ArtifactCategory.ENCRYPTED_VOLUMES:
            return "Obfuscation"
        if category in {ArtifactCategory.USN, ArtifactCategory.EVENT_LOGS} and ("clear" in text or "truncate" in text):
            return "Anti-Forensic"
        return "Activity"

    def _extract_subject(self, finding: Finding) -> str:
        text = f"{finding.location} {finding.title}"
        match = FILENAME_RE.search(text)
        if match:
            return match.group(1).lower()
        cleaned = finding.title or finding.location
        return cleaned.split("\\")[-1].split("/")[-1].strip() or finding.category.value

    def _is_smoking_gun(self, finding: Finding) -> bool:
        text = self._combined_text(finding)
        return (
            finding.severity in {Severity.CRITICAL, Severity.HIGH}
            and any(keyword in text for keyword in SMOKING_KEYWORDS)
        )

    def _combined_text(self, finding: Finding) -> str:
        return f"{finding.title} {finding.description} {finding.location}".lower()

    def _contains_any(self, finding: Finding, keywords: Iterable[str]) -> bool:
        text = self._combined_text(finding)
        return any(keyword.lower() in text for keyword in keywords)
