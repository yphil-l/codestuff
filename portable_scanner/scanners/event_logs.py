from __future__ import annotations

import json
import textwrap
from datetime import datetime, timezone
from typing import Dict, Iterable, List

from ..context import ScanContext
from ..models import ArtifactCategory, Finding, Severity
from ..utils import detect_keywords
from .base import ArtifactScanner


class EventLogScanner(ArtifactScanner):
    category = ArtifactCategory.EVENT_LOGS
    name = "Event Logs"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        findings: List[Finding] = []
        if not context.is_windows:
            context.log("Event log scanning is only supported on Windows hosts.")
            return findings

        findings.extend(self._check_service(context))
        lookback = context.options.lookback_hours
        queries = [
            ("Security", SECURITY_EVENTS),
            ("System", SYSTEM_EVENTS),
            ("Application", APPLICATION_EVENTS),
            ("Setup", SETUP_EVENTS),
            ("Microsoft-Windows-TaskScheduler/Operational", TASK_EVENTS),
            ("Microsoft-Windows-PowerShell/Operational", POWERSHELL_EVENTS),
        ]
        for log_name, meta in queries:
            events = self._query_log(context, log_name, meta.keys(), lookback)
            for evt in events:
                severity, title = meta.get(evt.get("Id"), (Severity.LOW, "Event"))
                message = evt.get("Message", "").strip()
                timestamp = _parse_timestamp(evt.get("TimeCreated"))
                if log_name.endswith("PowerShell/Operational"):
                    severity = Severity.HIGH if detect_keywords(message, context.options.keyword_indicators) else Severity.MEDIUM
                if log_name == "Application" and not detect_keywords(message, context.options.keyword_indicators):
                    continue
                findings.append(
                    Finding(
                        severity=severity,
                        category=self.category,
                        title=title,
                        location=f"{log_name} Event {evt.get('Id')}",
                        timestamp=timestamp,
                        description=message,
                    )
                )
            if log_name == "Security":
                failed = sum(1 for evt in events if evt.get("Id") == 4625)
                if failed >= 5:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category=self.category,
                            title="Multiple failed logon attempts",
                            location="Security log",
                            timestamp=datetime.now(timezone.utc),
                            description=f"Detected {failed} failed logons inside lookback window",
                        )
                    )

        return findings

    def _check_service(self, context: ScanContext) -> List[Finding]:
        try:
            result = context.run_command(["sc", "query", "eventlog"], timeout=10)
        except FileNotFoundError:
            return []
        normalized = result.stdout.lower()
        findings: List[Finding] = []
        if "stopped" in normalized:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category=self.category,
                    title="EventLog service stopped",
                    location="Service: eventlog",
                    timestamp=datetime.now(timezone.utc),
                    description="Windows Event Log service is not running",
                )
            )
        return findings

    def _query_log(
        self,
        context: ScanContext,
        log_name: str,
        ids: Iterable[int],
        lookback_hours: int,
        limit: int = 180,
    ) -> List[Dict[str, str]]:
        id_list = ",".join(str(event_id) for event_id in ids)
        script = textwrap.dedent(
            f"""
            $start = (Get-Date).AddHours(-{lookback_hours});
            $ids = @({id_list});
            try {{
                Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; Id=$ids; StartTime=$start}} -MaxEvents {limit} |
                    Select-Object Id, TimeCreated, Message |
                    ConvertTo-Json -Compress
            }} catch {{ }}
            """
        )
        result = context.run_powershell(script, timeout=240)
        payload = result.stdout.strip()
        if not payload:
            return []
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            context.log(f"Unable to parse JSON from {log_name} query")
            return []
        if isinstance(data, list):
            return data
        return [data]


def _parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


SECURITY_EVENTS: Dict[int, tuple[Severity, str]] = {
    1102: (Severity.CRITICAL, "Security log cleared"),
    4616: (Severity.HIGH, "System time change detected"),
    4624: (Severity.LOW, "Successful logon"),
    4625: (Severity.HIGH, "Failed logon attempt"),
    4720: (Severity.HIGH, "User account created"),
    4721: (Severity.HIGH, "User password reset"),
    4722: (Severity.HIGH, "User account enabled"),
    4726: (Severity.HIGH, "User account deleted"),
    4728: (Severity.HIGH, "Privileged group membership change"),
    4738: (Severity.HIGH, "Account modified"),
    5031: (Severity.MEDIUM, "Firewall policy change"),
}

SYSTEM_EVENTS: Dict[int, tuple[Severity, str]] = {
    104: (Severity.CRITICAL, "System log cleared"),
    7034: (Severity.MEDIUM, "Service crashed"),
    7040: (Severity.HIGH, "Service start type changed"),
    7045: (Severity.HIGH, "New service installed"),
    6005: (Severity.LOW, "Event log service started"),
    4616: (Severity.HIGH, "Time change recorded"),
}

APPLICATION_EVENTS: Dict[int, tuple[Severity, str]] = {
    3079: (Severity.CRITICAL, "USN journal deleted"),
    1000: (Severity.MEDIUM, "Application crash"),
    1001: (Severity.MEDIUM, "Windows Error Reporting"),
}

SETUP_EVENTS = {2: (Severity.MEDIUM, "Software installation detected")}
TASK_EVENTS = {
    106: (Severity.HIGH, "Scheduled task registered"),
    129: (Severity.MEDIUM, "Scheduled task executed"),
    140: (Severity.MEDIUM, "Task updated"),
}
POWERSHELL_EVENTS = {4103: (Severity.MEDIUM, "PowerShell command"), 4104: (Severity.MEDIUM, "PowerShell script"), 4105: (Severity.MEDIUM, "PowerShell start"), 4106: (Severity.MEDIUM, "PowerShell end")}
