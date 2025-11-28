from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .context import ScanContext
from .models import Finding, ScanSummary, Severity


class ReportBuilder:
    def __init__(self, context: ScanContext, summary: ScanSummary) -> None:
        self.context = context
        self.summary = summary

    def as_html(self) -> str:
        info = self.context.system_info
        rows = "".join(self._html_row(finding) for finding in self.summary.findings)
        timeline = "".join(
            f"<li>[{finding.timestamp:%H:%M:%S}] <strong>{finding.severity.value}</strong> - {finding.title} — {finding.location}</li>"
            for finding in sorted(self.summary.findings, key=lambda f: f.timestamp)
        )
        severity_cards = "".join(
            f"<div class='sev-card {severity.value.lower()}'><span>{severity.value}</span><strong>{count}</strong></div>"
            for severity, count in self.summary.severity_buckets().items()
        )
        html = f"""
        <!DOCTYPE html>
        <html lang=\"en\">
        <head>
            <meta charset=\"utf-8\" />
            <title>Forensic Scanner Report</title>
            <style>
                body {{ background:#050710; color:#e0fce9; font-family:'Consolas','Courier New',monospace; }}
                h1 {{ color:#00ff88; }}
                table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
                th, td {{ border-bottom:1px solid #222842; padding:8px; text-align:left; }}
                th {{ color:#00ff88; }}
                .sev-card {{ display:inline-block; margin-right:12px; padding:12px 18px; border-radius:8px; background:#101533; }}
                .sev-card.critical {{ border:1px solid #ff00ff; }}
                .sev-card.high {{ border:1px solid #ff7b00; }}
                .sev-card.medium {{ border:1px solid #f6c344; }}
                .sev-card.low {{ border:1px solid #7a8ea0; }}
                .timeline {{ list-style:none; padding-left:0; }}
                .timeline li {{ margin-bottom:6px; }}
            </style>
        </head>
        <body>
            <h1>FORENSIC SCANNER v1.0 - Report</h1>
            <p>Generated: {datetime.utcnow().isoformat()}Z</p>
            <section>
                <h2>System Info</h2>
                <p>Host: {info.hostname} | User: {info.username} ({info.user_sid}) | OS: {info.os_version}</p>
            </section>
            <section>
                <h2>Severity Overview</h2>
                {severity_cards}
            </section>
            <section>
                <h2>Findings</h2>
                <table>
                    <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Location</th><th>Timestamp</th><th>Description</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </section>
            <section>
                <h2>Timeline</h2>
                <ul class=\"timeline\">{timeline}</ul>
            </section>
        </body>
        </html>
        """
        return html

    def _html_row(self, finding: Finding) -> str:
        return (
            f"<tr><td>{finding.severity.value}</td><td>{finding.category.value}</td><td>{finding.title}</td>"
            f"<td>{finding.location}</td><td>{finding.timestamp.isoformat()}</td><td>{finding.description}</td></tr>"
        )

    def as_csv(self) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["severity", "category", "title", "location", "timestamp", "description"])
        for finding in self.summary.findings:
            writer.writerow(
                [
                    finding.severity.value,
                    finding.category.value,
                    finding.title,
                    finding.location,
                    finding.timestamp.isoformat(),
                    finding.description,
                ]
            )
        return output.getvalue()

    def as_json(self) -> str:
        payload = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "system": self.context.system_info.__dict__,
            "findings": [finding.to_dict() for finding in self.summary.findings],
        }
        return json.dumps(payload, indent=2)

    def as_text(self) -> str:
        lines = ["FORENSIC SCANNER v1.0", "======================", ""]
        lines.append("Severity Overview:")
        lines.extend(self._severity_ascii())
        lines.append("")
        for finding in self.summary.findings:
            lines.append(
                f"[{finding.severity.value}] {finding.title} | {finding.location} | {finding.timestamp.isoformat()}"
            )
            lines.append(f"    {finding.description}")
        return "\n".join(lines)

    def _severity_ascii(self) -> Iterable[str]:
        total = sum(self.summary.severity_buckets().values()) or 1
        lines = []
        for severity, count in self.summary.severity_buckets().items():
            bar = "#" * max(1, int((count / total) * 20))
            lines.append(f" - {severity.value:<8} [{bar:<20}] {count}")
        return lines


def export_reports(
    context: ScanContext,
    summary: ScanSummary,
    directory: Path,
    base_name: str = "forensic_report",
) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    builder = ReportBuilder(context, summary)
    outputs = {
        "html": directory / f"{base_name}.html",
        "csv": directory / f"{base_name}.csv",
        "json": directory / f"{base_name}.json",
        "txt": directory / f"{base_name}.txt",
    }
    outputs["html"].write_text(builder.as_html(), encoding="utf-8")
    outputs["csv"].write_text(builder.as_csv(), encoding="utf-8")
    outputs["json"].write_text(builder.as_json(), encoding="utf-8")
    outputs["txt"].write_text(builder.as_text(), encoding="utf-8")
    return outputs
