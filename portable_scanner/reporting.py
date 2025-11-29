from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .analytics import MinuteCategoryBreakdown, build_correlation_summary
from .context import ScanContext
from .models import ArtifactCategory, Finding, ScanSummary, Severity


class ReportBuilder:
    def __init__(self, context: ScanContext, summary: ScanSummary) -> None:
        self.context = context
        self.summary = summary
        self.correlation = build_correlation_summary(self.summary.findings)

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
        correlation_timeline = self._correlation_timeline_html()
        heatmap_html = self._heatmap_table_html()
        severity_matrix = self._category_severity_table_html()
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
                .corr-list {{ list-style:none; padding-left:0; }}
                .corr-list li {{ margin-bottom:6px; }}
                .matrix-table {{ width:100%; border-collapse:collapse; margin-top:12px; font-size:13px; }}
                .matrix-table th, .matrix-table td {{ border:1px solid #222842; padding:6px; text-align:left; }}
                .matrix-table th {{ background:#0b0f29; }}
                .matrix-table td.hot {{ background:#162041; }}
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
            <section>
                <h2>Correlation Timeline</h2>
                {correlation_timeline}
            </section>
            <section>
                <h2>Category vs Time Heatmap</h2>
                {heatmap_html}
            </section>
            <section>
                <h2>Per-Category Severity Tallies</h2>
                {severity_matrix}
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

    def _correlation_timeline_html(self) -> str:
        if self.correlation.is_empty:
            return "<p>No correlated artifacts detected within the scan window.</p>"
        items = []
        for cluster in self.correlation.minute_clusters:
            minute_label = cluster.minute.strftime("%Y-%m-%d %H:%MZ")
            category_bits = ", ".join(
                self._format_category_chip(breakdown)
                for breakdown in sorted(
                    cluster.category_breakdown.values(), key=lambda item: item.category.value
                )
            )
            items.append(f"<li><strong>{minute_label}</strong> — {category_bits}</li>")
        return f"<ul class='corr-list'>{''.join(items)}</ul>"

    def _format_category_chip(self, breakdown: MinuteCategoryBreakdown) -> str:
        severity_bits = ", ".join(
            f"{severity.value[0]}:{count}"
            for severity, count in breakdown.severity_counts.items()
            if count
        )
        if severity_bits:
            return f"{breakdown.category.value} ({breakdown.count} | {severity_bits})"
        return f"{breakdown.category.value} ({breakdown.count})"

    def _heatmap_table_html(self) -> str:
        minutes = self.correlation.ordered_minutes()
        if not minutes:
            return "<p>No overlapping minute-level activity recorded.</p>"
        header_cells = "".join(f"<th>{self._label_minute(minute)}</th>" for minute in minutes)
        rows = []
        for category in ArtifactCategory:
            heatmap = self.correlation.category_heatmap.get(category, {})
            cells = []
            for minute in minutes:
                value = heatmap.get(minute)
                cell_class = "hot" if value else ""
                display = value if value else ""
                cells.append(f"<td class='{cell_class}'>{display}</td>")
            rows.append(f"<tr><td>{category.value}</td>{''.join(cells)}</tr>")
        return (
            "<table class='matrix-table'><thead><tr><th>Category</th>"
            f"{header_cells}</tr></thead><tbody>{''.join(rows)}</tbody></table>"
        )

    def _category_severity_table_html(self) -> str:
        header_cells = "".join(f"<th>{severity.value}</th>" for severity in Severity)
        rows = []
        for category in ArtifactCategory:
            counts = self.correlation.category_severity.get(category, {})
            total = sum(counts.values()) if counts else 0
            severity_cells = "".join(f"<td>{counts.get(severity, 0)}</td>" for severity in Severity)
            rows.append(f"<tr><td>{category.value}</td>{severity_cells}<td>{total}</td></tr>")
        return (
            "<table class='matrix-table'><thead><tr><th>Category</th>"
            f"{header_cells}<th>Total</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
        )

    @staticmethod
    def _label_minute(value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.strftime("%m-%d %H:%M") + "Z"
        except ValueError:
            return value

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
        writer.writerow([])
        writer.writerow(["correlation_timeline"])
        writer.writerow(["minute", "categories", "total_findings"])
        for cluster in self.correlation.minute_clusters:
            categories = "; ".join(
                self._format_category_chip(breakdown)
                for breakdown in sorted(
                    cluster.category_breakdown.values(), key=lambda item: item.category.value
                )
            )
            writer.writerow([cluster.minute.isoformat(), categories, len(cluster.findings)])
        minutes = self.correlation.ordered_minutes()
        if minutes:
            writer.writerow([])
            writer.writerow(["category_vs_time_heatmap"])
            writer.writerow(["category", *[self._label_minute(minute) for minute in minutes]])
            for category in ArtifactCategory:
                heatmap = self.correlation.category_heatmap.get(category, {})
                writer.writerow([category.value, *[heatmap.get(minute, "") for minute in minutes]])
        writer.writerow([])
        writer.writerow(["category_severity_tallies"])
        writer.writerow(["category", *[severity.value for severity in Severity], "total"])
        for category in ArtifactCategory:
            counts = self.correlation.category_severity.get(category, {})
            total = sum(counts.values()) if counts else 0
            row = [category.value]
            for severity in Severity:
                row.append(counts.get(severity, 0))
            row.append(total)
            writer.writerow(row)
        return output.getvalue()

    def as_json(self) -> str:
        payload = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "system": self.context.system_info.__dict__,
            "findings": [finding.to_dict() for finding in self.summary.findings],
            "correlation": self.correlation.to_dict(),
        }
        return json.dumps(payload, indent=2)

    def as_text(self) -> str:
        lines = ["FORENSIC SCANNER v1.0", "======================", ""]
        lines.append("Severity Overview:")
        lines.extend(self._severity_ascii())
        lines.append("")
        lines.append("Correlation Timeline:")
        lines.extend(self._correlation_ascii())
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

    def _correlation_ascii(self) -> Iterable[str]:
        if self.correlation.is_empty:
            return [" - No correlated findings detected"]
        lines = []
        for cluster in self.correlation.top_clusters():
            categories = ", ".join(
                f"{breakdown.category.value}({breakdown.count})"
                for breakdown in sorted(
                    cluster.category_breakdown.values(), key=lambda item: item.category.value
                )
            )
            lines.append(f" - {cluster.minute.strftime('%Y-%m-%d %H:%M')}Z :: {categories}")
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
