from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .context import ScanContext
from .models import Finding, ScanSummary, Severity
from .utils import load_asset_text


class ReportBuilder:
    def __init__(self, context: ScanContext, summary: ScanSummary) -> None:
        self.context = context
        self.summary = summary

    def as_html(self) -> str:
        info = self.context.system_info
        correlation = self.summary.correlation
        
        if not correlation:
            return self._legacy_html()
        
        risk_score = correlation.risk_score
        bypass_score = correlation.bypass_score
        risk_color = self._risk_color(risk_score)
        risk_label = self._risk_label(risk_score)
        
        # Severity cards
        severity_cards = "".join(
            f'<div class="sev-card {severity.value.lower()}"><span>{severity.value}</span><strong>{count}</strong></div>'
            for severity, count in self.summary.severity_buckets().items()
        )
        
        # Risk gauge HTML
        gauge_html = f"""
        <div class="gauge-container">
            <svg viewBox="0 0 200 120" class="gauge-svg">
                <path d="M 20 100 A 80 80 0 0 1 180 100" stroke="#1a1f3a" stroke-width="20" fill="none"/>
                <path d="M 20 100 A 80 80 0 0 1 180 100" stroke="{risk_color}" stroke-width="20" fill="none"
                      stroke-dasharray="251" stroke-dashoffset="{251 - (251 * risk_score / 100)}" class="gauge-arc"/>
                <text x="100" y="85" text-anchor="middle" class="gauge-text">{risk_score}</text>
                <text x="100" y="105" text-anchor="middle" class="gauge-label">{risk_label}</text>
            </svg>
        </div>
        """
        
        # Clearing patterns
        clearing_html = ""
        if correlation.clearing_patterns:
            patterns_list = "".join(f"<li class='pattern-item'>🔥 {html.escape(p)}</li>" for p in correlation.clearing_patterns)
            clearing_html = f"""
            <section class="clearing-patterns">
                <h2>🚨 Clearing Patterns Detected</h2>
                <ul class="pattern-list">{patterns_list}</ul>
            </section>
            """
        
        # Evidence chains
        chains_html = ""
        if correlation.evidence_chains:
            chain_rows = []
            for chain in correlation.evidence_chains:
                gun_badge = "💥" if chain.smoking_gun else ""
                steps_text = " → ".join(step.action for step in chain.steps)
                chain_rows.append(f"""
                <tr class="chain-row">
                    <td class="chain-id">{html.escape(chain.chain_id)}</td>
                    <td class="chain-subject">{gun_badge} {html.escape(chain.subject)}</td>
                    <td class="chain-steps">{html.escape(steps_text)}</td>
                    <td class="chain-confidence">{html.escape(chain.confidence)}</td>
                    <td class="chain-summary">{html.escape(chain.summary)}</td>
                </tr>
                """)
            chains_html = f"""
            <section class="evidence-chains">
                <h2>🔗 Evidence Chains</h2>
                <table class="chains-table">
                    <thead>
                        <tr><th>ID</th><th>Subject</th><th>Steps</th><th>Confidence</th><th>Summary</th></tr>
                    </thead>
                    <tbody>{''.join(chain_rows)}</tbody>
                </table>
            </section>
            """
        
        # Counter-bypass matrix
        matrix_rows = []
        for entry in correlation.counter_matrix:
            status_class = "breached" if entry.status == "BREACHED" else "clean"
            matrix_rows.append(f"""
            <tr class="matrix-row {status_class}">
                <td class="matrix-label">{html.escape(entry.label)}</td>
                <td class="matrix-status">{html.escape(entry.status)}</td>
                <td class="matrix-detail">{html.escape(entry.detail)}</td>
                <td class="matrix-severity">{html.escape(entry.severity.value)}</td>
            </tr>
            """)
        matrix_html = f"""
        <section class="counter-matrix">
            <h2>🛡️ Counter-Bypass Matrix (Bypass Score: {bypass_score}/40)</h2>
            <table class="matrix-table">
                <thead>
                    <tr><th>Indicator</th><th>Status</th><th>Detail</th><th>Severity</th></tr>
                </thead>
                <tbody>{''.join(matrix_rows)}</tbody>
            </table>
        </section>
        """
        
        # Minecraft/Gaming Highlight Cards
        highlight_html = ""
        if correlation.highlight_cards:
            cards_html = "".join(f"""
            <div class="highlight-card {card.severity.value.lower()}">
                <div class="card-emoji">{card.emoji}</div>
                <div class="card-title">{html.escape(card.title)}</div>
                <div class="card-subtitle">{html.escape(card.subtitle)}</div>
            </div>
            """ for card in correlation.highlight_cards)
            highlight_html = f"""
            <section class="highlights">
                <h2>🎮 Game-Related Artifacts</h2>
                <div class="highlight-grid">{cards_html}</div>
            </section>
            """
        
        # Ban evasion summary
        ban_html = f"""
        <section class="ban-summary">
            <h2>🔍 Ban-Evasion Summary</h2>
            <p class="ban-text">{html.escape(correlation.ban_evasion_summary)}</p>
        </section>
        """
        
        # Timeline
        timeline_items = []
        for event in correlation.timeline:
            finding = event.finding
            gun_icon = "💥" if finding.smoking_gun else ""
            timeline_items.append(f"""
            <li class="timeline-item {finding.severity.value.lower()}">
                <span class="timeline-time">{event.timestamp.strftime('%H:%M:%S')}</span>
                <span class="timeline-action">{html.escape(event.action)}</span>
                <span class="timeline-subject">{gun_icon} {html.escape(event.subject)}</span>
                <span class="timeline-title">{html.escape(finding.title)}</span>
            </li>
            """)
        timeline_html = f"""
        <section class="timeline">
            <h2>⏱️ Timeline Reconstruction</h2>
            <ul class="timeline-list">{''.join(timeline_items)}</ul>
        </section>
        """
        
        # Findings table
        findings_rows = []
        for finding in self.summary.findings:
            gun_icon = "💥" if finding.smoking_gun else ""
            confidence_pct = int(finding.confidence * 100)
            findings_rows.append(f"""
            <tr class="finding-row {finding.severity.value.lower()}">
                <td>{gun_icon}</td>
                <td>{html.escape(finding.correlation_id or "")}</td>
                <td><span class="sev-badge {finding.severity.value.lower()}">{finding.severity.value}</span></td>
                <td>{html.escape(finding.category.value)}</td>
                <td>{html.escape(finding.title)}</td>
                <td>{html.escape(finding.location)}</td>
                <td>{finding.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td>{confidence_pct}%</td>
                <td class="finding-desc">{html.escape(finding.description)}</td>
            </tr>
            """)
        findings_html = f"""
        <section class="findings">
            <h2>📋 All Findings</h2>
            <table class="findings-table">
                <thead>
                    <tr><th>🔥</th><th>ID</th><th>Severity</th><th>Category</th><th>Title</th><th>Location</th><th>Timestamp</th><th>Confidence</th><th>Description</th></tr>
                </thead>
                <tbody>{''.join(findings_rows)}</tbody>
            </table>
        </section>
        """
        
        html_doc = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8"/>
            <title>Forensic Scanner Report</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    background: linear-gradient(135deg, #0a0e27 0%, #16213e 100%);
                    color: #e0fce9;
                    font-family: 'Consolas', 'Courier New', monospace;
                    padding: 20px;
                    line-height: 1.6;
                }}
                .container {{ max-width: 1800px; margin: 0 auto; }}
                h1 {{
                    color: #00ff88;
                    text-align: center;
                    font-size: 2.5em;
                    text-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
                    margin-bottom: 10px;
                }}
                h2 {{
                    color: #ff00ff;
                    margin: 30px 0 15px;
                    font-size: 1.8em;
                    text-shadow: 0 0 15px rgba(255, 0, 255, 0.4);
                }}
                .system-info {{
                    background: rgba(16, 21, 51, 0.8);
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                    border: 1px solid #ff00ff;
                }}
                .severity-overview {{
                    display: flex;
                    gap: 15px;
                    margin: 20px 0;
                    flex-wrap: wrap;
                }}
                .sev-card {{
                    flex: 1;
                    min-width: 150px;
                    padding: 20px;
                    border-radius: 10px;
                    background: rgba(16, 21, 51, 0.8);
                    text-align: center;
                    border: 2px solid;
                }}
                .sev-card.critical {{ border-color: #ff0066; }}
                .sev-card.high {{ border-color: #ff7b00; }}
                .sev-card.medium {{ border-color: #f6c344; }}
                .sev-card.low {{ border-color: #7a8ea0; }}
                .sev-card span {{ display: block; font-size: 0.9em; margin-bottom: 5px; }}
                .sev-card strong {{ font-size: 2em; color: #00ff88; }}
                .gauge-container {{
                    display: flex;
                    justify-content: center;
                    margin: 30px 0;
                }}
                .gauge-svg {{
                    width: 300px;
                    height: 180px;
                }}
                .gauge-arc {{
                    transition: stroke-dashoffset 1s ease;
                }}
                .gauge-text {{
                    font-size: 36px;
                    font-weight: bold;
                    fill: #00ff88;
                }}
                .gauge-label {{
                    font-size: 14px;
                    fill: #c4ffe8;
                }}
                section {{
                    background: rgba(16, 21, 51, 0.6);
                    padding: 25px;
                    border-radius: 10px;
                    margin: 25px 0;
                    border: 1px solid #2a3555;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #2a3555;
                }}
                th {{
                    color: #00ff88;
                    font-weight: bold;
                    background: rgba(0, 255, 136, 0.1);
                }}
                tr:hover {{
                    background: rgba(0, 255, 136, 0.05);
                }}
                .sev-badge {{
                    display: inline-block;
                    padding: 4px 10px;
                    border-radius: 5px;
                    font-size: 0.85em;
                    font-weight: bold;
                }}
                .sev-badge.critical {{ background: #ff0066; color: #fff; }}
                .sev-badge.high {{ background: #ff7b00; color: #fff; }}
                .sev-badge.medium {{ background: #f6c344; color: #000; }}
                .sev-badge.low {{ background: #7a8ea0; color: #fff; }}
                .clearing-patterns {{
                    border: 2px solid #ff0066;
                }}
                .pattern-list {{
                    list-style: none;
                    padding-left: 0;
                }}
                .pattern-item {{
                    padding: 10px;
                    margin: 8px 0;
                    background: rgba(255, 0, 102, 0.1);
                    border-left: 4px solid #ff0066;
                    border-radius: 5px;
                }}
                .chain-id {{
                    color: #ff00ff;
                    font-weight: bold;
                }}
                .matrix-row.breached {{
                    background: rgba(255, 0, 102, 0.15);
                }}
                .matrix-row.clean {{
                    background: rgba(0, 255, 136, 0.05);
                }}
                .matrix-status {{
                    font-weight: bold;
                    color: #ff0066;
                }}
                .matrix-row.clean .matrix-status {{
                    color: #00ff88;
                }}
                .highlight-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                    gap: 15px;
                    margin-top: 15px;
                }}
                .highlight-card {{
                    padding: 20px;
                    border-radius: 10px;
                    border: 2px solid;
                    text-align: center;
                }}
                .highlight-card.critical {{ border-color: #ff0066; background: rgba(255, 0, 102, 0.1); }}
                .highlight-card.high {{ border-color: #ff7b00; background: rgba(255, 123, 0, 0.1); }}
                .highlight-card.medium {{ border-color: #f6c344; background: rgba(246, 195, 68, 0.1); }}
                .card-emoji {{ font-size: 3em; margin-bottom: 10px; }}
                .card-title {{ font-size: 1.2em; font-weight: bold; color: #00ff88; }}
                .card-subtitle {{ font-size: 0.9em; color: #c4ffe8; margin-top: 5px; }}
                .ban-text {{
                    font-size: 1.1em;
                    padding: 15px;
                    background: rgba(255, 0, 255, 0.1);
                    border-left: 4px solid #ff00ff;
                    border-radius: 5px;
                }}
                .timeline-list {{
                    list-style: none;
                    padding-left: 0;
                }}
                .timeline-item {{
                    padding: 10px;
                    margin: 5px 0;
                    border-left: 3px solid #00ff88;
                    padding-left: 15px;
                    background: rgba(0, 255, 136, 0.05);
                    border-radius: 3px;
                }}
                .timeline-item.critical {{ border-left-color: #ff0066; }}
                .timeline-item.high {{ border-left-color: #ff7b00; }}
                .timeline-time {{
                    display: inline-block;
                    width: 90px;
                    color: #ff00ff;
                    font-weight: bold;
                }}
                .timeline-action {{
                    display: inline-block;
                    width: 120px;
                    color: #00ff88;
                }}
                .finding-desc {{
                    max-width: 400px;
                    white-space: normal;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 FORENSIC SCANNER v2.0</h1>
                <p style="text-align:center; color:#c4ffe8; margin-bottom:30px;">Generated: {datetime.utcnow().isoformat()}Z</p>
                
                <div class="system-info">
                    <h2>💻 System Information</h2>
                    <p><strong>Host:</strong> {html.escape(info.hostname)} | <strong>User:</strong> {html.escape(info.username)} ({html.escape(info.user_sid)})</p>
                    <p><strong>OS:</strong> {html.escape(info.os_version)}</p>
                </div>
                
                <section>
                    <h2>📊 Risk Assessment</h2>
                    {gauge_html}
                    <div class="severity-overview">{severity_cards}</div>
                </section>
                
                {clearing_html}
                {chains_html}
                {matrix_html}
                {highlight_html}
                {ban_html}
                {timeline_html}
                {findings_html}
            </div>
        </body>
        </html>
        """
        return html_doc

    def _legacy_html(self) -> str:
        """Fallback HTML when no correlation data available"""
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
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8" />
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
                <ul class="timeline">{timeline}</ul>
            </section>
        </body>
        </html>
        """

    def _html_row(self, finding: Finding) -> str:
        return (
            f"<tr><td>{finding.severity.value}</td><td>{finding.category.value}</td><td>{finding.title}</td>"
            f"<td>{finding.location}</td><td>{finding.timestamp.isoformat()}</td><td>{finding.description}</td></tr>"
        )

    def _risk_color(self, score: int) -> str:
        if score >= 80:
            return "#ff0066"
        elif score >= 60:
            return "#ff7b00"
        elif score >= 40:
            return "#f6c344"
        else:
            return "#00ff88"

    def _risk_label(self, score: int) -> str:
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "ELEVATED"
        elif score >= 20:
            return "MODERATE"
        else:
            return "LOW"

    def as_csv(self) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["correlation_id", "severity", "category", "title", "location", "timestamp", "confidence", "smoking_gun", "tags", "description"])
        for finding in self.summary.findings:
            writer.writerow(
                [
                    finding.correlation_id or "",
                    finding.severity.value,
                    finding.category.value,
                    finding.title,
                    finding.location,
                    finding.timestamp.isoformat(),
                    f"{finding.confidence:.2f}",
                    "YES" if finding.smoking_gun else "NO",
                    "; ".join(finding.tags),
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
        if self.summary.correlation:
            corr = self.summary.correlation
            payload["correlation"] = {
                "risk_score": corr.risk_score,
                "bypass_score": corr.bypass_score,
                "clearing_patterns": corr.clearing_patterns,
                "ban_evasion_summary": corr.ban_evasion_summary,
                "evidence_chains": [
                    {
                        "chain_id": chain.chain_id,
                        "subject": chain.subject,
                        "confidence": chain.confidence,
                        "smoking_gun": chain.smoking_gun,
                        "summary": chain.summary,
                        "steps": [
                            {
                                "action": step.action,
                                "subject": step.subject,
                                "timestamp": step.timestamp.isoformat(),
                                "finding_id": step.finding.correlation_id,
                            }
                            for step in chain.steps
                        ],
                    }
                    for chain in corr.evidence_chains
                ],
                "counter_matrix": [
                    {
                        "label": entry.label,
                        "status": entry.status,
                        "detail": entry.detail,
                        "severity": entry.severity.value,
                    }
                    for entry in corr.counter_matrix
                ],
            }
        return json.dumps(payload, indent=2)

    def as_text(self) -> str:
        lines = ["FORENSIC SCANNER v2.0", "======================", ""]
        
        if self.summary.correlation:
            corr = self.summary.correlation
            lines.append(f"Risk Score: {corr.risk_score}/100")
            lines.append(f"Bypass Score: {corr.bypass_score}/40")
            lines.append("")
            
            if corr.clearing_patterns:
                lines.append("Clearing Patterns:")
                for pattern in corr.clearing_patterns:
                    lines.append(f"  - {pattern}")
                lines.append("")
            
            lines.append(corr.ban_evasion_summary)
            lines.append("")
        
        lines.append("Severity Overview:")
        lines.extend(self._severity_ascii())
        lines.append("")
        
        for finding in self.summary.findings:
            gun = " [SMOKING GUN]" if finding.smoking_gun else ""
            corr_id = f" ({finding.correlation_id})" if finding.correlation_id else ""
            lines.append(
                f"[{finding.severity.value}]{gun} {finding.title}{corr_id} | {finding.location} | {finding.timestamp.isoformat()}"
            )
            lines.append(f"    {finding.description}")
            if finding.tags:
                lines.append(f"    Tags: {', '.join(finding.tags)}")
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
