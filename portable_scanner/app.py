from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from .context import ScanContext
from .engine import ScanEngine
from .models import ArtifactCategory, Finding, ScanOptions, ScanSummary, Severity
from .reporting import export_reports
from .scanners import build_scanners
from .utils import ensure_admin


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Windows Forensic Scanner")
    parser.add_argument("--nogui", action="store_true", help="Run scanner in console-only mode")
    parser.add_argument("--lookback", type=int, default=4, help="Lookback window in hours")
    parser.add_argument("--deep", action="store_true", help="Enable deep filesystem scan")
    parser.add_argument("--categories", nargs="*", choices=[c.name for c in ArtifactCategory], help="Subset of categories to scan")
    parser.add_argument("--export-dir", type=Path, help="Directory to write reports in CLI mode")
    parser.add_argument("--auto", action="store_true", help="Automatically start scan on GUI launch")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not ensure_admin():
        # A new elevated process has been spawned.
        return 0
    options = ScanOptions(
        lookback_hours=args.lookback,
        deep_scan=args.deep,
        output_directory=str(args.export_dir) if args.export_dir else None,
    )
    if args.nogui:
        return run_cli(options, args.categories, args.export_dir)

    from .gui import ForensicScannerApp

    app = ForensicScannerApp(options)
    if args.auto:
        app.after(500, app.start_scan)
    app.mainloop()
    return 0


def run_cli(options: ScanOptions, category_names: Iterable[str] | None, export_dir: Path | None) -> int:
    scanners = build_scanners()
    engine = ScanEngine(scanners)
    context = ScanContext(
        options=options,
        started_at=datetime.now(timezone.utc),
        logger=lambda msg: print(msg),
    )
    if category_names:
        categories = [ArtifactCategory[name] for name in category_names]
    else:
        categories = [scanner.category for scanner in scanners]
    severity_points = {
        Severity.CRITICAL: 12,
        Severity.HIGH: 8,
        Severity.MEDIUM: 4,
        Severity.LOW: 2,
    }
    live_state = {"score": 0}

    neon_colors = {
        Severity.CRITICAL: "\033[91m",
        Severity.HIGH: "\033[93m",
        Severity.MEDIUM: "\033[96m",
        Severity.LOW: "\033[92m",
    }
    RESET = "\033[0m"

    def live_finding(finding: Finding) -> None:
        increment = severity_points.get(finding.severity, 1)
        live_state["score"] = min(100, live_state["score"] + increment)
        color = neon_colors.get(finding.severity, RESET)
        gun = "💥 " if finding.smoking_gun else ""
        print(
            f"{color}[LIVE] {finding.severity.value:<8}{RESET} {gun}{finding.title}"
            f"  → Risk {live_state['score']:02d}"
        )

    summary = engine.scan(context, categories=categories, on_finding=live_finding)
    display_cli(summary)
    if export_dir:
        export_reports(context, summary, export_dir)
        print(f"Reports exported to {export_dir}")
    return 0


def display_cli(summary: ScanSummary) -> None:
    # ANSI color codes for neon styling
    NEON_PINK = "\033[95m"
    NEON_CYAN = "\033[96m"
    NEON_GREEN = "\033[92m"
    NEON_YELLOW = "\033[93m"
    NEON_RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    
    severity_colors = {
        "CRITICAL": NEON_RED + BOLD,
        "HIGH": NEON_YELLOW,
        "MEDIUM": NEON_CYAN,
        "LOW": NEON_GREEN,
    }
    
    print(f"\n{NEON_PINK}{BOLD}╔═══════════════════════════════════════════════════════════╗{RESET}")
    print(f"{NEON_PINK}{BOLD}║           FORENSIC SCANNER v2.0 - RESULTS                 ║{RESET}")
    print(f"{NEON_PINK}{BOLD}╚═══════════════════════════════════════════════════════════╝{RESET}\n")
    
    # Display correlation summary if available
    if summary.correlation:
        corr = summary.correlation
        risk_color = NEON_RED if corr.risk_score >= 70 else NEON_YELLOW if corr.risk_score >= 40 else NEON_GREEN
        
        print(f"{NEON_CYAN}{BOLD}═══ RISK ASSESSMENT ═══{RESET}")
        print(f"{risk_color}{BOLD}  Risk Score: {corr.risk_score}/100{RESET}")
        print(f"{NEON_YELLOW}  Bypass Score: {corr.bypass_score}/40{RESET}")
        
        if corr.clearing_patterns:
            print(f"\n{NEON_RED}{BOLD}🚨 CLEARING PATTERNS DETECTED:{RESET}")
            for pattern in corr.clearing_patterns:
                print(f"  {NEON_RED}▸ {pattern}{RESET}")
        
        if corr.evidence_chains:
            print(f"\n{NEON_PINK}{BOLD}🔗 EVIDENCE CHAINS: {len(corr.evidence_chains)}{RESET}")
            for chain in corr.evidence_chains[:3]:  # Show top 3
                gun = "💥 " if chain.smoking_gun else ""
                print(f"  {NEON_CYAN}[{chain.chain_id}] {gun}{chain.subject} - {chain.summary}{RESET}")
        
        print(f"\n{NEON_GREEN}{BOLD}🔍 {corr.ban_evasion_summary}{RESET}\n")
        
        # Display risk progression
        if corr.risk_progression and len(corr.risk_progression) > 1:
            print(f"{NEON_CYAN}Risk Progression: ", end="")
            milestones = [0, len(corr.risk_progression) // 2, len(corr.risk_progression) - 1]
            for i in milestones:
                score = corr.risk_progression[i]
                color = NEON_RED if score >= 70 else NEON_YELLOW if score >= 40 else NEON_GREEN
                print(f"{color}{score}{RESET}", end=" → " if i != milestones[-1] else "\n")
        print()
    
    # Display findings with neon styling
    print(f"{NEON_PINK}{BOLD}═══ FINDINGS ({len(summary.findings)}) ═══{RESET}\n")
    
    smoking_guns = [f for f in summary.findings if f.smoking_gun]
    if smoking_guns:
        print(f"{NEON_RED}{BOLD}💥 SMOKING GUNS: {len(smoking_guns)}{RESET}")
        for finding in smoking_guns[:5]:  # Show top 5 smoking guns
            color = severity_colors.get(finding.severity.value, RESET)
            print(f"{color}[{finding.severity.value}] {finding.title}{RESET}")
            print(f"  {NEON_CYAN}Location: {finding.location}{RESET}")
            print(f"  {NEON_GREEN}Confidence: {int(finding.confidence * 100)}%{RESET}\n")
    
    # Display all findings grouped by severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_findings = [f for f in summary.findings if f.severity.value == severity]
        if sev_findings:
            color = severity_colors.get(severity, RESET)
            print(f"{color}{BOLD}▼ {severity} ({len(sev_findings)}){RESET}")
            for finding in sev_findings[:10]:  # Limit to 10 per severity
                gun = "💥 " if finding.smoking_gun else ""
                corr_id = f"({finding.correlation_id}) " if finding.correlation_id else ""
                print(f"  {color}{gun}{corr_id}{finding.title}{RESET}")
                print(f"    {finding.category.value} | {finding.location}")
                print(f"    {finding.description[:120]}{'...' if len(finding.description) > 120 else ''}\n")
    
    print(f"{NEON_PINK}{BOLD}╚═══════════════════════════════════════════════════════════╝{RESET}\n")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
