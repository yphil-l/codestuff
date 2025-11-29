from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from .analytics import build_correlation_summary
from .context import ScanContext
from .engine import ScanEngine
from .models import ArtifactCategory, ScanOptions, ScanSummary, Severity
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
    summary = engine.scan(context, categories=categories)
    display_cli(summary)
    if export_dir:
        export_reports(context, summary, export_dir)
        print(f"Reports exported to {export_dir}")
    return 0


def display_cli(summary: ScanSummary) -> None:
    for finding in summary.findings:
        print(
            f"[{finding.severity.value}] {finding.category.value} | {finding.title}\n"
            f"    Location: {finding.location}\n    Time: {finding.timestamp.isoformat()}\n    {finding.description}\n"
        )
    correlation = build_correlation_summary(summary.findings)
    print("=== Correlation Timeline (per-minute) ===")
    if correlation.is_empty:
        print("  (no overlapping artifacts detected)")
    else:
        for cluster in correlation.top_clusters():
            categories = ", ".join(
                f"{breakdown.category.value}({breakdown.count})"
                for breakdown in sorted(
                    cluster.category_breakdown.values(), key=lambda item: item.category.value
                )
            )
            print(f"  - {cluster.minute.strftime('%Y-%m-%d %H:%M')}Z :: {categories}")
    print("\n=== Per-Category Severity Tallies ===")
    for category in ArtifactCategory:
        counts = correlation.category_severity.get(category, {})
        total = sum(counts.values()) if counts else 0
        if total == 0:
            continue
        severity_bits = ", ".join(
            f"{severity.value}:{counts.get(severity, 0)}"
            for severity in Severity
            if counts.get(severity, 0)
        ) or "0"
        print(f"  - {category.value}: {severity_bits} (total {total})")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
