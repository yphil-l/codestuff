from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, Iterable, List, Sequence

from .context import ScanContext
from .models import ArtifactCategory, Finding, ScanSummary
from .scanners.base import ArtifactScanner

FindingCallback = Callable[[Finding], None]
ProgressCallback = Callable[[float], None]


class ScanEngine:
    def __init__(self, scanners: Sequence[ArtifactScanner]) -> None:
        self._scanner_map: Dict[ArtifactCategory, ArtifactScanner] = {
            scanner.category: scanner for scanner in scanners
        }

    def categories(self) -> List[ArtifactCategory]:
        return list(self._scanner_map.keys())

    def scan(
        self,
        context: ScanContext,
        categories: Iterable[ArtifactCategory],
        on_finding: FindingCallback | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> ScanSummary:
        filtered = [cat for cat in categories if cat in self._scanner_map]
        total = len(filtered) or 1
        summary = ScanSummary()
        completed = 0
        lock = threading.Lock()

        def mark_progress() -> None:
            nonlocal completed
            with lock:
                completed += 1
                value = min(0.999, completed / total)
            if on_progress:
                on_progress(value)

        with ThreadPoolExecutor(max_workers=min(5, total)) as executor:
            futures = []
            for category in filtered:
                scanner = self._scanner_map[category]
                futures.append(
                    executor.submit(
                        self._run_scanner,
                        scanner,
                        context,
                        on_finding,
                        summary,
                        mark_progress,
                    )
                )

            for future in futures:
                future.result()

        if on_progress:
            on_progress(1.0)
        return summary

    def _run_scanner(
        self,
        scanner: ArtifactScanner,
        context: ScanContext,
        on_finding: FindingCallback | None,
        summary: ScanSummary,
        progress_callback: Callable[[], None],
    ) -> None:
        context.update_status(f"Scanning {scanner.name}...")
        try:
            for finding in scanner.scan(context):
                summary.findings.append(finding)
                if on_finding:
                    on_finding(finding)
        except Exception as exc:  # pragma: no cover
            context.log(f"{scanner.name} failed: {exc}")
        finally:
            progress_callback()
