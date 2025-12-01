from __future__ import annotations

import queue
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .context import ScanContext
from .engine import ScanEngine
from .models import ArtifactCategory, Finding, ScanOptions, ScanSummary, Severity
from .reporting import export_reports
from .scanners import build_scanners


class ForensicScannerApp(tk.Tk):
    def __init__(self, options: ScanOptions) -> None:
        super().__init__()
        self.title("FORENSIC SCANNER v1.0")
        self.configure(bg="#050710")
        self.geometry("1400x820")
        self.resizable(True, True)

        self.options = options
        self.scanners = build_scanners()
        self.engine = ScanEngine(self.scanners)
        self.category_vars: dict[ArtifactCategory, tk.BooleanVar] = {
            scanner.category: tk.BooleanVar(value=True) for scanner in self.scanners
        }
        self.all_var = tk.BooleanVar(value=True)

        self.log_queue: queue.Queue[str] = queue.Queue()
        self.finding_queue: queue.Queue[Finding] = queue.Queue()
        self.progress_queue: queue.Queue[float] = queue.Queue()
        self._current_context: ScanContext | None = None
        self._findings: list[Finding] = []
        self._scan_thread: threading.Thread | None = None
        self._running = False
        self._summary: ScanSummary | None = None
        self._correlation_rendered = False

        self._build_styles()
        self._build_layout()
        self._drain_queues()

    def _build_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TButton", background="#00ff88", foreground="#050710", font=("Consolas", 11, "bold"))
        style.configure("Treeview", background="#060c1f", foreground="#c4ffe8", fieldbackground="#060c1f", rowheight=28)
        style.configure("Horizontal.TProgressbar", troughcolor="#0a0e27", bordercolor="#0a0e27", background="#00ff88")

    def _build_layout(self) -> None:
        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)

        header = tk.Frame(self, bg="#050710")
        header.grid(row=0, column=0, columnspan=3, sticky="nsew", pady=10, padx=12)
        title = tk.Label(header, text="FORENSIC SCANNER v1.0", font=("Consolas", 22, "bold"), fg="#00ff88", bg="#050710")
        title.pack(side=tk.LEFT)
        self.status_indicator = tk.Label(header, text="● READY", font=("Consolas", 16), fg="#00ff88", bg="#050710")
        self.status_indicator.pack(side=tk.RIGHT)

        sidebar = tk.Frame(self, bg="#080b1a", bd=2, relief=tk.GROOVE)
        sidebar.grid(row=1, column=0, sticky="nsw", padx=(12, 6), pady=6)
        tk.Label(sidebar, text="Artifacts", fg="#ff00ff", bg="#080b1a", font=("Consolas", 12, "bold")).pack(anchor="w", padx=10, pady=(10, 4))
        tk.Checkbutton(
            sidebar,
            text="✓ All (scan everything)",
            variable=self.all_var,
            bg="#080b1a",
            fg="#c4ffe8",
            selectcolor="#080b1a",
            command=self._toggle_all,
        ).pack(anchor="w", padx=14, pady=(0, 8))
        for category in ArtifactCategory:
            chk = tk.Checkbutton(
                sidebar,
                text=f"✓ {category.value}",
                variable=self.category_vars.setdefault(category, tk.BooleanVar(value=True)),
                bg="#080b1a",
                fg="#c4ffe8",
                selectcolor="#080b1a",
            )
            chk.pack(anchor="w", padx=14, pady=2)

        output_frame = tk.Frame(self, bg="#050710")
        output_frame.grid(row=1, column=1, sticky="nsew", pady=6)
        output_frame.rowconfigure(0, weight=1)
        output_frame.columnconfigure(0, weight=1)
        self.output = scrolledtext.ScrolledText(
            output_frame,
            fg="#00ff88",
            bg="#030511",
            insertbackground="#00ff88",
            font=("Consolas", 11),
            wrap=tk.WORD,
        )
        self.output.grid(row=0, column=0, sticky="nsew")

        right_panel = tk.Frame(self, bg="#050710")
        right_panel.grid(row=1, column=2, sticky="ns", padx=(6, 12), pady=6)
        
        # Risk gauge section
        gauge_frame = tk.Frame(right_panel, bg="#080b1a", bd=2, relief=tk.GROOVE)
        gauge_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(gauge_frame, text="Risk Score", fg="#ff00ff", bg="#080b1a", font=("Consolas", 12, "bold")).pack(anchor="w", padx=10, pady=(5, 0))
        self.risk_label = tk.Label(gauge_frame, text="0/100", fg="#00ff88", bg="#080b1a", font=("Consolas", 24, "bold"))
        self.risk_label.pack(pady=10)
        self.risk_status = tk.Label(gauge_frame, text="LOW RISK", fg="#00ff88", bg="#080b1a", font=("Consolas", 10))
        self.risk_status.pack(pady=(0, 10))
        
        # Correlation panel
        corr_frame = tk.Frame(right_panel, bg="#080b1a", bd=2, relief=tk.GROOVE)
        corr_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(corr_frame, text="Correlation", fg="#ff00ff", bg="#080b1a", font=("Consolas", 11, "bold")).pack(anchor="w", padx=10, pady=(5, 0))
        self.corr_text = scrolledtext.ScrolledText(corr_frame, fg="#c4ffe8", bg="#030511", font=("Consolas", 9), height=8, wrap=tk.WORD)
        self.corr_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Findings tree
        tk.Label(right_panel, text="Findings", fg="#ff00ff", bg="#050710", font=("Consolas", 12, "bold")).pack(anchor="w")
        columns = ("id", "severity", "title", "time")
        self.tree = ttk.Treeview(right_panel, columns=columns, show="headings", height=15)
        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, anchor="w", width=100 if col in ("id", "severity") else 200 if col == "title" else 120)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self._show_finding_detail)

        self._reset_correlation_panel()

        bottom = tk.Frame(self, bg="#050710")
        bottom.grid(row=2, column=0, columnspan=3, sticky="ew", padx=12, pady=(0, 12))
        self.progress = ttk.Progressbar(bottom, orient=tk.HORIZONTAL, mode="determinate")
        self.progress.pack(fill=tk.X, padx=(0, 16), pady=6)
        button_frame = tk.Frame(bottom, bg="#050710")
        button_frame.pack(fill=tk.X)
        start_btn = ttk.Button(button_frame, text="START SCAN", command=self.start_scan)
        start_btn.pack(side=tk.LEFT, padx=4)
        export_btn = ttk.Button(button_frame, text="EXPORT REPORT", command=self.export_report)
        export_btn.pack(side=tk.LEFT, padx=4)
        clear_btn = ttk.Button(button_frame, text="CLEAR OUTPUT", command=self.clear_output)
        clear_btn.pack(side=tk.LEFT, padx=4)
        copy_btn = ttk.Button(button_frame, text="COPY FINDINGS", command=self.copy_findings)
        copy_btn.pack(side=tk.LEFT, padx=4)
        self.status_var = tk.StringVar(value="Idle")
        status_label = tk.Label(bottom, textvariable=self.status_var, fg="#c4ffe8", bg="#050710", font=("Consolas", 11))
        status_label.pack(anchor="w", pady=4)

    def _toggle_all(self) -> None:
        value = self.all_var.get()
        for var in self.category_vars.values():
            var.set(value)

    def start_scan(self) -> None:
        if self._running:
            return
        selected = [cat for cat, var in self.category_vars.items() if var.get()]
        if not selected:
            messagebox.showwarning("Forensic Scanner", "Select at least one artifact category")
            return
        self._running = True
        self.status_indicator.configure(text="● SCANNING", fg="#ff00ff")
        self.status_var.set("Scanning...")
        self.progress.configure(value=0)
        self._findings.clear()
        self._correlation_rendered = False
        self._summary = None
        self.tree.delete(*self.tree.get_children())
        self.output.delete("1.0", tk.END)
        self._reset_correlation_panel()
        context = ScanContext(
            options=self.options,
            started_at=datetime.now(timezone.utc),
            logger=self.log_queue.put,
            status_callback=self.log_queue.put,
        )
        self._current_context = context
        def run_scan() -> None:
            summary = self.engine.scan(
                context=context,
                categories=selected,
                on_finding=self.finding_queue.put,
                on_progress=self.progress_queue.put,
            )
            self._summary = summary
            self.log_queue.put("Scan complete.")
            self._running = False
        self._scan_thread = threading.Thread(target=run_scan, daemon=True)
        self._scan_thread.start()

    def export_report(self) -> None:
        if not self._findings:
            messagebox.showinfo("Forensic Scanner", "No findings to export yet")
            return
        directory = filedialog.askdirectory(title="Select export directory")
        if not directory:
            return
        summary = ScanSummary(findings=list(self._findings))
        outputs = export_reports(self._current_context or self._build_placeholder_context(), summary, Path(directory))
        messagebox.showinfo("Forensic Scanner", f"Reports exported to {Path(directory)}\n\n" + "\n".join(f"- {ext.upper()}: {path}" for ext, path in outputs.items()))

    def _build_placeholder_context(self) -> ScanContext:
        return ScanContext(
            options=self.options,
            started_at=datetime.now(timezone.utc),
            logger=lambda msg: None,
        )

    def clear_output(self) -> None:
        self.output.delete("1.0", tk.END)
        self.tree.delete(*self.tree.get_children())
        self._findings.clear()
        self.status_var.set("Idle")

    def copy_findings(self) -> None:
        if not self._findings:
            messagebox.showinfo("Forensic Scanner", "No findings to copy yet")
            return
        text = "\n".join(
            f"[{finding.severity.value}] {finding.title} | {finding.location} | {finding.timestamp:%Y-%m-%d %H:%M:%S}" for finding in self._findings
        )
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Forensic Scanner", "Findings copied to clipboard")

    def _drain_queues(self) -> None:
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.output.insert(tk.END, message + "\n")
                self.output.see(tk.END)
        except queue.Empty:
            pass
        try:
            while True:
                finding = self.finding_queue.get_nowait()
                self._findings.append(finding)
                gun = "💥" if finding.smoking_gun else ""
                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        finding.correlation_id or "",
                        finding.severity.value,
                        gun + finding.title,
                        finding.timestamp.strftime("%H:%M:%S"),
                    ),
                )
                self.status_var.set(self._build_status_summary())
        except queue.Empty:
            pass
        try:
            while True:
                progress = self.progress_queue.get_nowait()
                self.progress.configure(value=progress * 100)
                if progress >= 0.99 and not self._running:
                    self.status_indicator.configure(text="● READY", fg="#00ff88")
                    self._update_correlation_panel()
        except queue.Empty:
            pass
        self.after(100, self._drain_queues)

    def _build_status_summary(self) -> str:
        counts = {severity: 0 for severity in Severity}
        for finding in self._findings:
            counts[finding.severity] += 1
        return " | ".join(f"{severity.value}: {counts[severity]}" for severity in Severity)

    def _reset_correlation_panel(self) -> None:
        self._set_risk_display(0, "Awaiting Scan")
        self.corr_text.config(state=tk.NORMAL)
        self.corr_text.delete("1.0", tk.END)
        self.corr_text.insert(tk.END, "Correlation insights will appear once a scan completes.")
        self.corr_text.config(state=tk.DISABLED)

    def _update_correlation_panel(self) -> None:
        if self._running or self._correlation_rendered is True:
            return
        summary = self._summary
        if not summary or not summary.correlation:
            self._reset_correlation_panel()
            self._correlation_rendered = True
            return
        corr = summary.correlation
        self._set_risk_display(corr.risk_score, self._risk_label(corr.risk_score))
        lines = [
            f"Risk Score: {corr.risk_score}/100",
            f"Bypass Score: {corr.bypass_score}/40",
            "",
        ]
        if corr.clearing_patterns:
            lines.append("Clearing Patterns:")
            lines.extend(f" - {pattern}" for pattern in corr.clearing_patterns)
        else:
            lines.append("No clearing cascades detected.")
        lines.append("")
        lines.append(corr.ban_evasion_summary)
        if corr.highlight_cards:
            lines.append(f"Game highlights: {len(corr.highlight_cards)}")
        self.corr_text.config(state=tk.NORMAL)
        self.corr_text.delete("1.0", tk.END)
        self.corr_text.insert(tk.END, "\n".join(lines))
        self.corr_text.config(state=tk.DISABLED)
        self._correlation_rendered = True

    def _set_risk_display(self, score: int, label: str) -> None:
        color = self._risk_color(score)
        self.risk_label.config(text=f"{score}/100", fg=color)
        self.risk_status.config(text=label, fg=color)

    def _risk_color(self, score: int) -> str:
        if score >= 80:
            return "#ff0066"
        if score >= 60:
            return "#ff7b00"
        if score >= 40:
            return "#f6c344"
        return "#00ff88"

    def _risk_label(self, score: int) -> str:
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "ELEVATED"
        if score >= 20:
            return "MODERATE"
        return "LOW"

    def _show_finding_detail(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        index = self.tree.index(selected[0])
        if index >= len(self._findings):
            return
        finding = self._findings[index]
        messagebox.showinfo(
            "Finding Details",
            f"[{finding.severity.value}] {finding.title}\nCategory: {finding.category.value}\nLocation: {finding.location}\nTime: {finding.timestamp}\n\n{finding.description}",
        )
