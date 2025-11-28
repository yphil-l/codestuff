from __future__ import annotations

import os
import platform
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from .models import ScanOptions, SystemInfo
from .utils import ensure_windows_time, expand_env_vars, read_whoami_sid

LogFn = Callable[[str], None]


@dataclass
class ScanContext:
    options: ScanOptions
    started_at: datetime
    logger: LogFn
    status_callback: Optional[LogFn] = None

    def __post_init__(self) -> None:
        self.started_at = self.started_at.astimezone(timezone.utc)
        self._system_info: Optional[SystemInfo] = None
        self._is_windows = platform.system().lower().startswith("win")
        self._is_admin = None

    @property
    def is_windows(self) -> bool:
        return self._is_windows

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin
        if not self.is_windows:
            self._is_admin = False
            return False
        try:
            import ctypes

            self._is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            self._is_admin = False
        return self._is_admin

    @property
    def system_info(self) -> SystemInfo:
        if self._system_info:
            return self._system_info
        username = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
        os_version = platform.platform()
        sid = read_whoami_sid()
        self._system_info = SystemInfo(
            hostname=socket.gethostname(),
            username=username,
            os_version=os_version,
            user_sid=sid,
        )
        return self._system_info

    def log(self, message: str) -> None:
        self.logger(message)

    def update_status(self, message: str) -> None:
        if self.status_callback:
            self.status_callback(message)

    def run_command(self, command: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
        self.log(f"[cmd] {' '.join(command)}")
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def run_powershell(self, script: str, timeout: int = 120) -> subprocess.CompletedProcess:
        expanded = expand_env_vars(script)
        command = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            expanded,
        ]
        return self.run_command(command, timeout=timeout)

    def within_lookback(self, timestamp: datetime) -> bool:
        lookback_delta = ensure_windows_time(self.options.lookback_hours)
        return timestamp >= self.started_at - lookback_delta
