from __future__ import annotations

import importlib.resources as importlib_resources
import math
import os
import platform
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional


def ensure_windows_time(hours: int) -> timedelta:
    hours = max(1, hours)
    return timedelta(hours=hours)


def expand_env_vars(value: str) -> str:
    return os.path.expandvars(value)


def filetime_to_datetime(filetime: int) -> datetime:
    # FILETIME is 100-ns intervals since Jan 1 1601
    epoch_start = datetime(1601, 1, 1, tzinfo=timezone.utc)
    seconds, remainder = divmod(filetime, 10_000_000)
    microseconds = remainder // 10
    return epoch_start + timedelta(seconds=seconds, microseconds=microseconds)


def path_is_suspicious(path: str) -> bool:
    lowered = path.lower()
    risky_tokens = (
        "\\temp",
        "\\appdata",
        "\\local",
        "downloads",
        "\\public",
        "\\perflogs",
        "\\windows\\tasks",
        "\\programdata",
    )
    return any(token in lowered for token in risky_tokens)


def looks_random(text: str) -> bool:
    stripped = re.sub(r"[^a-zA-Z]", "", text)
    if len(stripped) < 8:
        return False
    entropy = _shannon_entropy(stripped)
    return entropy > 3.5


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    probabilities = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probabilities)


def detect_keywords(text: str, indicators: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(indicator.lower() in lowered for indicator in indicators)


def read_whoami_sid() -> str:
    if platform.system().lower() != "windows":
        return "unknown"
    try:
        import subprocess

        result = subprocess.run(
            ["whoami", "/user"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            if "SID" in line:
                parts = line.split()
                if parts:
                    return parts[-1]
    except Exception:
        return "unknown"
    return "unknown"


def ensure_admin(token_only: bool = False) -> bool:
    if platform.system().lower() != "windows":
        return True
    try:
        import ctypes

        shell32 = ctypes.windll.shell32
        is_admin = bool(shell32.IsUserAnAdmin())
        if is_admin or token_only:
            return is_admin
        params = " ".join(f'"{arg}"' for arg in sys.argv)
        shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return False
    except Exception:
        return True


def safe_path(root: Optional[str], *segments: str) -> Path:
    base = Path(root) if root else Path.cwd()
    return base.joinpath(*segments)


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def load_asset_text(name: str) -> str:
    try:
        return importlib_resources.files("portable_scanner.assets").joinpath(name).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return ""
