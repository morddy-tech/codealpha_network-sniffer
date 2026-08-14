"""Miscellaneous utilities: byte formatting, duration formatting."""

from __future__ import annotations

import datetime


def format_bytes(size: int) -> str:
    """Human-readable byte size (e.g. 3.7 MB)."""
    value = float(size or 0)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if value < 1024 or unit == "PB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def format_duration(seconds: float) -> str:
    """Human-readable duration as HH:MM:SS."""
    seconds = max(int(seconds), 0)
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def format_timestamp(value) -> str:
    """Local, second-precision timestamp."""
    if value is None:
        return "—"
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)
