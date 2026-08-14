"""Self-contained HTML report export (no external resources)."""

from __future__ import annotations

from html import escape
from typing import Any, Dict

from django.template.loader import render_to_string


def render_html(context: Dict[str, Any]) -> str:
    """Render a standalone HTML report document as a string."""
    return render_to_string("reports/html_report.html", context)


def format_bytes(size: int) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.0f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def escape_text(value) -> str:
    """HTML-escape a report value for safe display."""
    return escape(str(value if value is not None else ""))
