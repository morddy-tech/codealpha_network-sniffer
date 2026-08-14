"""JSON report export."""

from __future__ import annotations

import json
from typing import Any, Dict


def render_json(context: Dict[str, Any]) -> str:
    """Render a pretty-printed JSON string from a report context."""
    return json.dumps(context, indent=2, ensure_ascii=False) + "\n"
