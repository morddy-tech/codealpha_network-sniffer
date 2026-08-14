"""Template context processors."""

from __future__ import annotations

from .constants import SessionStatus
from .models import CaptureSession


def capture_status(request):
    """Provide a global capture-status summary for the top navigation bar."""
    latest = CaptureSession.objects.order_by("-started_at").first()
    running = None
    if latest is not None and latest.is_running:
        running = latest

    return {
        "global_running_session": running,
        "global_running_label": SessionStatus.RUNNING,
    }
