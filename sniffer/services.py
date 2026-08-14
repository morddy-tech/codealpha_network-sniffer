"""Application service layer: capture orchestration and settings management."""

from __future__ import annotations

import logging
from typing import Dict, Optional

from django.conf import settings
from django.utils import timezone

from sniffer.constants import (
    SETTING_DEFAULT_RETENTION_DAYS,
    SETTING_MAX_PAYLOAD_PREVIEW_BYTES,
    SETTING_PAYLOAD_STORAGE_ENABLED,
)
from sniffer.models import CaptureSession, NetworkInterface, get_setting, set_setting

logger = logging.getLogger("sniffer.services")


def create_capture_session(
    *,
    interface: str,
    session_name: str = "",
    packet_count: int = 0,
    protocol_filter: str = "",
    payload_enabled: bool = False,
) -> CaptureSession:
    """Create (but do not start) a capture session."""
    return CaptureSession.objects.create(
        session_name=session_name or f"Capture on {interface}",
        interface=interface,
        status="running",
        protocol_filter=protocol_filter or "",
        payload_storage_enabled=payload_enabled,
        requested_packet_count=max(packet_count, 0),
    )


def start_web_capture(
    *,
    interface: str,
    session_name: str = "",
    packet_count: int = 0,
    protocol_filter: str = "",
    payload_enabled: bool = False,
    timeout: Optional[float] = None,
):
    """Create and start a capture from the web UI (staff only)."""
    from capture.capture_service import CaptureController

    session = create_capture_session(
        interface=interface,
        session_name=session_name,
        packet_count=packet_count,
        protocol_filter=protocol_filter,
        payload_enabled=payload_enabled,
    )
    handle = CaptureController.start(
        session,
        count=packet_count,
        timeout=timeout,
        protocol_filter=protocol_filter,
    )
    logger.info("Web capture started: session=%d by request", session.id)
    return session


def stop_web_capture(session_id: int) -> Dict:
    """Request a graceful stop for a web-started capture."""
    from capture.capture_service import CaptureController

    handle = CaptureController.stop(session_id)
    return handle.snapshot()


def delete_session(session_id: int) -> Optional[int]:
    """Delete a session and all of its packets. Returns packet count or None."""
    try:
        session = CaptureSession.objects.get(pk=session_id)
    except CaptureSession.DoesNotExist:
        return None
    if session.is_running:
        from capture.capture_service import CaptureController

        handle = CaptureController.handle_for_session(session_id)
        if handle is not None:
            CaptureController.stop(session_id)
            if handle.thread is not None:
                handle.thread.join(timeout=10)
    packet_count = session.packets.count()
    logger.warning("Session %d deleted by administrator (%d packets).", session_id, packet_count)
    session.delete()
    return packet_count


def update_application_settings(
    *, payload_enabled: bool, max_payload_bytes: int, retention_days: int
) -> None:
    """Persist administrator-configured settings into ApplicationSetting."""
    set_setting(
        SETTING_PAYLOAD_STORAGE_ENABLED,
        "true" if payload_enabled else "false",
        "Store limited payload previews (hex + ASCII) for captured packets",
    )
    set_setting(
        SETTING_MAX_PAYLOAD_PREVIEW_BYTES,
        str(min(max(max_payload_bytes, 8), 4096)),
        "Maximum payload bytes stored per packet preview (8-4096)",
    )
    set_setting(
        SETTING_DEFAULT_RETENTION_DAYS,
        str(min(max(retention_days, 1), 3650)),
        "Default packet retention period in days",
    )
    logger.info("Application settings updated by administrator.")


def application_settings() -> Dict:
    """Current effective application settings (DB overrides env defaults)."""
    env_default = settings.PAYLOAD_STORAGE_ENABLED
    stored = get_setting(SETTING_PAYLOAD_STORAGE_ENABLED, "").lower() in {"1", "true", "yes", "on"}
    return {
        "payload_storage_enabled": stored,
        "env_default_payload_storage": env_default,
        "max_payload_preview_bytes": int(
            get_setting(SETTING_MAX_PAYLOAD_PREVIEW_BYTES, "256") or 256
        ),
        "retention_days": int(get_setting(SETTING_DEFAULT_RETENTION_DAYS, "30") or 30),
        "threat_intel_enabled": settings.THREAT_INTEL_ENABLED,
    }


def refresh_interfaces() -> Dict:
    """Discover host interfaces and sync the NetworkInterface table."""
    from capture.interface_manager import refresh_interface_table

    return refresh_interface_table()
