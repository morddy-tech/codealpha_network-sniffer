"""Packet capture service.

Runs Scapy captures in a background thread so the Django web server never
blocks.  The same service is used by:

  * ``python manage.py capture``
  * ``python capture_worker.py``
  * the Live Capture page (web-started captures)

Design notes
------------
* Packets are buffered and committed with ``bulk_create`` in batches.
* Session counters are persisted on a timer and on completion.
* A ``threading.Event`` provides graceful stop (stop_filter).
* Malformed packets are skipped by the parser; they never stop the capture.
* Tests can inject an in-memory packet source instead of a live interface.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from django.conf import settings
from django.utils import timezone

from sniffer.constants import SessionStatus
from sniffer.models import CaptureSession, DNSQuery, Packet, payload_preview_max_bytes

logger = logging.getLogger("capture.service")

# BPF filter mapping for the ``--protocol`` CLI / web filter option.
BPF_FILTERS: Dict[str, str] = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "icmpv6": "icmp6",
    "arp": "arp",
    "ipv4": "ip",
    "ipv6": "ip6",
    "dns": "tcp port 53 or udp port 53",
}


class _StopCapture(Exception):
    """Raised inside the packet handler to stop sniffing gracefully."""


def _db_write_retry(operation: Callable[[], None], attempts: int = 6, delay: float = 0.3) -> None:
    """
    Run a database write with retries.

    SQLite can transiently raise ``database table is locked`` when the capture
    worker thread and the web server write concurrently.  Retrying a few times
    with a short delay keeps the worker resilient without blocking capture.
    """
    from django.db import OperationalError

    for attempt in range(attempts):
        try:
            operation()
            return
        except OperationalError as exc:
            if "locked" in str(exc).lower() and attempt < attempts - 1:
                time.sleep(delay * (attempt + 1))
                continue
            raise


@dataclass
class CaptureHandle:
    """Live state of one running capture (kept in memory)."""

    session_id: int
    interface: str
    payload_enabled: bool
    protocol_filter: str = ""
    started_at: Any = field(default_factory=timezone.now)
    ended_at: Any = None
    status: str = SessionStatus.RUNNING
    packet_count: int = 0
    byte_count: int = 0
    error: str = ""
    is_stopping: bool = False
    # Set by CaptureController.stop() to gracefully halt the sniff loop.
    stop_event: Any = field(default_factory=threading.Event)
    lock: Any = field(default_factory=threading.Lock)
    thread: Any = None

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "session_id": self.session_id,
                "interface": self.interface,
                "payload_enabled": self.payload_enabled,
                "protocol_filter": self.protocol_filter,
                "status": self.status,
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "ended_at": self.ended_at.isoformat() if self.ended_at else None,
                "packet_count": self.packet_count,
                "byte_count": self.byte_count,
                "error": self.error,
            }


# In-process registry of running captures.  Web-started captures live in the
# Django process; CLI captures run in their own process and report through
# the database instead.
_RUNNING: Dict[int, CaptureHandle] = {}
_REGISTRY_LOCK = threading.RLock()


def running_handles() -> List[CaptureHandle]:
    with _REGISTRY_LOCK:
        return list(_RUNNING.values())


def handle_for_session(session_id: int) -> Optional[CaptureHandle]:
    with _REGISTRY_LOCK:
        return _RUNNING.get(session_id)


class CaptureController:
    """Start, stop and observe capture sessions."""

    # ------------------------------------------------------------------ public API
    @classmethod
    def start(
        cls,
        session: CaptureSession,
        *,
        count: int = 0,
        timeout: Optional[float] = None,
        protocol_filter: str = "",
        packet_source: Optional[Callable] = None,
    ) -> CaptureHandle:
        """
        Begin a capture in a background thread.

        :param session: CaptureSession row (status will be updated in place)
        :param count: maximum packets to capture (0 = unlimited)
        :param timeout: maximum duration in seconds (None = unlimited)
        :param protocol_filter: optional BPF label ("tcp", "udp", "icmp", ...)
        :param packet_source: optional callable(prn, **kwargs) used by tests
        """
        with _REGISTRY_LOCK:
            if handle_for_session(session.id) is not None:
                raise ValueError(f"A capture for session {session.id} is already running.")

            handle = CaptureHandle(
                session_id=session.id,
                interface=session.interface,
                payload_enabled=session.payload_storage_enabled,
                protocol_filter=protocol_filter[:16],
            )
            _RUNNING[session.id] = handle

        session.status = SessionStatus.RUNNING
        session.requested_packet_count = max(count, 0)
        session.protocol_filter = protocol_filter[:16]
        session.save(update_fields=["status", "requested_packet_count", "protocol_filter"])
        logger.info("Capture started: session=%d interface=%s count=%d timeout=%s", session.id, session.interface, count, timeout)

        thread = threading.Thread(
            target=cls._run,
            args=(session.id, session.interface, count, timeout, protocol_filter),
            kwargs={"packet_source": packet_source},
            name=f"capture-{session.id}",
            daemon=True,
        )
        handle.thread = thread
        thread.start()
        return handle

    @classmethod
    def stop(cls, session_id: int) -> CaptureHandle:
        """Request a graceful stop of a running capture."""
        handle = handle_for_session(session_id)
        if handle is None:
            raise ValueError(f"No running capture for session {session_id}.")

        with handle.lock:
            handle.status = SessionStatus.STOPPING
            handle.is_stopping = True
        # Signal the worker so the sniff loop terminates promptly - this works
        # even on an idle interface because the loop polls in short slices.
        handle.stop_event.set()
        logger.info("Stop requested for session %d", session_id)

        # Reflect "stopping" in the DB immediately for observability.
        CaptureSession.objects.filter(pk=session_id).update(status=SessionStatus.STOPPING)
        return handle

    @classmethod
    def status(cls, session_id: int) -> Dict[str, Any]:
        """Live status; falls back to the database for CLI-started sessions."""
        handle = handle_for_session(session_id)
        if handle is not None:
            return handle.snapshot()

        try:
            session = CaptureSession.objects.get(pk=session_id)
        except CaptureSession.DoesNotExist:
            return {"session_id": session_id, "status": "unknown", "error": "Session not found."}
        return {
            "session_id": session.id,
            "interface": session.interface,
            "payload_enabled": session.payload_storage_enabled,
            "protocol_filter": session.protocol_filter,
            "status": session.status,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "ended_at": session.ended_at.isoformat() if session.ended_at else None,
            "packet_count": session.packet_count,
            "byte_count": session.total_bytes,
            "error": session.error_message,
        }

    @classmethod
    def latest_status(cls) -> Dict[str, Any]:
        """Status of the most recent session (used by the top bar / capture page)."""
        latest = CaptureSession.objects.order_by("-started_at").first()
        if latest is None:
            return {
                "status": "idle",
                "packet_count": 0,
                "byte_count": 0,
                "protocol_filter": "",
            }
        return cls.status(latest.id)

    # ------------------------------------------------------------- worker internals
    @classmethod
    def _run(
        cls,
        session_id: int,
        interface: str,
        count: int,
        timeout: Optional[float],
        protocol_filter: str,
        packet_source: Optional[Callable] = None,
    ) -> None:
        handle = handle_for_session(session_id)
        if handle is None:  # pragma: no cover - defensive
            return

        stop_event = handle.stop_event
        batch: List[Dict[str, Any]] = []
        counters: Dict[str, int] = {
            "packets": 0,
            "bytes": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "icmpv6": 0,
            "dns": 0,
            "arp": 0,
            "ipv4": 0,
            "ipv6": 0,
        }
        start_ts = time.monotonic()

        # Periodically persist counters to the session row.
        stats_thread = cls._start_stats_thread(session_id, handle, stop_event)
        max_payload = payload_preview_max_bytes()

        def handle_packet(packet) -> bool:
            """Process a single captured packet. Returns True to stop."""
            parsed = _parse_with_import(packet, handle.payload_enabled, max_payload)
            if parsed is not None:
                batch.append(parsed)
                counters["packets"] += 1
                counters["bytes"] += parsed["packet_length"]
                cls._bump(counters, parsed)

                if len(batch) >= settings.CAPTURE_COMMIT_BATCH_SIZE:
                    cls._flush(session_id, batch)
                    batch.clear()
                _refresh_handle(handle, counters)

            if stop_event.is_set() or (count and counters["packets"] >= count):
                return True
            return False

        try:
            elapsed = 0.0
            while True:
                remaining = None
                if timeout is not None:
                    remaining = timeout - elapsed
                    if remaining <= 0:
                        break
                # Always poll in short slices (even without a user timeout) so
                # a stop request takes effect quickly on idle interfaces.
                slice_timeout = min(remaining, 5.0) if remaining is not None else 5.0

                if packet_source is not None:
                    # Test path: in-memory packets, no network access.
                    for packet in packet_source():
                        if handle_packet(packet):
                            break
                    break

                sniff = _import_sniff()
                if sniff is None:
                    raise RuntimeError("Scapy is not installed; live capture is unavailable.")

                sniff(
                    iface=interface,
                    prn=handle_packet,
                    store=False,
                    count=None if count == 0 else count,
                    timeout=slice_timeout,
                    stop_filter=lambda _p: stop_event.is_set(),
                    filter=BPF_FILTERS.get(protocol_filter),
                )
                if stop_event.is_set() or (count and counters["packets"] >= count):
                    break
                elapsed = time.monotonic() - start_ts
        except Exception as exc:  # noqa: BLE001 - report any worker failure
            logger.exception("Capture worker failed for session %d", session_id)
            with handle.lock:
                handle.status = SessionStatus.FAILED
                handle.error = _human_error(exc)
                handle.ended_at = timezone.now()
            try:
                CaptureSession.objects.filter(pk=session_id).update(
                    status=SessionStatus.FAILED,
                    error_message=_human_error(exc)[:4000],
                    ended_at=timezone.now(),
                )
            except Exception:  # noqa: BLE001 - DB may be unavailable
                logger.exception("Could not persist failure state for session %d", session_id)
        finally:
            stop_event.set()
            cls._flush(session_id, batch)
            _refresh_handle(handle, counters)
            cls._persist_counters(session_id, counters)
            cls._finalize(session_id, handle, counters)
            with _REGISTRY_LOCK:
                _RUNNING.pop(session_id, None)
            logger.info("Capture worker exited for session %d", session_id)

    @staticmethod
    def _start_stats_thread(session_id: int, handle: CaptureHandle, stop_event: threading.Event):
        interval = max(settings.CAPTURE_STATS_INTERVAL_SECONDS, 1)

        def persist():
            while not stop_event.wait(interval):
                try:
                    with handle.lock:
                        if handle.packet_count == 0:
                            continue
                    CaptureSession.objects.filter(pk=session_id).update(
                        packet_count=handle.packet_count,
                        total_bytes=handle.byte_count,
                    )
                except Exception:  # noqa: BLE001 - DB may be unavailable
                    logger.exception("Stats persistence failed for session %d", session_id)

        thread = threading.Thread(
            target=persist, name=f"stats-{session_id}", daemon=True
        )
        thread.start()
        return thread

    @staticmethod
    def _flush(session_id: int, batch: List[Dict[str, Any]]) -> None:
        if not batch:
            return

        def commit():
            packet_rows = [
                Packet(session_id=session_id, **{k: v for k, v in item.items() if k != "dns_entries"})
                for item in batch
            ]
            Packet.objects.bulk_create(packet_rows)

            dns_rows: List[DNSQuery] = []
            for item, packet_row in zip(batch, packet_rows):
                for entry in item.get("dns_entries", []):
                    dns_rows.append(DNSQuery(packet=packet_row, **entry))
            if dns_rows:
                DNSQuery.objects.bulk_create(dns_rows)
            logger.debug("Committed %d packets for session %d", len(batch), session_id)

        try:
            _db_write_retry(commit)
        except Exception:  # noqa: BLE001 - never let DB errors kill the capture
            logger.exception("Packet commit failed for session %d", session_id)

    @staticmethod
    def _bump(counters: Dict[str, int], parsed: Dict[str, Any]) -> None:
        protocol = parsed["protocol"]
        if protocol == "TCP":
            counters["tcp"] += 1
        elif protocol == "UDP":
            counters["udp"] += 1
        elif protocol == "ICMP":
            counters["icmp"] += 1
        elif protocol == "ICMPv6":
            counters["icmpv6"] += 1
        elif protocol == "DNS":
            counters["dns"] += 1
        elif protocol == "ARP":
            counters["arp"] += 1
        if parsed["is_ipv4"]:
            counters["ipv4"] += 1
        if parsed["is_ipv6"]:
            counters["ipv6"] += 1
        if parsed["protocol"] != "DNS" and parsed["dns_entries"]:
            counters["dns"] += 1

    @staticmethod
    def _persist_counters(session_id: int, counters: Dict[str, int]) -> None:
        def commit():
            CaptureSession.objects.filter(pk=session_id).update(
                packet_count=counters["packets"],
                total_bytes=counters["bytes"],
                tcp_count=counters["tcp"],
                udp_count=counters["udp"],
                icmp_count=counters["icmp"] + counters["icmpv6"],
                dns_count=counters["dns"],
                arp_count=counters["arp"],
                ipv4_count=counters["ipv4"],
                ipv6_count=counters["ipv6"],
            )

        try:
            _db_write_retry(commit)
        except Exception:  # noqa: BLE001
            logger.exception("Could not persist counters for session %d", session_id)

    @staticmethod
    def _finalize(session_id: int, handle: CaptureHandle, counters: Dict[str, int]) -> None:
        with handle.lock:
            status = handle.status
            error = handle.error
            if status != SessionStatus.FAILED:
                status = SessionStatus.COMPLETED
                handle.status = status
            if handle.ended_at is None:
                handle.ended_at = timezone.now()

        def commit():
            CaptureSession.objects.filter(pk=session_id).update(
                status=status,
                ended_at=handle.ended_at,
                error_message=error[:4000] if error else "",
            )

        try:
            _db_write_retry(commit)
        except Exception:  # noqa: BLE001
            logger.exception("Could not finalize session %d", session_id)


def _refresh_handle(handle: CaptureHandle, counters: Dict[str, int]) -> None:
    with handle.lock:
        handle.packet_count = counters["packets"]
        handle.byte_count = counters["bytes"]


def _import_sniff():
    """Import scapy's sniff lazily so Django works without Npcap installed."""
    try:
        from scapy.sendrecv import sniff  # type: ignore[import-untyped]
    except ImportError:
        return None
    return sniff


def _parse_with_import(packet, payload_enabled: bool, max_payload: int):
    from capture.packet_parser import parse_packet

    return parse_packet(
        packet,
        payload_enabled=payload_enabled,
        max_payload_bytes=max_payload,
    )


def _human_error(exc: Exception) -> str:
    """Convert a worker exception into a human-readable message."""
    text = str(exc) or exc.__class__.__name__
    lowered = text.lower()
    if "npcap" in lowered or "winpcap" in lowered:
        return "Packet capture requires Npcap/WinPcap to be installed on Windows."
    if "permission" in lowered or "access denied" in lowered:
        return "Permission denied: elevated privileges are required for packet capture."
    if "interface" in lowered or "no such device" in lowered:
        return f"Interface unavailable: {text}"
    return text[:4000]
