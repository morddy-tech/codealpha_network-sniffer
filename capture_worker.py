#!/usr/bin/env python
"""Standalone packet capture worker.

Runs outside of Django's web server process so packet capture can never
block the dashboard.  It initializes Django for ORM access, then delegates
to the shared :mod:`capture.capture_service`.

Usage::

    python capture_worker.py --interface "Wi-Fi" --count 100
    python capture_worker.py --interface eth0 --protocol tcp --timeout 30
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time


def _bootstrap_django() -> None:
    """Configure and initialize Django so models can be used."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    import django

    django.setup()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capture_worker.py",
        description=(
            "CodeAlpha Advanced Network Traffic Analyzer - capture worker. "
            "Captures packets from an authorized interface and stores "
            "sanitized metadata in the Django database."
        ),
    )
    parser.add_argument("--interface", required=True, help="Network interface to capture on (e.g. 'Wi-Fi', 'eth0').")
    parser.add_argument("--name", default="", help="Session name (default: auto-generated).")
    parser.add_argument("--count", type=int, default=0, help="Maximum packets to capture (0 = until stopped).")
    parser.add_argument("--protocol", default="", choices=["tcp", "udp", "icmp", "icmpv6", "arp", "ipv4", "ipv6", "dns"], help="Optional protocol filter (BPF).")
    parser.add_argument("--timeout", type=float, default=None, help="Maximum capture duration in seconds.")
    parser.add_argument("--payload", action="store_true", help="Store limited payload previews (OFF by default).")
    parser.add_argument("--no-payload", action="store_true", help="Explicitly disable payload storage (default).")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap_django()

    from capture.capture_service import CaptureController
    from capture.interface_manager import is_interface_available
    from sniffer.models import CaptureSession

    if not is_interface_available(args.interface):
        print(f"[ERROR] Interface '{args.interface}' was not found on this host.", file=sys.stderr)
        return 2

    payload = args.payload and not args.no_payload
    session = CaptureSession.objects.create(
        session_name=args.name or f"CLI capture on {args.interface}",
        interface=args.interface,
        status="running",
        protocol_filter=args.protocol or "",
        payload_storage_enabled=payload,
        requested_packet_count=args.count,
    )

    print(f"[INFO] Starting capture on '{args.interface}' (session #{session.id})")
    if args.count:
        print(f"[INFO] Target packets: {args.count}")
    if args.timeout:
        print(f"[INFO] Timeout: {args.timeout}s")
    if args.protocol:
        print(f"[INFO] Protocol filter: {args.protocol}")
    if payload:
        print("[INFO] Payload preview storage: ENABLED")
    else:
        print("[INFO] Payload preview storage: disabled")

    handle = CaptureController.start(
        session,
        count=args.count,
        timeout=args.timeout,
        protocol_filter=args.protocol,
    )
    thread = handle.thread
    while thread is not None and thread.is_alive():
        status = handle.snapshot()
        print(
            f"\r[INFO] packets={status['packet_count']} bytes={status['byte_count']} "
            f"status={status['status']}   ",
            end="",
            flush=True,
        )
        time.sleep(1)

    final = handle.snapshot()
    print(f"\n[INFO] Capture finished: status={final['status']}")
    if final["error"]:
        print(f"[ERROR] {final['error']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
