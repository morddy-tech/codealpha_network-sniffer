"""Django management command: python manage.py capture."""

from __future__ import annotations

import sys
import time

from django.core.management.base import BaseCommand

from sniffer.models import CaptureSession


class Command(BaseCommand):
    help = (
        "Start a packet capture on an authorized network interface. "
        "Packets are parsed and stored as sanitized metadata. "
        "Only monitor networks you own or are explicitly authorized to monitor."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument("--interface", required=True, help="Interface name, e.g. 'Wi-Fi' or 'eth0'.")
        parser.add_argument("--name", default="", help="Session name (default: auto-generated).")
        parser.add_argument("--count", type=int, default=0, help="Maximum packets to capture (0 = until stopped).")
        parser.add_argument(
            "--protocol",
            default="",
            choices=["tcp", "udp", "icmp", "icmpv6", "arp", "ipv4", "ipv6", "dns"],
            help="Optional protocol filter applied as a BPF expression.",
        )
        parser.add_argument("--timeout", type=float, default=None, help="Stop after N seconds.")
        parser.add_argument("--payload", action="store_true", help="Store limited payload previews (OFF by default).")
        parser.add_argument("--no-payload", action="store_true", help="Disable payload preview storage.")

    def handle(self, *args, **options) -> None:
        from capture.capture_service import CaptureController
        from capture.interface_manager import is_interface_available

        interface = options["interface"]
        if not is_interface_available(interface):
            self.stderr.write(self.style.ERROR(f"Interface '{interface}' was not found on this host."))
            self.stderr.write(self.style.NOTICE("Run 'python manage.py list_interfaces' to see available interfaces."))
            sys.exit(2)

        payload = options["payload"] and not options["no_payload"]
        session = CaptureSession.objects.create(
            session_name=options["name"] or f"Capture on {interface}",
            interface=interface,
            status="running",
            protocol_filter=options["protocol"] or "",
            payload_storage_enabled=payload,
            requested_packet_count=options["count"],
        )

        self.stdout.write(
            self.style.SUCCESS(f"Starting capture on '{interface}' (session #{session.id})")
        )
        if options["count"]:
            self.stdout.write(f"  target packets: {options['count']}")
        if options["timeout"]:
            self.stdout.write(f"  timeout: {options['timeout']}s")
        if options["protocol"]:
            self.stdout.write(f"  protocol filter: {options['protocol']}")
        self.stdout.write(f"  payload previews: {'enabled' if payload else 'disabled'}")

        handle = CaptureController.start(
            session,
            count=options["count"],
            timeout=options["timeout"],
            protocol_filter=options["protocol"],
        )

        thread = handle.thread
        while thread is not None and thread.is_alive():
            status = handle.snapshot()
            self.stdout.write(
                f"\r  packets={status['packet_count']} bytes={status['byte_count']} "
                f"status={status['status']}   ",
                ending="",
            )
            self.stdout.flush()
            time.sleep(1)
        self.stdout.write()

        final = handle.snapshot()
        if final["status"] == "failed":
            self.stderr.write(self.style.ERROR(f"Capture failed: {final['error']}"))
            sys.exit(1)
        self.stdout.write(self.style.SUCCESS(f"Capture finished: {final['packet_count']} packets stored."))
