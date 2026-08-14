"""Django management command: python manage.py analyze_session <session_id>."""

from __future__ import annotations

import sys

from django.core.management.base import BaseCommand

from sniffer.models import CaptureSession


class Command(BaseCommand):
    help = "Print a summary and passive anomaly indicators for a capture session."

    def add_arguments(self, parser) -> None:
        parser.add_argument("session_id", type=int, help="Capture session ID.")

    def handle(self, *args, **options) -> None:
        from capture.statistics import build_session_statistics

        try:
            session = CaptureSession.objects.get(pk=options["session_id"])
        except CaptureSession.DoesNotExist:
            self.stderr.write(self.style.ERROR(f"Session #{options['session_id']} does not exist."))
            sys.exit(1)

        stats = build_session_statistics(session)
        self.stdout.write(self.style.MIGRATE_HEADING(f"\nSession: {session.session_name}"))
        self.stdout.write(f"  interface : {session.interface}")
        self.stdout.write(f"  status    : {session.status}")
        self.stdout.write(f"  duration  : {session.duration:.1f}s")
        self.stdout.write(f"  packets   : {stats.packet_count}")
        self.stdout.write(f"  bytes     : {stats.total_bytes}")
        self.stdout.write(f"  TCP/UDP   : {stats.tcp_count} / {stats.udp_count}")
        self.stdout.write(f"  ICMP      : {stats.icmp_count}")
        self.stdout.write(f"  ARP       : {stats.arp_count}")
        self.stdout.write(f"  DNS       : {stats.dns_count}")
        self.stdout.write(f"  IPv4/IPv6 : {stats.ipv4_count} / {stats.ipv6_count}")

        self.stdout.write(self.style.MIGRATE_HEADING("\nTop source IPs:"))
        for ip, total in stats.top_sources[:10]:
            self.stdout.write(f"  {ip or '(unknown)':<45} {total}")
        self.stdout.write(self.style.MIGRATE_HEADING("\nTop destination IPs:"))
        for ip, total in stats.top_destinations[:10]:
            self.stdout.write(f"  {ip or '(unknown)':<45} {total}")

        if stats.anomalies:
            self.stdout.write(self.style.WARNING("\nPotential anomaly indicators (passive heuristics):"))
            for indicator in stats.anomalies:
                self.stdout.write(f"  [{indicator.severity.upper()}] {indicator.title}")
                self.stdout.write(f"      {indicator.description}")
        else:
            self.stdout.write(self.style.SUCCESS("\nNo anomaly indicators exceeded configured thresholds."))
