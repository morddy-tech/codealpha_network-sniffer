"""Django management command: python manage.py list_interfaces."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from sniffer.models import NetworkInterface


class Command(BaseCommand):
    help = "List network interfaces available for packet capture on this host."

    def handle(self, *args, **options) -> None:
        from capture.interface_manager import discover_interfaces, refresh_interface_table

        discovered = discover_interfaces()
        if not discovered:
            self.stderr.write(
                self.style.WARNING(
                    "No interfaces could be discovered. On Windows, install Npcap "
                    "(https://npcap.com) and restart. On Linux/macOS, the capture "
                    "user needs permission to open packet sockets."
                )
            )
            return

        refresh_interface_table()
        rows = (
            NetworkInterface.objects.order_by("-last_seen", "name")
            if NetworkInterface.objects.exists()
            else []
        )
        self.stdout.write(f"Found {len(discovered)} network interface(s):\n")
        known = {r.name: r for r in rows} if rows else {}
        for info in discovered:
            row = known.get(info.name)
            marker = "[ACTIVE]" if row is not None and row.is_active else "[idle ]"
            self.stdout.write(f"  {marker} {info.name}")
            if info.mac_address:
                self.stdout.write(f"         MAC: {info.mac_address}")
            if info.addresses:
                self.stdout.write(f"         IPs: {', '.join(info.addresses)}")
            if info.description and info.description != info.name:
                self.stdout.write(f"         desc: {info.description}")

        self.stdout.write(
            self.style.NOTICE(
                "\nNote: live capture may require administrator/root privileges "
                "and (on Windows) Npcap."
            )
        )
