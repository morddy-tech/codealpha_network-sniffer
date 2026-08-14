"""Django management command: python manage.py cleanup_packets.

Deletes old capture data according to an explicit retention configuration.
Nothing is ever deleted automatically.
"""

from __future__ import annotations

import sys
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from sniffer.models import CaptureSession


class Command(BaseCommand):
    help = (
        "Delete capture sessions (and their packets) older than N days, or a "
        "single session with --session-id. Requires explicit configuration; "
        "no data is ever deleted automatically."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--older-than",
            type=int,
            default=None,
            help="Delete sessions that ended more than N days ago.",
        )
        parser.add_argument(
            "--session-id", type=int, default=None, help="Delete a specific session and its packets."
        )
        parser.add_argument(
            "--dry-run", action="store_true", help="Report what would be deleted without deleting."
        )

    def handle(self, *args, **options) -> None:
        dry_run = options["dry_run"]
        session_id = options["session_id"]
        days = options["older_than"]

        if session_id is None and days is None:
            self.stderr.write(
                self.style.ERROR("Provide either --older-than N or --session-id ID.")
            )
            sys.exit(2)
        if days is not None and days < 1:
            self.stderr.write(self.style.ERROR("--older-than must be >= 1 day."))
            sys.exit(2)

        targets: list[CaptureSession] = []
        if session_id is not None:
            try:
                targets = [CaptureSession.objects.get(pk=session_id)]
            except CaptureSession.DoesNotExist:
                self.stderr.write(self.style.ERROR(f"Session #{session_id} does not exist."))
                sys.exit(1)
        else:
            cutoff = timezone.now() - timedelta(days=days)
            targets = list(CaptureSession.objects.filter(ended_at__lt=cutoff))

        if not targets:
            self.stdout.write("Nothing to clean up.")
            return

        for session in targets:
            packet_count = session.packets.count()
            action = "would delete" if dry_run else "deleting"
            self.stdout.write(
                f"  {action} session #{session.id} '{session.session_name}' "
                f"({packet_count} packets)"
            )

        if dry_run:
            self.stdout.write(self.style.NOTICE(f"\nDry run: {len(targets)} session(s) would be deleted."))
            return

        for session in targets:
            session.delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted {len(targets)} session(s)."))
