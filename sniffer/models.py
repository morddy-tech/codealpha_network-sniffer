"""Database models for the traffic analyzer.

Design notes
------------
- Models are intentionally database-agnostic (no PostgreSQL-specific fields)
  so the project can move from SQLite to PostgreSQL without migrations changes.
- Payload storage is strictly limited: payload previews are stored as short
  text fields, never full packet bodies.
- Heavily-filtered columns are indexed to keep the explorer responsive.
"""

from __future__ import annotations

from django.db import models
from django.db.models import Count, Q, Sum
from django.utils import timezone

from .constants import SETTING_MAX_PAYLOAD_PREVIEW_BYTES, SessionStatus


class CaptureSession(models.Model):
    """A single packet capture run on one network interface."""

    session_name = models.CharField(max_length=200, db_index=True)
    interface = models.CharField(max_length=128)
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=16,
        choices=SessionStatus.CHOICES,
        default=SessionStatus.RUNNING,
        db_index=True,
    )

    # Live statistics (updated periodically by the capture worker)
    packet_count = models.PositiveIntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)
    tcp_count = models.PositiveIntegerField(default=0)
    udp_count = models.PositiveIntegerField(default=0)
    icmp_count = models.PositiveIntegerField(default=0)
    dns_count = models.PositiveIntegerField(default=0)
    arp_count = models.PositiveIntegerField(default=0)
    ipv4_count = models.PositiveIntegerField(default=0)
    ipv6_count = models.PositiveIntegerField(default=0)

    # Capture parameters
    requested_packet_count = models.PositiveIntegerField(
        default=0, help_text="0 means capture until stopped."
    )
    protocol_filter = models.CharField(
        max_length=16, blank=True, default="", help_text="Optional filter label."
    )
    payload_storage_enabled = models.BooleanField(
        default=False, help_text="Whether payload previews were stored for this session."
    )
    error_message = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-started_at"]
        indexes = [
            models.Index(fields=["status", "started_at"]),
        ]

    def __str__(self) -> str:
        return self.session_name

    @property
    def duration(self) -> float:
        """Duration in seconds (0 until the session ends)."""
        if not self.ended_at:
            return 0.0
        return max((self.ended_at - self.started_at).total_seconds(), 0.0)

    @property
    def is_running(self) -> bool:
        return self.status in (SessionStatus.RUNNING, SessionStatus.STOPPING)

    def mark_completed(self) -> None:
        self.status = SessionStatus.COMPLETED
        self.ended_at = timezone.now()
        self.save(update_fields=["status", "ended_at"])

    def mark_failed(self, error: str) -> None:
        self.status = SessionStatus.FAILED
        self.error_message = error[:4000]
        self.ended_at = timezone.now()
        self.save(update_fields=["status", "error_message", "ended_at"])

    def refresh_statistics(self) -> None:
        """Recompute counters from stored packets (used after manual cleanup)."""
        agg = self.packets.aggregate(
            total=Sum("packet_length"),
            tcp=Count("id", filter=Q(transport_protocol="TCP")),
            udp=Count("id", filter=Q(transport_protocol="UDP")),
            icmp=Count("id", filter=Q(protocol="ICMP")),
            icmp6=Count("id", filter=Q(protocol="ICMPv6")),
            dns=Count("id", filter=Q(protocol="DNS")),
            arp=Count("id", filter=Q(protocol="ARP")),
            v4=Count("id", filter=Q(is_ipv4=True)),
            v6=Count("id", filter=Q(is_ipv6=True)),
        )
        self.packet_count = self.packets.count()
        self.total_bytes = agg["total"] or 0
        self.tcp_count = agg["tcp"] or 0
        self.udp_count = agg["udp"] or 0
        self.icmp_count = (agg["icmp"] or 0) + (agg["icmp6"] or 0)
        self.dns_count = agg["dns"] or 0
        self.arp_count = agg["arp"] or 0
        self.ipv4_count = agg["v4"] or 0
        self.ipv6_count = agg["v6"] or 0
        self.save(
            update_fields=[
                "packet_count",
                "total_bytes",
                "tcp_count",
                "udp_count",
                "icmp_count",
                "dns_count",
                "arp_count",
                "ipv4_count",
                "ipv6_count",
            ]
        )


class Packet(models.Model):
    """Sanitized metadata for one captured packet."""

    session = models.ForeignKey(
        CaptureSession, on_delete=models.CASCADE, related_name="packets"
    )
    timestamp = models.DateTimeField(db_index=True)
    source_ip = models.CharField(max_length=45, blank=True, default="", db_index=True)
    destination_ip = models.CharField(max_length=45, blank=True, default="", db_index=True)
    source_port = models.PositiveIntegerField(null=True, blank=True)
    destination_port = models.PositiveIntegerField(null=True, blank=True)

    # protocol = dominant L3/L4 label ("TCP", "UDP", "ICMP", "ARP", ...)
    protocol = models.CharField(max_length=16, blank=True, default="", db_index=True)
    # transport_protocol = L4 transport ("" when not applicable)
    transport_protocol = models.CharField(max_length=16, blank=True, default="")

    packet_length = models.PositiveIntegerField(default=0)
    ttl = models.PositiveSmallIntegerField(null=True, blank=True)
    tcp_flags = models.CharField(max_length=16, blank=True, default="")
    icmp_type = models.PositiveSmallIntegerField(null=True, blank=True)
    icmp_code = models.PositiveSmallIntegerField(null=True, blank=True)

    # Limited diagnostic payload preview (never a full payload)
    payload_length = models.PositiveIntegerField(null=True, blank=True)
    payload_preview = models.TextField(blank=True, default="")
    payload_hex = models.TextField(blank=True, default="")

    is_ipv4 = models.BooleanField(default=False)
    is_ipv6 = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp", "-id"]
        indexes = [
            models.Index(fields=["session", "timestamp"]),
            models.Index(fields=["session", "protocol"]),
            models.Index(fields=["protocol", "timestamp"]),
            models.Index(fields=["source_ip", "destination_ip"]),
            models.Index(fields=["session", "source_port", "destination_port"]),
        ]

    def __str__(self) -> str:
        return f"{self.protocol or '?'} {self.source_ip} -> {self.destination_ip}"

    @property
    def has_payload(self) -> bool:
        return bool(self.payload_hex or self.payload_preview)


class DNSQuery(models.Model):
    """A DNS query observed inside a captured packet."""

    packet = models.ForeignKey(
        Packet, on_delete=models.CASCADE, related_name="dns_queries"
    )
    query_name = models.CharField(max_length=255, db_index=True)
    query_type = models.CharField(max_length=16, blank=True, default="", db_index=True)
    response_code = models.CharField(max_length=16, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["query_name", "query_type"]),
        ]

    def __str__(self) -> str:
        return f"{self.query_name} ({self.query_type})"


class NetworkInterface(models.Model):
    """A network interface discovered on the capture host."""

    name = models.CharField(max_length=128, unique=True)
    description = models.CharField(max_length=255, blank=True, default="")
    mac_address = models.CharField(max_length=32, blank=True, default="")
    is_active = models.BooleanField(default=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class ApplicationSetting(models.Model):
    """Key/value application configuration stored in the database."""

    key = models.CharField(max_length=64, unique=True)
    value = models.CharField(max_length=255, blank=True, default="")
    description = models.CharField(max_length=255, blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["key"]

    def __str__(self) -> str:
        return f"{self.key}={self.value}"


def get_setting(key: str, default: str = "") -> str:
    """Fetch a setting value with a fallback default."""
    try:
        return ApplicationSetting.objects.get(key=key).value or default
    except ApplicationSetting.DoesNotExist:
        return default


def set_setting(key: str, value: str, description: str = "") -> None:
    """Create or update a setting value."""
    ApplicationSetting.objects.update_or_create(
        key=key, defaults={"value": value, "description": description}
    )


def payload_preview_max_bytes() -> int:
    """Effective maximum payload preview size from settings/DB config."""
    raw = get_setting(SETTING_MAX_PAYLOAD_PREVIEW_BYTES, "256")
    try:
        return max(8, min(int(raw), 4096))
    except (TypeError, ValueError):
        return 256
