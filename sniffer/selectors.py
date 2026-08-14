"""Selector functions: clean, focused ORM queries for views and reports."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from django.db.models import Count, Q, Sum
from django.utils import timezone

from sniffer.models import CaptureSession, DNSQuery, Packet


def dashboard_summary() -> Dict[str, Any]:
    """Aggregated figures for the dashboard header cards."""
    packets = Packet.objects.all()
    return {
        "session_count": CaptureSession.objects.count(),
        "packet_count": packets.count(),
        "total_bytes": packets.aggregate(total=Sum("packet_length"))["total"] or 0,
        "tcp_count": packets.filter(protocol="TCP").count(),
        "udp_count": packets.filter(protocol="UDP").count(),
        "icmp_count": packets.filter(protocol__in=["ICMP", "ICMPv6"]).count(),
        "dns_count": packets.filter(protocol="DNS").count(),
        "arp_count": packets.filter(protocol="ARP").count(),
        "ipv4_count": packets.filter(is_ipv4=True).count(),
        "ipv6_count": packets.filter(is_ipv6=True).count(),
        "dns_query_count": DNSQuery.objects.count(),
    }


def recent_sessions(limit: int = 6) -> List[CaptureSession]:
    return list(CaptureSession.objects.order_by("-started_at")[:limit])


def recent_packets(limit: int = 10) -> List[Packet]:
    return list(Packet.objects.select_related("session").order_by("-timestamp")[:limit])


def top_ip_activity(limit: int = 6) -> Dict[str, List[tuple]]:
    """Top source and destination IPs across all captured data."""
    qs = Packet.objects.all()
    sources = _group_count(qs, "source_ip", limit)
    destinations = _group_count(qs, "destination_ip", limit)
    return {"sources": sources, "destinations": destinations}


def top_ports(limit: int = 6) -> List[tuple]:
    qs = Packet.objects.exclude(destination_port=None)
    return _group_count(qs, "destination_port", limit)


def _group_count(queryset, field: str, limit: int) -> List[tuple]:
    from django.db import models

    model_field = queryset.model._meta.get_field(field)
    excludes = {f"{field}__isnull": True}
    if isinstance(model_field, (models.CharField, models.TextField)):
        excludes[field] = ""
    return list(
        queryset.exclude(**excludes)
        .values_list(field)
        .annotate(total=Count("id"))
        .order_by("-total")[:limit]
    )


def analytics_overview(days: Optional[int] = None) -> Dict[str, Any]:
    """Cross-session analytics dataset."""
    from capture.protocol_analyzer import (
        packet_size_distribution,
        protocol_distribution,
        top_values,
        traffic_over_time,
    )

    if days:
        cutoff = timezone.now() - timezone.timedelta(days=days)
        packets = Packet.objects.filter(timestamp__gte=cutoff)
    else:
        packets = Packet.objects.all()

    return {
        "protocol_distribution": protocol_distribution(days=days),
        "packet_sizes": packet_size_distribution(),
        "timeline": traffic_over_time(bucket_seconds=60),
        "top_sources": top_values(packets, "source_ip", 10),
        "top_destinations": top_values(packets, "destination_ip", 10),
        "top_source_ports": top_values(packets, "source_port", 10),
        "top_destination_ports": top_values(packets, "destination_port", 10),
        "total_packets": packets.count(),
    }
