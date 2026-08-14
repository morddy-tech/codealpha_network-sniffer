"""Passive traffic statistics and anomaly indicators.

These indicators are heuristic, passive observations.  They are explicitly
labeled as requiring human investigation and are NOT presented as definitive
intrusion-detection results.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List

from django.db import models
from django.db.models import Avg, Count, Max, Sum
from django.utils import timezone

logger = logging.getLogger("capture.statistics")

# Heuristic thresholds (conservative by design).
DNS_SAME_NAME_THRESHOLD = 100          # queries for the same name
ICMP_PERCENT_THRESHOLD = 20.0          # ICMP share of traffic
TCP_SYN_PERCENT_THRESHOLD = 40.0       # packets with a SYN flag
PACKET_RATE_SD_THRESHOLD = 6.0         # peak minute rate vs mean rate
DISTINCT_PORTS_THRESHOLD = 500         # distinct destination ports


@dataclass
class AnomalyIndicator:
    """A passive heuristic anomaly indicator."""

    severity: str  # "info" | "warning" | "high"
    title: str
    description: str

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
        }


@dataclass
class SessionStatistics:
    """Aggregated statistics for one capture session."""

    session_id: int
    session_name: str
    packet_count: int = 0
    total_bytes: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    arp_count: int = 0
    dns_count: int = 0
    ipv4_count: int = 0
    ipv6_count: int = 0
    top_sources: List[tuple] = field(default_factory=list)
    top_destinations: List[tuple] = field(default_factory=list)
    top_source_ports: List[tuple] = field(default_factory=list)
    top_destination_ports: List[tuple] = field(default_factory=list)
    anomalies: List[AnomalyIndicator] = field(default_factory=list)

    @property
    def average_packet_size(self) -> float:
        if not self.packet_count:
            return 0.0
        return round(self.total_bytes / self.packet_count, 1)

    def as_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "session_name": self.session_name,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "tcp_count": self.tcp_count,
            "udp_count": self.udp_count,
            "icmp_count": self.icmp_count,
            "arp_count": self.arp_count,
            "dns_count": self.dns_count,
            "ipv4_count": self.ipv4_count,
            "ipv6_count": self.ipv6_count,
            "average_packet_size": self.average_packet_size,
            "top_sources": list(self.top_sources),
            "top_destinations": list(self.top_destinations),
            "top_source_ports": list(self.top_source_ports),
            "top_destination_ports": list(self.top_destination_ports),
            "anomalies": [a.as_dict() for a in self.anomalies],
        }


def build_session_statistics(session) -> SessionStatistics:
    """Compute statistics for a capture session from stored packets."""
    from sniffer.models import Packet

    packets = session.packets
    stats = SessionStatistics(
        session_id=session.id,
        session_name=session.session_name,
        packet_count=session.packet_count,
        total_bytes=session.total_bytes,
        tcp_count=session.tcp_count,
        udp_count=session.udp_count,
        icmp_count=session.icmp_count,
        arp_count=session.arp_count,
        dns_count=session.dns_count,
        ipv4_count=session.ipv4_count,
        ipv6_count=session.ipv6_count,
    )

    stats.top_sources = _top(packets, "source_ip", 10)
    stats.top_destinations = _top(packets, "destination_ip", 10)
    stats.top_source_ports = _top(packets, "source_port", 10)
    stats.top_destination_ports = _top(packets, "destination_port", 10)

    stats.anomalies = _detect_anomalies(session, packets)
    return stats


def _top(queryset, field: str, limit: int) -> List[tuple]:
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


def _detect_anomalies(session, packets) -> List[AnomalyIndicator]:
    """Heuristic, passive anomaly indicators — not IDS conclusions."""
    indicators: List[AnomalyIndicator] = []

    # 1. ICMP share of traffic
    if session.packet_count >= 50:
        icmp_share = (session.icmp_count / session.packet_count) * 100.0
        if icmp_share > ICMP_PERCENT_THRESHOLD:
            indicators.append(
                AnomalyIndicator(
                    severity="warning",
                    title="Elevated ICMP traffic",
                    description=(
                        f"ICMP is {icmp_share:.1f}% of {session.packet_count} packets "
                        f"(threshold {ICMP_PERCENT_THRESHOLD:.0f}%). "
                        "Potential anomaly indicator — requires human investigation."
                    ),
                )
            )

    # 2. Peak packet-rate spike vs mean
    minute_buckets: dict = {}
    now = timezone.now()
    cutoff = now - timezone.timedelta(hours=6)
    recent = packets.filter(timestamp__gte=cutoff)
    for ts in recent.values_list("timestamp", flat=True).iterator():
        minute_buckets[int(ts.timestamp()) // 60] = minute_buckets.get(int(ts.timestamp()) // 60, 0) + 1
    if len(minute_buckets) >= 3:
        values = list(minute_buckets.values())
        mean = sum(values) / len(values)
        peak = max(values)
        if mean > 0 and peak / mean > PACKET_RATE_SD_THRESHOLD:
            indicators.append(
                AnomalyIndicator(
                    severity="high",
                    title="Traffic spike detected",
                    description=(
                        f"Peak minute rate ({peak} pkts/min) is {peak / mean:.1f}x the "
                        f"mean rate ({mean:.1f} pkts/min). "
                        "Potential anomaly indicator — requires human investigation."
                    ),
                )
            )

    # 3. DNS query concentration for a single name
    from sniffer.models import DNSQuery

    hot = (
        DNSQuery.objects.filter(packet__session=session)
        .values("query_name")
        .annotate(total=Count("id"))
        .filter(total__gte=DNS_SAME_NAME_THRESHOLD)
        .order_by("-total")[:5]
    )
    for row in hot:
        indicators.append(
            AnomalyIndicator(
                severity="warning",
                title="High-frequency DNS queries",
                description=(
                    f"'{row['query_name']}' was queried {row['total']} times in this "
                    f"session (threshold {DNS_SAME_NAME_THRESHOLD}). "
                    "Potential anomaly indicator — requires human investigation."
                ),
            )
        )

    # 4. Unusually high number of distinct destination ports
    distinct_ports = (
        packets.exclude(destination_port=None).values("destination_port").distinct().count()
    )
    if distinct_ports > DISTINCT_PORTS_THRESHOLD:
        indicators.append(
            AnomalyIndicator(
                severity="info",
                title="High destination-port concentration",
                description=(
                    f"{distinct_ports} distinct destination ports observed (threshold "
                    f"{DISTINCT_PORTS_THRESHOLD}). "
                    "Potential anomaly indicator — requires human investigation."
                ),
            )
        )

    # 5. SYN-heavy traffic
    if session.tcp_count >= 100:
        syn_count = packets.filter(tcp_flags__contains="S", transport_protocol="TCP").count()
        syn_share = (syn_count / session.tcp_count) * 100.0
        if syn_share > TCP_SYN_PERCENT_THRESHOLD:
            indicators.append(
                AnomalyIndicator(
                    severity="warning",
                    title="Elevated SYN traffic",
                    description=(
                        f"{syn_share:.1f}% of TCP packets carry a SYN flag (threshold "
                        f"{TCP_SYN_PERCENT_THRESHOLD:.0f}%). "
                        "Potential anomaly indicator — requires human investigation."
                    ),
                )
            )

    return indicators
