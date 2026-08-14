"""Protocol analysis helpers used by views, reports and the capture worker."""

from __future__ import annotations

import logging
from typing import Dict, List, Tuple

from django.db import models
from django.db.models import Count, Q
from django.utils import timezone

logger = logging.getLogger("capture.analyzer")

PROTOCOL_LABELS = ["TCP", "UDP", "ICMP", "ICMPv6", "ARP", "DNS", "IP", "IPv6", "OTHER"]


def protocol_distribution(session=None, days: int | None = None) -> List[Tuple[str, int]]:
    """
    Count packets per protocol label.

    Returns a list of (label, count) tuples ordered by count descending.
    """
    from sniffer.models import Packet

    qs = Packet.objects.all()
    if session is not None:
        qs = qs.filter(session=session)
    if days is not None:
        qs = qs.filter(timestamp__gte=timezone.now() - timezone.timedelta(days=days))

    counts = dict(
        qs.values_list("protocol").annotate(total=Count("id")).order_by("-total")
    )
    ordered: List[Tuple[str, int]] = []
    for label in PROTOCOL_LABELS:
        if counts.get(label):
            ordered.append((label, counts[label]))
    for label, total in counts.items():
        if label not in dict(ordered):
            ordered.append((label, total))
    return ordered


def top_values(queryset, field: str, limit: int = 10) -> List[Tuple[str, int]]:
    """Return the top distinct values for a given field."""
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


def traffic_over_time(
    session=None, bucket_seconds: int = 60, limit_buckets: int = 120
) -> List[Tuple[str, int, int]]:
    """
    Group packets into fixed time buckets.

    Returns a list of (bucket_label, packet_count, byte_count) tuples.
    """
    from sniffer.models import Packet

    qs = Packet.objects.all()
    if session is not None:
        qs = qs.filter(session=session)

    qs = qs.only("timestamp", "packet_length")

    buckets: Dict[int, List[int]] = {}
    now = timezone.now()
    cutoff = now - timezone.timedelta(seconds=bucket_seconds * limit_buckets)
    qs = qs.filter(timestamp__gte=cutoff)

    for ts, length in qs.values_list("timestamp", "packet_length").iterator():
        seconds = int(ts.timestamp())
        bucket = seconds - (seconds % bucket_seconds)
        buckets.setdefault(bucket, [0, 0])
        buckets[bucket][0] += 1
        buckets[bucket][1] += length or 0

    if not buckets:
        return []

    start = min(buckets)
    end = max(buckets)
    result: List[Tuple[str, int, int]] = []
    bucket_ts = start
    while bucket_ts <= end:
        count, size = buckets.get(bucket_ts, [0, 0])
        label = timezone.datetime.fromtimestamp(bucket_ts, tz=timezone.get_current_timezone())
        result.append((label.strftime("%H:%M"), count, size))
        bucket_ts += bucket_seconds
    return result


def dns_query_frequency(session=None, limit: int = 25) -> List[Dict]:
    """Most frequently queried DNS names within the session/period."""
    from sniffer.models import DNSQuery

    qs = DNSQuery.objects.filter(packet__session=session) if session else DNSQuery.objects.all()
    rows = (
        qs.values("query_name", "query_type")
        .annotate(total=Count("id"))
        .order_by("-total")[:limit]
    )
    return list(rows)


def packet_size_distribution(session=None, buckets: Tuple[int, ...] = (64, 128, 256, 512, 1024, 1500)) -> List[Tuple[str, int]]:
    """Histogram of packet sizes into fixed buckets."""
    from sniffer.models import Packet

    qs = Packet.objects.all()
    if session is not None:
        qs = qs.filter(session=session)

    labels = [f"<= {b}" for b in buckets]
    result = dict.fromkeys(labels, 0)

    for length in qs.values_list("packet_length", flat=True).iterator():
        placed = False
        for idx, bound in enumerate(buckets):
            if length <= bound:
                result[labels[idx]] += 1
                placed = True
                break
        if not placed:
            result[labels[-1]] += 1
    return list(result.items())
