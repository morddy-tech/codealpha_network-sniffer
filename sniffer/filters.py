"""Query-set filtering helpers for the packet explorer and analytics pages."""

from __future__ import annotations

from typing import Optional

from django.db.models import Q, QuerySet

from sniffer.constants import Protocol
from sniffer.forms import DNSFilterForm, PacketFilterForm, SessionFilterForm


def filter_packets(queryset: QuerySet, form: PacketFilterForm) -> QuerySet:
    """Apply validated explorer filters to a packet queryset."""
    cleaned = form.cleaned_data

    q = (cleaned.get("q") or "").strip()
    if q:
        queryset = queryset.filter(
            Q(source_ip__icontains=q)
            | Q(destination_ip__icontains=q)
            | Q(protocol__icontains=q)
            | Q(tcp_flags__icontains=q)
        )

    protocol = (cleaned.get("protocol") or "").strip()
    if protocol:
        queryset = _protocol_queryset(queryset, protocol)

    session = cleaned.get("session")
    if session:
        queryset = queryset.filter(session=session)

    source_ip = (cleaned.get("source_ip") or "").strip()
    if source_ip:
        queryset = queryset.filter(source_ip__icontains=source_ip)

    destination_ip = (cleaned.get("destination_ip") or "").strip()
    if destination_ip:
        queryset = queryset.filter(destination_ip__icontains=destination_ip)

    port = cleaned.get("port")
    if port:
        queryset = queryset.filter(Q(source_port=port) | Q(destination_port=port))

    date_from = cleaned.get("date_from")
    if date_from:
        queryset = queryset.filter(timestamp__date__gte=date_from)

    date_to = cleaned.get("date_to")
    if date_to:
        queryset = queryset.filter(timestamp__date__lte=date_to)

    return queryset


def filter_sessions(queryset: QuerySet, form: SessionFilterForm) -> QuerySet:
    """Apply validated session-list filters."""
    cleaned = form.cleaned_data
    q = (cleaned.get("q") or "").strip()
    if q:
        queryset = queryset.filter(
            Q(session_name__icontains=q) | Q(interface__icontains=q)
        )
    status = (cleaned.get("status") or "").strip()
    if status:
        queryset = queryset.filter(status=status)
    return queryset


def filter_dns_queries(queryset: QuerySet, form: DNSFilterForm) -> QuerySet:
    """Apply validated DNS-analysis filters."""
    cleaned = form.cleaned_data
    q = (cleaned.get("q") or "").strip()
    if q:
        queryset = queryset.filter(query_name__icontains=q)
    query_type = (cleaned.get("query_type") or "").strip()
    if query_type:
        queryset = queryset.filter(query_type__iexact=query_type)
    return queryset


def _protocol_queryset(queryset: QuerySet, protocol: str) -> QuerySet:
    """Map a filter label to ORM lookups."""
    label = protocol.lower()
    if label == "tcp":
        return queryset.filter(protocol=Protocol.TCP)
    if label == "udp":
        return queryset.filter(protocol=Protocol.UDP)
    if label == "icmp":
        return queryset.filter(protocol=Protocol.ICMP)
    if label == "icmpv6":
        return queryset.filter(protocol=Protocol.ICMPV6)
    if label == "arp":
        return queryset.filter(protocol=Protocol.ARP)
    if label == "dns":
        return queryset.filter(protocol=Protocol.DNS)
    if label == "ipv4":
        return queryset.filter(is_ipv4=True)
    if label == "ipv6":
        return queryset.filter(is_ipv6=True)
    return queryset
