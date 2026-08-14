"""Lightweight JSON serializers for the built-in REST-ish API.

Keeps the payload exposure minimal: packet payload previews are only
serialized when the owning session explicitly enabled payload storage.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable


def serialize_session(session) -> Dict[str, Any]:
    return {
        "id": session.id,
        "session_name": session.session_name,
        "interface": session.interface,
        "status": session.status,
        "started_at": session.started_at.isoformat() if session.started_at else None,
        "ended_at": session.ended_at.isoformat() if session.ended_at else None,
        "packet_count": session.packet_count,
        "total_bytes": session.total_bytes,
        "tcp_count": session.tcp_count,
        "udp_count": session.udp_count,
        "icmp_count": session.icmp_count,
        "dns_count": session.dns_count,
        "arp_count": session.arp_count,
        "ipv4_count": session.ipv4_count,
        "ipv6_count": session.ipv6_count,
        "protocol_filter": session.protocol_filter,
        "payload_storage_enabled": session.payload_storage_enabled,
    }


def serialize_packet(packet, *, include_payload: bool = False) -> Dict[str, Any]:
    data = {
        "id": packet.id,
        "session": packet.session_id,
        "timestamp": packet.timestamp.isoformat() if packet.timestamp else None,
        "source_ip": packet.source_ip,
        "destination_ip": packet.destination_ip,
        "source_port": packet.source_port,
        "destination_port": packet.destination_port,
        "protocol": packet.protocol,
        "transport_protocol": packet.transport_protocol,
        "packet_length": packet.packet_length,
        "ttl": packet.ttl,
        "tcp_flags": packet.tcp_flags,
        "icmp_type": packet.icmp_type,
        "icmp_code": packet.icmp_code,
        "is_ipv4": packet.is_ipv4,
        "is_ipv6": packet.is_ipv6,
    }
    if include_payload and packet.has_payload:
        data["payload_length"] = packet.payload_length
        data["payload_preview"] = packet.payload_preview
        data["payload_hex"] = packet.payload_hex
    return data


def serialize_dns_query(query) -> Dict[str, Any]:
    return {
        "id": query.id,
        "packet": query.packet_id,
        "query_name": query.query_name,
        "query_type": query.query_type,
        "response_code": query.response_code,
        "created_at": query.created_at.isoformat() if query.created_at else None,
    }


def serialize_interface(interface) -> Dict[str, Any]:
    return {
        "id": interface.id,
        "name": interface.name,
        "description": interface.description,
        "mac_address": interface.mac_address,
        "is_active": interface.is_active,
        "last_seen": interface.last_seen.isoformat() if interface.last_seen else None,
    }


def paginate(queryset, page: int, page_size: int) -> tuple:
    """Return (page_queryset, total, page, total_pages)."""
    from django.core.paginator import EmptyPage, Paginator

    paginator = Paginator(queryset, page_size)
    try:
        page_obj = paginator.page(page)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)
    return page_obj, paginator.count, page_obj.number, paginator.num_pages
