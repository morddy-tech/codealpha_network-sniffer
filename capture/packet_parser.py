"""Defensive packet parsing.

Converts raw Scapy packets into sanitized metadata dictionaries that are safe
to store in the database.  Every layer is optional: a packet that is missing
a layer simply yields empty fields for that layer.  One malformed packet must
never take down the capture worker.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from django.utils import timezone

from sniffer.constants import Protocol

logger = logging.getLogger("capture.parser")

# Layers we inspect, ordered from the most specific to the most generic.
try:
    from scapy.layers.dns import DNS, DNSQR  # type: ignore[import-untyped]
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore[import-untyped]
    from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6  # type: ignore[import-untyped]
    from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]
    from scapy.packet import Packet as ScapyPacket  # type: ignore[import-untyped]
    from scapy.packet import Raw  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - Scapy is a hard dependency
    ScapyPacket = None  # type: ignore[assignment]
    Ether = IP = IPv6 = ARP = TCP = UDP = ICMP = DNS = DNSQR = Raw = None  # type: ignore[assignment]

_ETHERTYPES = {
    0x0800: Protocol.IP,
    0x86DD: Protocol.IPV6,
    0x0806: Protocol.ARP,
}


def _flag_string(tcp_layer) -> str:
    """Build a compact TCP flag string like ``SA`` or ``PA``."""
    try:
        flags = int(tcp_layer.flags)
    except (AttributeError, TypeError, ValueError):
        return ""
    from sniffer.constants import tcp_flags_to_string

    return tcp_flags_to_string(flags)


def parse_packet(packet, *, payload_enabled: bool, max_payload_bytes: int) -> Optional[Dict[str, Any]]:
    """
    Extract sanitized metadata from a Scapy packet.

    :param packet: a Scapy packet instance
    :param payload_enabled: store limited payload previews?
    :param max_payload_bytes: maximum payload bytes stored
    :return: metadata dict, or ``None`` when the packet cannot be parsed
    """
    if ScapyPacket is None:  # pragma: no cover
        raise RuntimeError("Scapy is not installed; cannot parse packets.")

    if not isinstance(packet, ScapyPacket):
        return None

    try:
        return _parse_packet_inner(packet, payload_enabled, max_payload_bytes)
    except Exception:  # noqa: BLE001 - defensive: never let one packet kill the capture
        logger.warning("Failed to parse a packet (%s); skipping.", type(packet).__name__)
        return None


def _parse_packet_inner(
    packet: "ScapyPacket", payload_enabled: bool, max_payload_bytes: int
) -> Dict[str, Any]:
    ether = packet.getlayer(Ether)
    ip = packet.getlayer(IP)
    ip6 = packet.getlayer(IPv6)
    arp = packet.getlayer(ARP)
    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP)
    icmp = packet.getlayer(ICMP)
    icmp6 = packet.getlayer(ICMPv6EchoRequest)
    dns = packet.getlayer(DNS)
    raw = packet.getlayer(Raw)

    # ------------------------------------------------------------------ IP addressing
    source_ip = ""
    destination_ip = ""
    ttl = None
    is_ipv4 = ip is not None
    is_ipv6 = ip6 is not None

    if ip is not None:
        try:
            source_ip = str(ip.src)
            destination_ip = str(ip.dst)
            ttl = int(getattr(ip, "ttl", 0)) or None
        except (AttributeError, ValueError):
            pass
    elif ip6 is not None:
        try:
            source_ip = str(ip6.src)
            destination_ip = str(ip6.dst)
            ttl = int(getattr(ip6, "hlim", 0)) or None
        except (AttributeError, ValueError):
            pass
    elif arp is not None:
        try:
            source_ip = str(arp.psrc)
            destination_ip = str(arp.pdst)
        except (AttributeError, ValueError):
            pass

    # ------------------------------------------------------------ protocol resolution
    protocol = _resolve_protocol(ether, arp, ip, ip6, icmp, icmp6, tcp, udp)
    transport = _resolve_transport(tcp, udp, icmp, icmp6)
    if dns is not None and transport:
        protocol = Protocol.DNS

    # -------------------------------------------------------------------------- ports
    source_port = None
    destination_port = None
    if tcp is not None:
        source_port, destination_port = int(tcp.sport), int(tcp.dport)
    elif udp is not None:
        source_port, destination_port = int(udp.sport), int(udp.dport)

    # ------------------------------------------------------------------------ ICMP info
    icmp_type = None
    icmp_code = None
    if icmp is not None:
        icmp_type, icmp_code = int(icmp.type), int(icmp.code)
    elif icmp6 is not None:
        icmp_type, icmp_code = int(icmp6.type), int(icmp6.code)

    # ------------------------------------------------------------------- TCP flags
    tcp_flags = _flag_string(tcp) if tcp is not None else ""

    # ------------------------------------------------------------- DNS query metadata
    dns_entries: list[Dict[str, str]] = []
    if dns is not None:
        dns_entries = _extract_dns_entries(dns)

    # ---------------------------------------------------------------- payload preview
    payload_length = None
    payload_preview = ""
    payload_hex = ""
    if raw is not None:
        try:
            payload = bytes(raw.load)
        except (AttributeError, TypeError, ValueError):
            payload = b""
        payload_length = len(payload)
        if payload_enabled and payload:
            limit = max(1, int(max_payload_bytes))
            truncated = payload[:limit]
            payload_hex = truncated.hex(" ")
            payload_preview = _ascii_preview(truncated)
            if len(payload) > limit:
                payload_preview += " … (truncated)"

    # ----------------------------------------------------------------------- lengths
    # IMPORTANT: never call len(packet) on a freshly built/unsniffed packet
    # without explicit MACs - Scapy rebuilds the packet and may attempt live
    # ARP resolution (getmacbyip) for empty/broadcast destination MACs, which
    # performs real network I/O and can block. Prefer the wire length that
    # the capture layer records (no rebuild), and only fall back to a build
    # for packets whose layers are already fully populated.
    packet_length = 0
    wirelen = getattr(packet, "wirelen", None)
    if wirelen is not None:
        try:
            packet_length = int(wirelen)
        except (TypeError, ValueError):
            packet_length = 0
    else:
        try:
            packet_length = len(packet)
        except Exception:  # noqa: BLE001 - some crafted packets are not sized
            pass

    return {
        "timestamp": timezone.now(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "transport_protocol": transport,
        "packet_length": packet_length,
        "ttl": ttl,
        "tcp_flags": tcp_flags,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "payload_length": payload_length,
        "payload_preview": payload_preview,
        "payload_hex": payload_hex,
        "is_ipv4": is_ipv4,
        "is_ipv6": is_ipv6,
        "dns_entries": dns_entries,
    }


def _resolve_protocol(ether, arp, ip, ip6, icmp, icmp6, tcp, udp) -> str:
    """Determine the dominant protocol label for the packet."""
    if arp is not None:
        return Protocol.ARP
    if icmp is not None:
        return Protocol.ICMP
    if icmp6 is not None:
        return Protocol.ICMPV6
    if tcp is not None:
        return Protocol.TCP
    if udp is not None:
        return Protocol.UDP
    if ip is not None:
        return Protocol.IP
    if ip6 is not None:
        return Protocol.IPV6
    if ether is not None:
        ethertype = int(getattr(ether, "type", 0)) or 0
        return _ETHERTYPES.get(ethertype, Protocol.OTHER)
    return Protocol.UNKNOWN


def _resolve_transport(tcp, udp, icmp, icmp6) -> str:
    """Determine the L4 transport protocol label, if any."""
    if tcp is not None:
        return Protocol.TCP
    if udp is not None:
        return Protocol.UDP
    if icmp is not None:
        return Protocol.ICMP
    if icmp6 is not None:
        return Protocol.ICMPV6
    return ""


def _extract_dns_entries(dns) -> list[Dict[str, str]]:
    """Extract DNS query metadata (name, type) plus the response code."""
    from sniffer.constants import dns_qtype_label, dns_rcode_label

    entries: list[Dict[str, str]] = []
    try:
        rcode = dns_rcode_label(getattr(dns, "rcode", 0))
    except (AttributeError, ValueError):
        rcode = ""

    qdcount = 0
    try:
        qdcount = int(getattr(dns, "qdcount", 0)) or 0
    except (AttributeError, ValueError):
        qdcount = 0

    for idx in range(min(max(qdcount, 0), 16)):  # bounded loop for safety
        try:
            qd = dns.qd[idx]  # type: ignore[attr-defined]
        except (IndexError, TypeError, AttributeError):
            break
        if qd is None or not isinstance(qd, DNSQR):
            continue
        try:
            raw_name = getattr(qd, "qname", b"") or b""
            if isinstance(raw_name, bytes):
                qname = raw_name.decode("utf-8", errors="replace")
            else:
                qname = str(raw_name)
            qtype = dns_qtype_label(getattr(qd, "qtype", None))
        except (AttributeError, ValueError):
            continue
        qname = qname.rstrip(".")
        if qname and len(qname) <= 255:
            entries.append({"query_name": qname, "query_type": qtype, "response_code": rcode})
    return entries


def _ascii_preview(payload: bytes) -> str:
    """Render a safe ASCII preview of raw bytes."""
    chars = []
    for byte in payload:
        if 32 <= byte <= 126:
            chars.append(chr(byte))
        else:
            chars.append(".")
    return "".join(chars)
