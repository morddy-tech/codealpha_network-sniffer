"""In-memory Scapy packet factories for unit tests only.

These packets are constructed entirely in memory and are NEVER transmitted
onto a real network. They exercise the parser/protocol stack deterministically.
"""

from __future__ import annotations

import os

from scapy.all import (  # type: ignore[import-untyped]
    ARP,
    DNS,
    DNSQR,
    Ether,
    ICMP,
    ICMPv6EchoRequest,
    IP,
    IPv6,
    Raw,
    TCP,
    UDP,
)

ETHERTYPE_IPV6 = 0x86DD

# Explicit unicast MACs: building an Ether/IP packet with an empty or
# broadcast destination MAC makes Scapy attempt live ARP resolution at build
# time (getmacbyip -> real network I/O). Tests must never touch the network.
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"


def tcp_packet(
    src: str = "192.168.1.10",
    dst: str = "8.8.8.8",
    sport: int = 49152,
    dport: int = 443,
    ttl: int = 64,
    flags: int = 0x12,  # SYN+ACK
    payload: bytes = b"",
):
    """Build an Ethernet/IPv4/TCP packet with optional payload."""
    return Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src, dst=dst, ttl=ttl) / TCP(sport=sport, dport=dport, flags=flags) / (Raw(load=payload) if payload else b"")


def udp_packet(
    src: str = "192.168.1.20",
    dst: str = "10.0.0.5",
    sport: int = 5353,
    dport: int = 53,
    payload: bytes = b"",
):
    return Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / (Raw(load=payload) if payload else b"")


def icmp_packet(
    src: str = "192.168.1.1",
    dst: str = "192.168.1.254",
    icmp_type: int = 8,
    icmp_code: int = 0,
):
    return Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src, dst=dst) / ICMP(type=icmp_type, code=icmp_code)


def dns_packet(
    src: str = "192.168.1.30",
    dst: str = "8.8.4.4",
    qname: str = "example.com",
    qtype: int = 1,  # A
    rcode: int = 0,
):
    return (
        Ether(src=SRC_MAC, dst=DST_MAC)
        / IP(src=src, dst=dst)
        / UDP(sport=54321, dport=53)
        / DNS(qr=0, qdcount=1, rcode=rcode, qd=DNSQR(qname=qname, qtype=qtype))
    )


def arp_packet(
    src_ip: str = "192.168.1.5",
    dst_ip: str = "192.168.1.1",
):
    return Ether(src=SRC_MAC, dst=DST_MAC) / ARP(psrc=src_ip, pdst=dst_ip)


def ipv6_packet(
    src: str = "2001:db8::1",
    dst: str = "2001:db8::2",
    dport: int = 443,
):
    return Ether(src=SRC_MAC, dst=DST_MAC) / IPv6(src=src, dst=dst) / TCP(sport=50000, dport=dport, flags=0x02)


def icmpv6_packet(src: str = "fe80::1", dst: str = "ff02::1"):
    return Ether(src=SRC_MAC, dst=DST_MAC) / IPv6(src=src, dst=dst) / ICMPv6EchoRequest()


def malformed_packet():
    """A packet that should not crash the parser (garbage raw bytes)."""
    return Ether(b"\xff\xfe" * 30) / Raw(load=b"\x00\x01garbage\xff\xfe")


def ethernet_only_packet():
    return Ether(src=SRC_MAC, dst=DST_MAC) / Raw(load=b"\x00" * 14)
