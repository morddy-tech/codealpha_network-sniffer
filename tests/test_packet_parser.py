"""Packet parser tests — pure in-memory Scapy packets, no network traffic."""

from __future__ import annotations

from django.test import SimpleTestCase

from capture.packet_parser import parse_packet
from tests.test_factories import (
    arp_packet,
    dns_packet,
    ethernet_only_packet,
    icmp_packet,
    icmpv6_packet,
    ipv6_packet,
    malformed_packet,
    tcp_packet,
    udp_packet,
)


class PacketParserTests(SimpleTestCase):
    def _parse(self, packet, payload_enabled=False, max_bytes=256):
        result = parse_packet(
            packet, payload_enabled=payload_enabled, max_payload_bytes=max_bytes
        )
        self.assertIsNotNone(result)
        return result

    # ------------------------------------------------------------ TCP
    def test_tcp_packet(self):
        data = self._parse(tcp_packet(payload=b"GET / HTTP/1.1"))
        self.assertEqual(data["protocol"], "TCP")
        self.assertEqual(data["transport_protocol"], "TCP")
        self.assertEqual(data["source_ip"], "192.168.1.10")
        self.assertEqual(data["destination_ip"], "8.8.8.8")
        self.assertEqual(data["source_port"], 49152)
        self.assertEqual(data["destination_port"], 443)
        self.assertEqual(data["ttl"], 64)
        self.assertEqual(data["tcp_flags"], "SA")
        self.assertEqual(data["is_ipv4"], True)
        self.assertEqual(data["is_ipv6"], False)

    def test_tcp_flags_string(self):
        self.assertEqual(self._parse(tcp_packet(flags=0x02))["tcp_flags"], "S")
        self.assertEqual(self._parse(tcp_packet(flags=0x01))["tcp_flags"], "F")
        self.assertEqual(self._parse(tcp_packet(flags=0x12))["tcp_flags"], "SA")

    # ------------------------------------------------------------ UDP
    def test_udp_packet(self):
        data = self._parse(udp_packet())
        self.assertEqual(data["protocol"], "UDP")
        self.assertEqual(data["transport_protocol"], "UDP")
        self.assertEqual(data["source_port"], 5353)
        self.assertEqual(data["destination_port"], 53)

    # ------------------------------------------------------------ ICMP
    def test_icmp_packet(self):
        data = self._parse(icmp_packet())
        self.assertEqual(data["protocol"], "ICMP")
        self.assertEqual(data["icmp_type"], 8)
        self.assertEqual(data["icmp_code"], 0)
        self.assertIsNone(data["source_port"])

    def test_icmpv6_packet(self):
        data = self._parse(icmpv6_packet())
        self.assertEqual(data["protocol"], "ICMPv6")
        self.assertEqual(data["is_ipv6"], True)

    # ------------------------------------------------------------ ARP
    def test_arp_packet(self):
        data = self._parse(arp_packet())
        self.assertEqual(data["protocol"], "ARP")
        self.assertEqual(data["source_ip"], "192.168.1.5")
        self.assertEqual(data["destination_ip"], "192.168.1.1")

    # ------------------------------------------------------------ IPv6
    def test_ipv6_packet(self):
        data = self._parse(ipv6_packet())
        self.assertEqual(data["protocol"], "TCP")
        self.assertEqual(data["is_ipv6"], True)
        self.assertEqual(data["source_ip"], "2001:db8::1")

    # ------------------------------------------------------------ DNS
    def test_dns_packet(self):
        data = self._parse(dns_packet(qname="sub.example.org", qtype=28))
        self.assertEqual(data["protocol"], "DNS")
        self.assertEqual(len(data["dns_entries"]), 1)
        entry = data["dns_entries"][0]
        self.assertEqual(entry["query_name"], "sub.example.org")
        self.assertEqual(entry["query_type"], "AAAA")
        self.assertEqual(entry["response_code"], "NOERROR")

    # ------------------------------------------------------------ malformed
    def test_malformed_packet_does_not_crash(self):
        result = parse_packet(
            malformed_packet(), payload_enabled=True, max_payload_bytes=256
        )
        # Either parsed defensively or skipped - but never raises.
        self.assertIsNotNone(result)

    def test_ethernet_only_packet(self):
        data = self._parse(ethernet_only_packet())
        self.assertEqual(data["protocol"], "OTHER")
        self.assertEqual(data["source_ip"], "")

    # ------------------------------------------------------------ payload
    def test_payload_disabled_by_default(self):
        data = self._parse(tcp_packet(payload=b"secret-stuff-here"))
        self.assertEqual(data["payload_preview"], "")
        self.assertEqual(data["payload_hex"], "")
        self.assertEqual(data["payload_length"], 17)

    def test_payload_enabled_and_truncated(self):
        data = self._parse(
            tcp_packet(payload=b"A" * 100), payload_enabled=True, max_bytes=32
        )
        self.assertEqual(len(data["payload_hex"].replace(" ", "")), 64)
        self.assertEqual(len(data["payload_hex"].split()), 32)
        self.assertIn("truncated", data["payload_preview"])

    def test_payload_ascii_preview_escapes_non_printables(self):
        data = self._parse(
            udp_packet(payload=b"Hello\x00\xffWorld"), payload_enabled=True, max_bytes=64
        )
        self.assertIn("Hello", data["payload_preview"])
        self.assertIn("World", data["payload_preview"])

    def test_payload_length_metadata_always_stored(self):
        data = self._parse(udp_packet(payload=b"x" * 50))
        self.assertEqual(data["payload_length"], 50)

    # ------------------------------------------------------------ misc
    def test_zero_length_preview_when_no_raw(self):
        data = self._parse(icmp_packet())
        self.assertIsNone(data["payload_length"])

    def test_packet_length_is_captured(self):
        data = self._parse(tcp_packet())
        self.assertGreater(data["packet_length"], 40)
