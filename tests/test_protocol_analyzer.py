"""Protocol analyzer and statistics tests."""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from capture.protocol_analyzer import (
    dns_query_frequency,
    packet_size_distribution,
    protocol_distribution,
    top_values,
    traffic_over_time,
)
from capture.statistics import build_session_statistics
from sniffer.constants import tcp_flags_to_string
from sniffer.models import CaptureSession, DNSQuery, Packet
from tests.test_factories import dns_packet, icmp_packet, tcp_packet, udp_packet


class TcpFlagsHelperTests(TestCase):
    def test_flags_to_string(self):
        self.assertEqual(tcp_flags_to_string(0), "")
        self.assertEqual(tcp_flags_to_string(0x02), "S")
        self.assertEqual(tcp_flags_to_string(0x18), "PA")
        self.assertEqual(tcp_flags_to_string(0xFF), "FSRPAUEC")


class ProtocolDistributionTests(TestCase):
    def setUp(self):
        self.session = CaptureSession.objects.create(session_name="S", interface="eth0")

    def _add(self, packet, ts=None):
        from capture.packet_parser import parse_packet

        data = parse_packet(packet, payload_enabled=False, max_payload_bytes=256)
        row = Packet.objects.create(
            session=self.session,
            timestamp=ts or timezone.now(),
            **{k: v for k, v in data.items() if k not in ("dns_entries", "timestamp")},
        )
        for entry in data["dns_entries"]:
            DNSQuery.objects.create(packet=row, **entry)
        return row

    def test_distribution_counts(self):
        self._add(tcp_packet())
        self._add(tcp_packet())
        self._add(udp_packet())
        self._add(icmp_packet())

        distribution = dict(protocol_distribution(session=self.session))
        self.assertEqual(distribution["TCP"], 2)
        self.assertEqual(distribution["UDP"], 1)
        self.assertEqual(distribution["ICMP"], 1)

    def test_top_values(self):
        self._add(tcp_packet(src="10.1.1.1"))
        self._add(tcp_packet(src="10.1.1.1"))
        self._add(udp_packet(src="10.1.1.2"))
        tops = top_values(Packet.objects.all(), "source_ip", 5)
        self.assertEqual(tops[0][0], "10.1.1.1")
        self.assertEqual(tops[0][1], 2)

    def test_traffic_over_time_buckets(self):
        now = timezone.now()
        self._add(tcp_packet(), ts=now)
        self._add(tcp_packet(), ts=now - timedelta(seconds=30))
        self._add(udp_packet(), ts=now - timedelta(minutes=5))
        buckets = traffic_over_time(session=self.session, bucket_seconds=60)
        self.assertGreaterEqual(len(buckets), 5)
        # Total packets must be preserved across all buckets.
        self.assertEqual(sum(bucket[1] for bucket in buckets), 3)

    def test_packet_size_distribution(self):
        self._add(tcp_packet())
        self._add(udp_packet())
        sizes = dict(packet_size_distribution(session=self.session))
        self.assertGreater(sum(sizes.values()), 0)

    def test_dns_frequency(self):
        for _ in range(3):
            self._add(dns_packet(qname="hot.example.com"))
        self._add(dns_packet(qname="rare.example.net"))
        rows = dns_query_frequency(session=self.session)
        self.assertEqual(rows[0]["query_name"], "hot.example.com")
        self.assertEqual(rows[0]["total"], 3)


class SessionStatisticsTests(TestCase):
    def setUp(self):
        self.session = CaptureSession.objects.create(
            session_name="S", interface="eth0", packet_count=4, total_bytes=1000
        )

    def _add(self, packet):
        from capture.packet_parser import parse_packet

        data = parse_packet(packet, payload_enabled=False, max_payload_bytes=256)
        Packet.objects.create(
            session=self.session,
            timestamp=timezone.now(),
            **{k: v for k, v in data.items() if k not in ("dns_entries", "timestamp")},
        )
        self.session.refresh_statistics()

    def test_build_session_statistics(self):
        self._add(tcp_packet())
        self._add(tcp_packet())
        self._add(udp_packet())
        self._add(icmp_packet())

        stats = build_session_statistics(self.session)
        self.assertEqual(stats.tcp_count, 2)
        self.assertEqual(stats.udp_count, 1)
        self.assertEqual(stats.icmp_count, 1)
        self.assertGreater(stats.average_packet_size, 0)
        self.assertTrue(any(ip[0] == "192.168.1.10" for ip in stats.top_sources))
        self.assertEqual(len(stats.anomalies), 0)

    def test_as_dict_shape(self):
        data = build_session_statistics(self.session).as_dict()
        self.assertIn("packet_count", data)
        self.assertIn("anomalies", data)
        self.assertIn("top_sources", data)

    def test_icmp_anomaly_detected(self):
        for _ in range(30):
            self._add(icmp_packet())
        for _ in range(20):
            self._add(tcp_packet())
        stats = build_session_statistics(self.session)
        self.assertGreaterEqual(stats.packet_count, 50)
        self.assertTrue(any(a.title == "Elevated ICMP traffic" for a in stats.anomalies))
