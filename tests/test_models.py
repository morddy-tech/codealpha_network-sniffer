"""Model and ORM tests."""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from sniffer.constants import SessionStatus
from sniffer.models import (
    ApplicationSetting,
    CaptureSession,
    DNSQuery,
    NetworkInterface,
    Packet,
    get_setting,
    set_setting,
)
from tests.test_factories import (
    arp_packet,
    dns_packet,
    icmp_packet,
    tcp_packet,
    udp_packet,
)
from capture.packet_parser import parse_packet


class CaptureSessionModelTests(TestCase):
    def test_create_session_with_defaults(self):
        session = CaptureSession.objects.create(session_name="Test", interface="eth0")
        self.assertEqual(session.status, SessionStatus.RUNNING)
        self.assertEqual(session.packet_count, 0)
        self.assertIsNone(session.ended_at)

    def test_str(self):
        session = CaptureSession.objects.create(session_name="My Capture", interface="eth0")
        self.assertEqual(str(session), "My Capture")

    def test_duration_zero_when_not_ended(self):
        session = CaptureSession.objects.create(session_name="S", interface="eth0")
        self.assertEqual(session.duration, 0.0)

    def test_mark_completed_and_failed(self):
        session = CaptureSession.objects.create(session_name="S", interface="eth0")
        session.mark_completed()
        session.refresh_from_db()
        self.assertEqual(session.status, SessionStatus.COMPLETED)
        self.assertIsNotNone(session.ended_at)

        session.mark_failed("boom")
        session.refresh_from_db()
        self.assertEqual(session.status, SessionStatus.FAILED)
        self.assertIn("boom", session.error_message)

    def test_refresh_statistics_recomputes_from_packets(self):
        session = CaptureSession.objects.create(session_name="S", interface="eth0")
        packets = [tcp_packet(), udp_packet(), icmp_packet(), arp_packet()]
        rows = []
        for p in packets:
            data = parse_packet(p, payload_enabled=False, max_payload_bytes=256)
            rows.append(Packet(session=session, **{k: v for k, v in data.items() if k != "dns_entries"}))
        Packet.objects.bulk_create(rows)

        session.refresh_statistics()
        self.assertEqual(session.packet_count, 4)
        self.assertEqual(session.tcp_count, 1)
        self.assertEqual(session.udp_count, 1)
        self.assertEqual(session.icmp_count, 1)
        self.assertEqual(session.arp_count, 1)
        self.assertEqual(session.ipv4_count, 3)

    def test_cascade_delete(self):
        session = CaptureSession.objects.create(session_name="S", interface="eth0")
        data = parse_packet(tcp_packet(), payload_enabled=False, max_payload_bytes=256)
        Packet.objects.create(session=session, **{k: v for k, v in data.items() if k != "dns_entries"})
        session.delete()
        self.assertEqual(Packet.objects.count(), 0)


class PacketModelTests(TestCase):
    def setUp(self):
        self.session = CaptureSession.objects.create(session_name="S", interface="eth0")

    def _packet_row(self, packet, **overrides):
        data = parse_packet(packet, payload_enabled=True, max_payload_bytes=64)
        row = {k: v for k, v in data.items() if k != "dns_entries"}
        row.update(overrides)
        return Packet.objects.create(session=self.session, **row)

    def test_str_and_payload_flag(self):
        row = self._packet_row(tcp_packet(payload=b"hello"))
        self.assertIn("192.168.1.10", str(row))
        self.assertTrue(row.has_payload)

    def test_indexed_lookups(self):
        self._packet_row(tcp_packet(src="10.0.0.1", dst="10.0.0.2"))
        self.assertEqual(Packet.objects.filter(source_ip="10.0.0.1").count(), 1)
        self.assertEqual(Packet.objects.filter(protocol="TCP").count(), 1)
        self.assertEqual(Packet.objects.filter(session=self.session).count(), 1)


class DNSQueryModelTests(TestCase):
    def setUp(self):
        self.session = CaptureSession.objects.create(session_name="S", interface="eth0")

    def test_dns_query_creation_and_cascade(self):
        data = parse_packet(dns_packet(), payload_enabled=False, max_payload_bytes=256)
        packet = Packet.objects.create(
            session=self.session,
            **{k: v for k, v in data.items() if k != "dns_entries"},
        )
        for entry in data["dns_entries"]:
            DNSQuery.objects.create(packet=packet, **entry)

        self.assertEqual(DNSQuery.objects.count(), 1)
        q = DNSQuery.objects.get()
        self.assertEqual(q.query_name, "example.com")
        self.assertEqual(q.query_type, "A")

        packet.delete()
        self.assertEqual(DNSQuery.objects.count(), 0)


class NetworkInterfaceModelTests(TestCase):
    def test_unique_name_and_str(self):
        NetworkInterface.objects.create(name="eth0")
        from django.db import transaction

        with self.assertRaises(Exception):
            with transaction.atomic():
                NetworkInterface.objects.create(name="eth0")
        self.assertEqual(str(NetworkInterface.objects.get(name="eth0")), "eth0")


class ApplicationSettingModelTests(TestCase):
    def test_get_set_default(self):
        self.assertEqual(get_setting("DOES_NOT_EXIST", "fallback"), "fallback")

    def test_set_and_get(self):
        set_setting("KEY_A", "value-a", "desc")
        self.assertEqual(get_setting("KEY_A", ""), "value-a")
        row = ApplicationSetting.objects.get(key="KEY_A")
        self.assertEqual(row.description, "desc")

    def test_update_existing(self):
        set_setting("KEY_B", "1")
        set_setting("KEY_B", "2")
        self.assertEqual(ApplicationSetting.objects.filter(key="KEY_B").count(), 1)
        self.assertEqual(get_setting("KEY_B", ""), "2")
