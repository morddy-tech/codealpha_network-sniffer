"""JSON API endpoint tests."""

from __future__ import annotations

import json

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse

from capture.packet_parser import parse_packet
from sniffer.models import CaptureSession, DNSQuery, Packet
from tests.test_factories import dns_packet, tcp_packet


class ApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="apiuser", password="pass12345")
        self.session = CaptureSession.objects.create(
            session_name="API Session", interface="eth0", status="completed"
        )
        data = parse_packet(tcp_packet(payload=b"hello"), payload_enabled=True, max_payload_bytes=64)
        self.packet = Packet.objects.create(
            session=self.session,
            **{k: v for k, v in data.items() if k != "dns_entries"},
        )
        data = parse_packet(dns_packet(), payload_enabled=False, max_payload_bytes=64)
        dns_packet_row = Packet.objects.create(
            session=self.session,
            **{k: v for k, v in data.items() if k != "dns_entries"},
        )
        for entry in data["dns_entries"]:
            DNSQuery.objects.create(packet=dns_packet_row, **entry)

        self.session.refresh_statistics()
        self.client = Client()
        self.client.force_login(self.user)

    def test_api_requires_authentication(self):
        client = Client()
        for endpoint in ("api_sessions", "api_packets", "api_statistics", "api_dns", "api_interfaces"):
            response = client.get(reverse(endpoint))
            self.assertEqual(response.status_code, 401, endpoint)

    def test_api_sessions_paginated(self):
        response = self.client.get(reverse("api_sessions"))
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["results"][0]["session_name"], "API Session")

    def test_api_session_detail(self):
        response = self.client.get(reverse("api_session_detail", args=[self.session.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content)["id"], self.session.id)

    def test_api_packets(self):
        response = self.client.get(reverse("api_packets"))
        payload = json.loads(response.content)
        self.assertEqual(payload["count"], 2)
        packet = payload["results"][0]
        self.assertNotIn("payload_preview", packet)

    def test_api_packet_detail_payload_hidden_when_disabled(self):
        self.session.payload_storage_enabled = False
        self.session.save()
        response = self.client.get(reverse("api_packet_detail", args=[self.packet.id]))
        payload = json.loads(response.content)
        self.assertNotIn("payload_hex", payload)

    def test_api_packet_detail_payload_exposed_when_enabled(self):
        self.session.payload_storage_enabled = True
        self.session.save()
        response = self.client.get(reverse("api_packet_detail", args=[self.packet.id]))
        payload = json.loads(response.content)
        self.assertEqual(payload["payload_preview"], "hello")

    def test_api_statistics(self):
        response = self.client.get(reverse("api_statistics"))
        payload = json.loads(response.content)
        self.assertIn("summary", payload)
        self.assertIn("protocol_distribution", payload)
        self.assertGreaterEqual(payload["summary"]["packet_count"], 2)

    def test_api_dns(self):
        response = self.client.get(reverse("api_dns"))
        payload = json.loads(response.content)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["results"][0]["query_name"], "example.com")

    def test_api_interfaces(self):
        from sniffer.models import NetworkInterface

        NetworkInterface.objects.create(name="eth-test")
        response = self.client.get(reverse("api_interfaces"))
        payload = json.loads(response.content)
        self.assertTrue(any(i["name"] == "eth-test" for i in payload["results"]))

    def test_api_packets_filterable(self):
        response = self.client.get(reverse("api_packets"), {"protocol": "tcp"})
        payload = json.loads(response.content)
        self.assertEqual(payload["count"], 1)

    def test_api_packets_page_size_limits(self):
        response = self.client.get(reverse("api_packets"), {"page_size": "9999"})
        self.assertEqual(response.status_code, 200)

    def test_api_404(self):
        response = self.client.get(reverse("api_packet_detail", args=[99999]))
        self.assertEqual(response.status_code, 404)
