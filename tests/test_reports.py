"""Report generation and export tests."""

from __future__ import annotations

import csv
import io
import json

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse

from capture.packet_parser import parse_packet
from sniffer.models import CaptureSession, DNSQuery, Packet
from tests.test_factories import dns_packet, tcp_packet, udp_packet


class ReportTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="viewer", password="pass12345")
        self.session = CaptureSession.objects.create(
            session_name="Report Session",
            interface="eth0",
            status="completed",
        )

        def add(packet):
            data = parse_packet(packet, payload_enabled=False, max_payload_bytes=256)
            row = Packet.objects.create(
                session=self.session,
                **{k: v for k, v in data.items() if k != "dns_entries"},
            )
            for entry in data["dns_entries"]:
                DNSQuery.objects.create(packet=row, **entry)

        add(tcp_packet())
        add(udp_packet())
        add(dns_packet())

        self.session.refresh_statistics()
        self.client = Client()
        self.client.force_login(self.user)

    def test_report_context_shape(self):
        from reports.services import report_context

        context = report_context(self.session)
        self.assertEqual(context["session"]["id"], self.session.id)
        self.assertIn("statistics", context)
        self.assertIn("protocol_distribution", context)
        self.assertIn("traffic_timeline", context)
        self.assertIn("dns_top_queries", context)
        self.assertGreater(context["statistics"]["packet_count"], 0)

    def test_csv_export_content(self):
        response = self.client.get(reverse("report_csv", args=[self.session.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"].split(";")[0], "text/csv")
        self.assertIn("attachment", response["Content-Disposition"])

        reader = csv.reader(io.StringIO(response.content.decode("utf-8-sig")))
        rows = [row for row in reader]
        joined = " ".join(" ".join(row) for row in rows)
        self.assertIn("Report Session", joined)
        self.assertIn("TCP", joined)

    def test_json_export_content(self):
        response = self.client.get(reverse("report_json", args=[self.session.id]))
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertEqual(payload["session"]["name"], "Report Session")
        self.assertGreaterEqual(payload["statistics"]["packet_count"], 3)

    def test_html_export_content(self):
        response = self.client.get(reverse("report_html", args=[self.session.id]))
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response["Content-Type"])
        self.assertIn("Report Session", response.content.decode())
        self.assertIn("Traffic Statistics", response.content.decode())

    def test_reports_require_login(self):
        client = Client()
        for name in ("report_html", "report_csv", "report_json"):
            response = client.get(reverse(name, args=[self.session.id]))
            self.assertEqual(response.status_code, 302, name)

    def test_reports_404_for_invalid_session(self):
        for name in ("report_html", "report_csv", "report_json"):
            response = self.client.get(reverse(name, args=[99999]))
            self.assertEqual(response.status_code, 404, name)

    def test_no_payload_in_exports(self):
        response = self.client.get(reverse("report_json", args=[self.session.id]))
        payload = json.loads(response.content)
        for section in payload.values():
            self.assertNotIn("payload_hex", str(section))
            self.assertNotIn("payload_preview", str(section))
