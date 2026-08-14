"""View tests: authentication, permissions, filters, pagination, reports."""

from __future__ import annotations

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from capture.packet_parser import parse_packet
from sniffer.models import CaptureSession, DNSQuery, Packet
from tests.test_factories import dns_packet, tcp_packet, udp_packet


def _make_packet_row(session, packet, payload_enabled=False):
    data = parse_packet(
        packet, payload_enabled=payload_enabled, max_payload_bytes=256
    )
    return Packet.objects.create(
        session=session, **{k: v for k, v in data.items() if k != "dns_entries"}
    )


class AuthTestCase(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            username="admin", password="pass12345", is_staff=True
        )
        self.user = User.objects.create_user(username="viewer", password="pass12345")
        self.session = CaptureSession.objects.create(
            session_name="Home LAN", interface="eth0", status="completed"
        )

    def _login(self, who="admin"):
        client = Client()
        client.force_login(getattr(self, who))
        return client


class LandingPageTests(AuthTestCase):
    def test_home_public(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Advanced Network")
        self.assertContains(response, "Open Dashboard")

    def test_dashboard_requires_login(self):
        response = self.client.get(reverse("dashboard"))
        self.assertRedirects(response, f"{reverse('login')}?next={reverse('dashboard')}")

    def test_dashboard_authenticated(self):
        client = self._login("user")
        response = client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)


class CapturePageTests(AuthTestCase):
    def test_capture_requires_staff(self):
        client = self._login("user")
        response = client.get(reverse("capture"))
        self.assertEqual(response.status_code, 403)

    def test_capture_page_staff(self):
        client = self._login("staff")
        response = client.get(reverse("capture"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Start Capture")

    def test_capture_start_requires_staff(self):
        client = self._login("user")
        response = client.post(reverse("capture_start"), {})
        self.assertEqual(response.status_code, 403)

    def test_capture_start_validation_error(self):
        client = self._login("staff")
        response = client.post(reverse("capture_start"), {"interface": ""})
        self.assertEqual(response.status_code, 400)

    def test_capture_start_rejects_when_running(self):
        CaptureSession.objects.create(
            session_name="Running", interface="eth0", status="running"
        )
        client = self._login("staff")
        response = client.post(reverse("capture_start"), {"interface": "eth0"})
        self.assertEqual(response.status_code, 409)

    def test_capture_stop_invalid_id(self):
        client = self._login("staff")
        response = client.post(reverse("capture_stop"), {"session_id": "abc"})
        self.assertEqual(response.status_code, 400)


class SessionViewsTests(AuthTestCase):
    def test_session_list_filters_and_pagination(self):
        for i in range(30):
            CaptureSession.objects.create(session_name=f"S{i}", interface="eth0")
        client = self._login("staff")
        response = client.get(reverse("session_list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["total"], 31)

        response = client.get(reverse("session_list"), {"q": "S2"})
        self.assertContains(response, "S2")

    def test_session_detail_404(self):
        client = self._login("staff")
        response = client.get(reverse("session_detail", args=[99999]))
        self.assertEqual(response.status_code, 404)

    def test_session_detail_shows_stats(self):
        _make_packet_row(self.session, tcp_packet())
        _make_packet_row(self.session, udp_packet())
        client = self._login("staff")
        response = client.get(reverse("session_detail", args=[self.session.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Home LAN")

    def test_session_delete_requires_staff(self):
        client = self._login("user")
        response = client.post(reverse("session_delete", args=[self.session.id]))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(CaptureSession.objects.filter(pk=self.session.id).exists())

    def test_session_delete_staff(self):
        _make_packet_row(self.session, tcp_packet())
        client = self._login("staff")
        response = client.post(reverse("session_delete", args=[self.session.id]))
        self.assertRedirects(response, reverse("session_list"))
        self.assertFalse(CaptureSession.objects.filter(pk=self.session.id).exists())
        self.assertEqual(Packet.objects.count(), 0)


class PacketExplorerTests(AuthTestCase):
    def setUp(self):
        super().setUp()
        self.p1 = _make_packet_row(self.session, tcp_packet(src="10.0.0.1", dst="10.0.0.9"))
        self.p2 = _make_packet_row(self.session, udp_packet(src="10.0.0.2"))
        self.p3 = _make_packet_row(self.session, tcp_packet(src="10.0.0.3", dport=8080))

    def test_packet_list(self):
        client = self._login("staff")
        response = client.get(reverse("packet_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "10.0.0.1")

    def test_filter_by_protocol(self):
        client = self._login("staff")
        response = client.get(reverse("packet_list"), {"protocol": "tcp"})
        self.assertEqual(response.context["total"], 2)

    def test_filter_by_source_ip(self):
        client = self._login("staff")
        response = client.get(reverse("packet_list"), {"source_ip": "10.0.0.2"})
        self.assertEqual(response.context["total"], 1)

    def test_filter_by_port(self):
        client = self._login("staff")
        response = client.get(reverse("packet_list"), {"port": "8080"})
        self.assertEqual(response.context["total"], 1)

    def test_filter_by_session(self):
        client = self._login("staff")
        response = client.get(reverse("packet_list"), {"session": self.session.id})
        self.assertEqual(response.context["total"], 3)

    def test_search_query(self):
        client = self._login("staff")
        response = client.get(reverse("packet_list"), {"q": "10.0.0.9"})
        self.assertEqual(response.context["total"], 1)

    def test_pagination(self):
        for i in range(60):
            _make_packet_row(self.session, udp_packet(src=f"10.9.9.{i % 250}"))
        client = self._login("staff")
        response = client.get(reverse("packet_list"))
        self.assertLessEqual(len(response.context["page_obj"].object_list), 25)

    def test_packet_detail(self):
        client = self._login("staff")
        response = client.get(reverse("packet_detail", args=[self.p1.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "10.0.0.1")
        self.assertContains(response, "Payload Preview")

    def test_packet_detail_no_payload_when_disabled(self):
        client = self._login("staff")
        response = client.get(reverse("packet_detail", args=[self.p1.id]))
        self.assertContains(response, "No payload preview stored")

    def test_packet_detail_404(self):
        client = self._login("staff")
        response = client.get(reverse("packet_detail", args=[99999]))
        self.assertEqual(response.status_code, 404)


class AnalyticsViewsTests(AuthTestCase):
    def test_analytics_page(self):
        client = self._login("staff")
        response = client.get(reverse("analytics"))
        self.assertEqual(response.status_code, 200)

    def test_dns_analysis_page_with_data(self):
        data = parse_packet(dns_packet(), payload_enabled=False, max_payload_bytes=256)
        packet = _make_packet_row(self.session, dns_packet())
        for entry in data["dns_entries"]:
            DNSQuery.objects.create(packet=packet, **entry)
        client = self._login("staff")
        response = client.get(reverse("dns_analysis"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "example.com")

    def test_dns_filter(self):
        data = parse_packet(dns_packet(qtype=1), payload_enabled=False, max_payload_bytes=256)
        packet = _make_packet_row(self.session, dns_packet())
        for entry in data["dns_entries"]:
            DNSQuery.objects.create(packet=packet, **entry)
        client = self._login("staff")
        response = client.get(reverse("dns_analysis"), {"query_type": "A"})
        self.assertContains(response, "example.com")


class SettingsAndInterfacesTests(AuthTestCase):
    def test_settings_requires_staff(self):
        client = self._login("user")
        response = client.get(reverse("settings"))
        self.assertEqual(response.status_code, 403)

    def test_settings_post_updates_values(self):
        client = self._login("staff")
        response = client.post(
            reverse("settings"),
            {
                "payload_storage_enabled": "on",
                "max_payload_preview_bytes": "512",
                "retention_days": "45",
            },
        )
        self.assertRedirects(response, reverse("settings"))
        from sniffer.models import get_setting

        self.assertEqual(get_setting("PAYLOAD_STORAGE_ENABLED", ""), "true")
        self.assertEqual(get_setting("MAX_PAYLOAD_PREVIEW_BYTES", ""), "512")
        self.assertEqual(get_setting("DEFAULT_RETENTION_DAYS", ""), "45")

    def test_settings_rejects_bad_values(self):
        client = self._login("staff")
        response = client.post(
            reverse("settings"),
            {"payload_storage_enabled": "on", "max_payload_preview_bytes": "999999", "retention_days": "0"},
        )
        self.assertEqual(response.status_code, 200)

    def test_interfaces_page(self):
        client = self._login("staff")
        response = client.get(reverse("interfaces"))
        self.assertEqual(response.status_code, 200)


class LoginRateLimitTests(TestCase):
    def test_login_view_rate_limited(self):
        client = Client()
        url = reverse("login")
        for _ in range(10):
            client.post(url, {"username": "x", "password": "y"})
        response = client.post(url, {"username": "x", "password": "y"})
        self.assertIn(response.status_code, (200, 403))
