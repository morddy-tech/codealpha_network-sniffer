"""Capture controller lifecycle tests using injected in-memory packets.

No packet is ever transmitted onto a real network: the packet source is a
plain Python iterator of factory-built Scapy packets.

``TransactionTestCase`` is used because the capture worker writes from a
background thread; transactional ``TestCase`` would hold DB locks that the
worker thread cannot obtain.
"""

from __future__ import annotations

import time
from unittest import mock

from django.test import TransactionTestCase

from capture.capture_service import CaptureController
from sniffer.constants import SessionStatus
from sniffer.models import CaptureSession, DNSQuery, Packet
from tests.test_factories import dns_packet, tcp_packet, udp_packet


class CaptureControllerTests(TransactionTestCase):
    reset_sequences = True
    def _session(self, payload_enabled=False, **kwargs):
        return CaptureSession.objects.create(
            session_name=kwargs.pop("session_name", "Test capture"),
            interface="test0",
            status=SessionStatus.RUNNING,
            payload_storage_enabled=payload_enabled,
            **kwargs,
        )

    def _source(self, packets):
        return lambda: packets

    def _run_and_wait(self, handle, timeout=15):
        thread = handle.thread
        deadline = time.monotonic() + timeout
        while thread is not None and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        handle.ended_at = None
        return handle

    def test_capture_with_injected_packets_stores_rows(self):
        session = self._session()
        handle = CaptureController.start(session, count=0, packet_source=self._source([tcp_packet(), udp_packet()]))
        self._run_and_wait(handle)

        self.assertEqual(Packet.objects.count(), 2)
        session.refresh_from_db()
        self.assertEqual(session.status, SessionStatus.COMPLETED)
        self.assertEqual(session.packet_count, 2)
        self.assertEqual(session.tcp_count, 1)
        self.assertEqual(session.udp_count, 1)
        self.assertIsNotNone(session.ended_at)

    def test_count_limit_stops_capture(self):
        session = self._session()
        packets = [tcp_packet() for _ in range(50)]
        handle = CaptureController.start(session, count=10, packet_source=self._source(packets))
        self._run_and_wait(handle)
        session.refresh_from_db()
        self.assertEqual(session.packet_count, 10)

    def test_dns_entries_persisted(self):
        session = self._session()
        handle = CaptureController.start(session, count=0, packet_source=self._source([dns_packet()]))
        self._run_and_wait(handle)
        self.assertEqual(DNSQuery.objects.count(), 1)
        self.assertEqual(DNSQuery.objects.get().query_name, "example.com")
        session.refresh_from_db()
        self.assertEqual(session.dns_count, 1)

    def test_payload_storage_respected(self):
        session = self._session(payload_enabled=True)
        handle = CaptureController.start(session, count=0, packet_source=self._source([tcp_packet(payload=b"hello-world")]))
        self._run_and_wait(handle)
        packet = Packet.objects.get()
        self.assertEqual(packet.payload_preview, "hello-world")
        self.assertEqual(packet.payload_hex, b"hello-world".hex(" "))

    def test_payload_off_by_default(self):
        session = self._session()
        handle = CaptureController.start(session, count=0, packet_source=self._source([tcp_packet(payload=b"secret")]))
        self._run_and_wait(handle)
        packet = Packet.objects.get()
        self.assertEqual(packet.payload_preview, "")
        self.assertEqual(packet.payload_hex, "")
        self.assertEqual(packet.payload_length, 6)

    def test_malformed_source_does_not_kill_capture(self):
        from tests.test_factories import malformed_packet

        session = self._session()
        handle = CaptureController.start(
            session, count=0, packet_source=self._source([malformed_packet(), tcp_packet()])
        )
        self._run_and_wait(handle)
        session.refresh_from_db()
        self.assertEqual(session.status, SessionStatus.COMPLETED)
        # Garbage packets are handled defensively and stored as metadata;
        # they must never terminate the capture.
        self.assertEqual(Packet.objects.count(), 2)

    def test_worker_failure_marks_session_failed(self):
        session = self._session()
        with mock.patch("capture.capture_service._import_sniff", return_value=None):
            handle = CaptureController.start(session, count=0, packet_source=None)
            self._run_and_wait(handle)
        session.refresh_from_db()
        self.assertEqual(session.status, SessionStatus.FAILED)
        self.assertIn("Scapy", session.error_message)

    def test_duplicate_start_rejected(self):
        session = self._session()
        handle = CaptureController.start(session, count=0, packet_source=self._source([tcp_packet()]))
        with self.assertRaises(ValueError):
            CaptureController.start(session, count=0, packet_source=self._source([tcp_packet()]))
        self._run_and_wait(handle)

    def test_stop_requests_graceful_stop(self):
        session = self._session()
        handle = CaptureController.start(session, count=0, packet_source=self._source([tcp_packet()]))
        stopped = CaptureController.stop(session.id)
        self.assertEqual(stopped.snapshot()["status"], SessionStatus.STOPPING)
        self._run_and_wait(handle)
        session.refresh_from_db()
        self.assertEqual(session.status, SessionStatus.COMPLETED)

    def test_stop_terminates_unlimited_capture(self):
        """A stop request must halt an endless capture (regression test)."""

        def endless_source():
            while True:
                yield tcp_packet()

        session = self._session()
        handle = CaptureController.start(session, count=0, packet_source=endless_source)
        time.sleep(0.3)
        self.assertTrue(handle.thread.is_alive())

        CaptureController.stop(session.id)
        self._run_and_wait(handle)

        session.refresh_from_db()
        self.assertEqual(session.status, SessionStatus.COMPLETED)
        self.assertGreater(session.packet_count, 0)

    def test_stop_unknown_session_raises(self):
        with self.assertRaises(ValueError):
            CaptureController.stop(99999)

    def test_status_falls_back_to_database(self):
        session = self._session()
        snapshot = CaptureController.status(session.id)
        self.assertEqual(snapshot["session_id"], session.id)
        self.assertIn("status", snapshot)

    def test_latest_status_idle(self):
        self.assertEqual(CaptureController.latest_status()["status"], "idle")

    def test_handle_registry_cleanup_after_finish(self):
        from capture.capture_service import handle_for_session

        session = self._session()
        handle = CaptureController.start(session, count=0, packet_source=self._source([tcp_packet()]))
        self._run_and_wait(handle)
        self.assertIsNone(handle_for_session(session.id))
