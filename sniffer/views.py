"""View layer for the traffic analyzer.

Access model
------------
* ``/`` (landing page) is public.
* Everything else requires authentication.
* Capture controls, settings and session deletion require staff membership.
"""

from __future__ import annotations

import json
import logging
from functools import wraps
from typing import Any, Dict

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from capture.protocol_analyzer import dns_query_frequency
from core.security import ip_rate_limit
from sniffer import selectors, services
from sniffer.constants import Protocol
from sniffer.filters import filter_dns_queries, filter_packets, filter_sessions
from sniffer.forms import (
    CaptureForm,
    DNSFilterForm,
    PacketFilterForm,
    SessionFilterForm,
    SettingsForm,
)
from sniffer.models import CaptureSession, DNSQuery, Packet, payload_preview_max_bytes
from sniffer.serializers import (
    paginate,
    serialize_dns_query,
    serialize_interface,
    serialize_packet,
    serialize_session,
)
from sniffer.utils import format_bytes, format_duration

logger = logging.getLogger("sniffer.views")

_PAGE_SIZE = 25


# ---------------------------------------------------------------------------
# Public landing page
# ---------------------------------------------------------------------------
def home(request):
    """Public project landing page."""
    return render(request, "sniffer/index.html")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@login_required
def dashboard(request):
    summary = selectors.dashboard_summary()
    context = {
        "summary": summary,
        "recent_sessions": selectors.recent_sessions(),
        "recent_packets": selectors.recent_packets(),
        "top_activity": selectors.top_ip_activity(),
        "top_ports": selectors.top_ports(),
        "protocol_distribution": selectors.analytics_overview()["protocol_distribution"],
        "has_data": summary["packet_count"] > 0,
        "chart_data": _dashboard_chart_json(),
    }
    return render(request, "sniffer/dashboard.html", context)


def _dashboard_chart_json() -> Dict[str, Any]:
    """JSON payloads for dashboard charts (rendered safely via json_script)."""
    overview = selectors.analytics_overview(days=7)
    proto_counts = dict(overview["protocol_distribution"])
    summary = selectors.dashboard_summary()
    return {
        "protocol_distribution": overview["protocol_distribution"],
        "timeline": overview["timeline"],
        "packet_sizes": overview["packet_sizes"],
        "top_sources": overview["top_sources"],
        "top_destinations": overview["top_destinations"],
        "top_ports": overview["top_destination_ports"],
        "summary": {
            "tcp_count": proto_counts.get("TCP", 0),
            "udp_count": proto_counts.get("UDP", 0),
            "ipv4_count": summary["ipv4_count"],
            "ipv6_count": summary["ipv6_count"],
        },
    }


# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------
@login_required
def capture_page(request):
    if not request.user.is_staff:
        return HttpResponseForbidden(
            "Capture controls require staff authorization. Contact an administrator."
        )
    form = CaptureForm()
    status = services.application_settings()
    from capture.capture_service import CaptureController

    CaptureController.reconcile_stale()
    running = CaptureSession.objects.filter(status__in=["running", "stopping"]).first()
    return render(
        request,
        "sniffer/capture.html",
        {
            "form": form,
            "running": running,
            "payload_default": status["payload_storage_enabled"],
            "max_payload_bytes": payload_preview_max_bytes(),
        },
    )


@login_required
@require_POST
@ip_rate_limit(limit=10, window_seconds=60)
def capture_start(request):
    if not request.user.is_staff:
        return JsonResponse({"error": "Staff authorization required."}, status=403)

    if CaptureSession.objects.filter(status__in=["running", "stopping"]).exists():
        return JsonResponse(
            {"error": "A capture is already running. Stop it before starting a new one."},
            status=409,
        )

    form = CaptureForm(request.POST)
    if not form.is_valid():
        return JsonResponse({"error": form.errors.as_json()}, status=400)

    data = form.cleaned_data
    try:
        session = services.start_web_capture(
            interface=data["interface"],
            session_name=data.get("session_name") or "",
            packet_count=data.get("packet_count") or 0,
            protocol_filter=data.get("protocol") or "",
            payload_enabled=bool(data.get("payload")),
        )
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=409)
    except Exception as exc:  # noqa: BLE001 - surface any worker error
        logger.exception("Capture start failed")
        return JsonResponse({"error": f"Capture failed to start: {exc}"}, status=500)

    logger.info("Capture started by %s (session %d)", request.user.username, session.id)
    return JsonResponse(
        {"ok": True, "session_id": session.id, "url": reverse("session_detail", args=[session.id])}
    )


@login_required
@require_POST
@ip_rate_limit(limit=15, window_seconds=60)
def capture_stop(request):
    if not request.user.is_staff:
        return JsonResponse({"error": "Staff authorization required."}, status=403)

    session_id = request.POST.get("session_id")
    try:
        session_id = int(session_id)
    except (TypeError, ValueError):
        return JsonResponse({"error": "Invalid session id."}, status=400)

    try:
        snapshot = services.stop_web_capture(session_id)
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=409)

    logger.info("Capture stop requested by %s (session %d)", request.user.username, session_id)
    return JsonResponse({"ok": True, "status": snapshot["status"]})


@login_required
def capture_status(request):
    """Polling endpoint for the live capture page."""
    return JsonResponse(services.application_settings() | CaptureControllerStatus.latest())


# Small indirection so tests can override without touching services.
class CaptureControllerStatus:
    @staticmethod
    def latest() -> Dict[str, Any]:
        from capture.capture_service import CaptureController

        return CaptureController.latest_status()


# ---------------------------------------------------------------------------
# Capture sessions
# ---------------------------------------------------------------------------
@login_required
def session_list(request):
    form = SessionFilterForm(request.GET)
    queryset = CaptureSession.objects.all()
    if form.is_valid():
        queryset = filter_sessions(queryset, form)
    else:
        form = SessionFilterForm()

    paginator = Paginator(queryset, _PAGE_SIZE)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(
        request,
        "sniffer/session_list.html",
        {"form": form, "page_obj": page_obj, "total": paginator.count},
    )


@login_required
def session_detail(request, session_id: int):
    session = get_object_or_404(CaptureSession, pk=session_id)
    from capture.protocol_analyzer import protocol_distribution, traffic_over_time
    from capture.statistics import build_session_statistics

    stats = build_session_statistics(session)
    context = {
        "session": session,
        "stats": stats,
        "duration": format_duration(session.duration),
        "bytes": format_bytes(session.total_bytes),
        "protocol_distribution": protocol_distribution(session=session),
        "timeline": traffic_over_time(session, bucket_seconds=60),
        "dns_top": dns_query_frequency(session, limit=15),
        "top_ports": stats.top_destination_ports,
        "chart_data": {
            "protocols": protocol_distribution(session=session),
            "timeline": traffic_over_time(session, bucket_seconds=60),
        },
    }
    return render(request, "sniffer/session_detail.html", context)


@login_required
@require_POST
def session_delete(request, session_id: int):
    if not request.user.is_staff:
        return HttpResponseForbidden("Staff authorization required.")
    deleted = services.delete_session(session_id)
    if deleted is None:
        return JsonResponse({"error": "Session not found."}, status=404)
    logger.info("Session %d deleted by %s", session_id, request.user.username)
    messages.success(request, f"Session deleted ({deleted} packets removed).")
    return redirect("session_list")


# ---------------------------------------------------------------------------
# Packet explorer
# ---------------------------------------------------------------------------
@login_required
def packet_list(request):
    form = PacketFilterForm(request.GET)
    queryset = Packet.objects.select_related("session").all()
    if form.is_valid():
        queryset = filter_packets(queryset, form)
    else:
        form = PacketFilterForm()

    paginator = Paginator(queryset, _PAGE_SIZE)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(
        request,
        "sniffer/packet_list.html",
        {
            "form": form,
            "page_obj": page_obj,
            "total": paginator.count,
            "page_size": _PAGE_SIZE,
            "max_payload_bytes": payload_preview_max_bytes(),
        },
    )


@login_required
def packet_detail(request, packet_id: int):
    packet = get_object_or_404(
        Packet.objects.select_related("session"), pk=packet_id
    )
    dns_queries = packet.dns_queries.all()
    return render(
        request,
        "sniffer/packet_detail.html",
        {
            "packet": packet,
            "dns_queries": dns_queries,
            "payload_hex_chunks": _chunk_hex(packet.payload_hex),
            "payload_preview": packet.payload_preview,
            "max_payload_bytes": payload_preview_max_bytes(),
        },
    )


def _chunk_hex(hex_string: str, width: int = 32) -> list[str]:
    """Split a hex dump into display rows (without loading it all at once)."""
    if not hex_string:
        return []
    return [hex_string[i : i + width] for i in range(0, len(hex_string), width)]


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------
@login_required
def analytics(request):
    overview = selectors.analytics_overview(days=7)
    return render(
        request,
        "sniffer/analytics.html",
        {
            "overview": overview,
            "chart_data": {
                "protocols": overview["protocol_distribution"],
                "sizes": overview["packet_sizes"],
                "timeline": overview["timeline"],
            },
        },
    )


@login_required
def dns_analysis(request):
    form = DNSFilterForm(request.GET)
    queryset = DNSQuery.objects.select_related("packet").all()
    if form.is_valid():
        queryset = filter_dns_queries(queryset, form)
    else:
        form = DNSFilterForm()

    paginator = Paginator(queryset, _PAGE_SIZE)
    page_obj = paginator.get_page(request.GET.get("page"))

    top_names = list(
        DNSQuery.objects.values("query_name", "query_type")
        .annotate(total=Count("id"))
        .order_by("-total")[:25]
    )
    return render(
        request,
        "sniffer/dns_analysis.html",
        {
            "form": form,
            "page_obj": page_obj,
            "total": paginator.count,
            "top_names": top_names,
            "chart_data": {
                "types": list(
                    DNSQuery.objects.values_list("query_type")
                    .annotate(total=Count("id"))
                    .order_by("-total")[:8]
                )
            },
        },
    )


# ---------------------------------------------------------------------------
# Interfaces & settings
# ---------------------------------------------------------------------------
@login_required
def interface_list(request):
    from sniffer.models import NetworkInterface

    interfaces = NetworkInterface.objects.all()
    if request.GET.get("refresh") and request.user.is_staff:
        summary = services.refresh_interfaces()
        messages.success(
            request,
            f"Interface table refreshed: {summary['added']} added, {summary['updated']} updated.",
        )
        interfaces = NetworkInterface.objects.all()
        logger.info("Interface table refreshed by %s", request.user.username)
    return render(request, "sniffer/interfaces.html", {"interfaces": interfaces})


@login_required
def settings_page(request):
    if not request.user.is_staff:
        return HttpResponseForbidden("Settings require staff authorization.")

    if request.method == "POST":
        form = SettingsForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            services.update_application_settings(
                payload_enabled=bool(data["payload_storage_enabled"]),
                max_payload_bytes=data["max_payload_preview_bytes"],
                retention_days=data["retention_days"],
            )
            messages.success(request, "Settings saved.")
            return redirect("settings")
    else:
        form = SettingsForm()

    return render(
        request,
        "sniffer/settings.html",
        {"form": form, "current": services.application_settings()},
    )


# ---------------------------------------------------------------------------
# Reports (require authentication; validated session ids only)
# ---------------------------------------------------------------------------
def _get_report_session(session_id: int) -> CaptureSession:
    return get_object_or_404(CaptureSession, pk=session_id)


@login_required
def report_html(request, session_id: int):
    session = _get_report_session(session_id)
    from reports.services import report_context

    from reports.html_report import render_html as build

    body = build(report_context(session))
    response = HttpResponse(body, content_type="text/html; charset=utf-8")
    response["Content-Disposition"] = (
        f'attachment; filename="session-{session.id}-report.html"'
    )
    return response


@login_required
def report_csv(request, session_id: int):
    session = _get_report_session(session_id)
    from reports.csv_export import render_csv as build
    from reports.services import report_context

    body = build(report_context(session))
    response = HttpResponse(body, content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="session-{session.id}-report.csv"'
    return response


@login_required
def report_json(request, session_id: int):
    session = _get_report_session(session_id)
    from reports.json_export import render_json as build
    from reports.services import report_context

    body = build(report_context(session))
    response = HttpResponse(body, content_type="application/json; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="session-{session.id}-report.json"'
    return response


# ---------------------------------------------------------------------------
# Built-in JSON API (no external dependencies)
# ---------------------------------------------------------------------------
def api_login_required(view_func):
    """Require authentication, returning JSON 401 instead of a redirect."""

    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({"detail": "Authentication required."}, status=401)
        return view_func(request, *args, **kwargs)

    return wrapped


def _paginate_api(request, queryset):
    try:
        page = max(int(request.GET.get("page", 1)), 1)
        page_size = min(max(int(request.GET.get("page_size", 20)), 1), 100)
    except ValueError:
        page, page_size = 1, 20
    page_obj, total, page, pages = paginate(queryset, page, page_size)
    return page_obj, total, page, pages


@api_login_required
def api_sessions(request):
    queryset = CaptureSession.objects.all().order_by("-started_at")
    page_obj, total, page, pages = _paginate_api(request, queryset)
    return JsonResponse(
        {
            "count": total,
            "page": page,
            "total_pages": pages,
            "results": [serialize_session(s) for s in page_obj],
        }
    )


@api_login_required
def api_session_detail(request, session_id: int):
    session = get_object_or_404(CaptureSession, pk=session_id)
    return JsonResponse(serialize_session(session))


@api_login_required
def api_packets(request):
    queryset = Packet.objects.select_related("session").order_by("-timestamp")
    form = PacketFilterForm(request.GET)
    if form.is_valid():
        queryset = filter_packets(queryset, form)
    page_obj, total, page, pages = _paginate_api(request, queryset)
    return JsonResponse(
        {
            "count": total,
            "page": page,
            "total_pages": pages,
            "results": [serialize_packet(p) for p in page_obj],
        }
    )


@api_login_required
def api_packet_detail(request, packet_id: int):
    packet = get_object_or_404(Packet.objects.select_related("session"), pk=packet_id)
    include_payload = packet.session.payload_storage_enabled and packet.has_payload
    return JsonResponse(serialize_packet(packet, include_payload=include_payload))


@api_login_required
def api_statistics(request):
    summary = selectors.dashboard_summary()
    overview = selectors.analytics_overview(days=7)
    from capture.statistics import build_session_statistics

    latest = CaptureSession.objects.order_by("-started_at").first()
    latest_stats = (
        build_session_statistics(latest).as_dict() if latest is not None else {}
    )
    return JsonResponse(
        {
            "summary": summary,
            "protocol_distribution": [
                {"protocol": label, "count": count}
                for label, count in overview["protocol_distribution"]
            ],
            "latest_session": latest_stats,
        }
    )


@api_login_required
def api_dns(request):
    queryset = DNSQuery.objects.select_related("packet").order_by("-created_at")
    form = DNSFilterForm(request.GET)
    if form.is_valid():
        queryset = filter_dns_queries(queryset, form)
    page_obj, total, page, pages = _paginate_api(request, queryset)
    return JsonResponse(
        {
            "count": total,
            "page": page,
            "total_pages": pages,
            "results": [serialize_dns_query(q) for q in page_obj],
        }
    )


@api_login_required
def api_interfaces(request):
    from sniffer.models import NetworkInterface

    queryset = NetworkInterface.objects.order_by("name")
    return JsonResponse(
        {"results": [serialize_interface(i) for i in queryset]}
    )
