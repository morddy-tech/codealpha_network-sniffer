"""URL routing for the sniffer application."""

from __future__ import annotations

from django.urls import path

from . import views

urlpatterns = [
    # Landing / dashboard
    path("", views.home, name="home"),
    path("dashboard/", views.dashboard, name="dashboard"),

    # Live capture
    path("capture/", views.capture_page, name="capture"),
    path("capture/start/", views.capture_start, name="capture_start"),
    path("capture/stop/", views.capture_stop, name="capture_stop"),
    path("capture/status/", views.capture_status, name="capture_status"),

    # Sessions
    path("sessions/", views.session_list, name="session_list"),
    path("sessions/<int:session_id>/", views.session_detail, name="session_detail"),
    path("sessions/<int:session_id>/delete/", views.session_delete, name="session_delete"),

    # Packet explorer
    path("packets/", views.packet_list, name="packet_list"),
    path("packets/<int:packet_id>/", views.packet_detail, name="packet_detail"),

    # Analytics
    path("analytics/", views.analytics, name="analytics"),
    path("analytics/dns/", views.dns_analysis, name="dns_analysis"),

    # Interfaces & settings
    path("interfaces/", views.interface_list, name="interfaces"),
    path("settings/", views.settings_page, name="settings"),

    # Reports
    path("reports/session/<int:session_id>/html/", views.report_html, name="report_html"),
    path("reports/session/<int:session_id>/csv/", views.report_csv, name="report_csv"),
    path("reports/session/<int:session_id>/json/", views.report_json, name="report_json"),

    # Built-in JSON API
    path("api/sessions/", views.api_sessions, name="api_sessions"),
    path("api/sessions/<int:session_id>/", views.api_session_detail, name="api_session_detail"),
    path("api/packets/", views.api_packets, name="api_packets"),
    path("api/packets/<int:packet_id>/", views.api_packet_detail, name="api_packet_detail"),
    path("api/statistics/", views.api_statistics, name="api_statistics"),
    path("api/dns/", views.api_dns, name="api_dns"),
    path("api/interfaces/", views.api_interfaces, name="api_interfaces"),
]
