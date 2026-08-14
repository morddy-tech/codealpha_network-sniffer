"""Django admin configuration for the sniffer models."""

from __future__ import annotations

from django.contrib import admin

from .models import (
    ApplicationSetting,
    CaptureSession,
    DNSQuery,
    NetworkInterface,
    Packet,
)


@admin.register(CaptureSession)
class CaptureSessionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "session_name",
        "interface",
        "status",
        "packet_count",
        "total_bytes",
        "started_at",
        "ended_at",
    )
    list_filter = ("status", "protocol_filter", "payload_storage_enabled", "started_at")
    search_fields = ("session_name", "interface", "error_message")
    readonly_fields = (
        "started_at",
        "created_at",
        "ended_at",
    )
    date_hierarchy = "started_at"
    actions = ["delete_selected_sessions"]

    fieldsets = (
        (None, {"fields": ("session_name", "interface", "status", "protocol_filter")}),
        (
            "Capture options",
            {
                "fields": (
                    "requested_packet_count",
                    "payload_storage_enabled",
                )
            },
        ),
        (
            "Statistics",
            {
                "fields": (
                    "packet_count",
                    "total_bytes",
                    "tcp_count",
                    "udp_count",
                    "icmp_count",
                    "dns_count",
                    "arp_count",
                    "ipv4_count",
                    "ipv6_count",
                )
            },
        ),
        (
            "Timing",
            {"fields": ("started_at", "ended_at", "created_at")},
        ),
        ("Errors", {"fields": ("error_message",), "classes": ("collapse",)}),
    )

    @admin.action(description="Delete selected sessions and their packets")
    def delete_selected_sessions(self, request, queryset):  # pragma: no cover
        deleted = 0
        for session in queryset:
            deleted += session.packets.count()
        deleted_pk = list(queryset.values_list("id", flat=True))
        queryset.delete()
        self.message_user(
            request,
            f"Deleted {len(deleted_pk)} session(s) and {deleted} packet row(s).",
        )


@admin.register(Packet)
class PacketAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "session",
        "timestamp",
        "protocol",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "packet_length",
    )
    list_filter = ("protocol", "transport_protocol", "is_ipv4", "is_ipv6")
    search_fields = ("source_ip", "destination_ip", "protocol")
    date_hierarchy = "timestamp"
    ordering = ("-timestamp",)
    list_select_related = ("session",)

    # Payload previews are intentionally NOT shown in the admin list view.
    fieldsets = (
        (None, {"fields": ("session", "timestamp")}),
        (
            "Addressing",
            {
                "fields": (
                    "source_ip",
                    "destination_ip",
                    "source_port",
                    "destination_port",
                )
            },
        ),
        (
            "Protocol information",
            {
                "fields": (
                    "protocol",
                    "transport_protocol",
                    "packet_length",
                    "ttl",
                    "tcp_flags",
                    "icmp_type",
                    "icmp_code",
                )
            },
        ),
        (
            "Version flags",
            {"fields": ("is_ipv4", "is_ipv6")},
        ),
        (
            "Payload preview (limited diagnostic data)",
            {
                "fields": (
                    "payload_length",
                    "payload_preview",
                    "payload_hex",
                ),
                "classes": ("collapse",),
            },
        ),
    )
    readonly_fields = [f.name for f in Packet._meta.fields]


@admin.register(DNSQuery)
class DNSQueryAdmin(admin.ModelAdmin):
    list_display = ("query_name", "query_type", "response_code", "packet", "created_at")
    list_filter = ("query_type", "response_code")
    search_fields = ("query_name",)
    date_hierarchy = "created_at"
    list_select_related = ("packet",)


@admin.register(NetworkInterface)
class NetworkInterfaceAdmin(admin.ModelAdmin):
    list_display = ("name", "description", "mac_address", "is_active", "last_seen")
    list_filter = ("is_active",)
    search_fields = ("name", "mac_address")
    readonly_fields = ("created_at",)


@admin.register(ApplicationSetting)
class ApplicationSettingAdmin(admin.ModelAdmin):
    list_display = ("key", "value", "updated_at")
    search_fields = ("key", "description")
    readonly_fields = ("updated_at",)
