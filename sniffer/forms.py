"""Django forms for the traffic analyzer."""

from __future__ import annotations

from django import forms

from capture.interface_manager import discover_interfaces
from core.validators import validate_protocol_filter
from sniffer.constants import Protocol, SessionStatus
from sniffer.models import CaptureSession, NetworkInterface, get_setting


class CaptureForm(forms.Form):
    """Form used by the Live Capture page."""

    session_name = forms.CharField(
        max_length=200,
        required=False,
        label="Capture name",
        widget=forms.TextInput(attrs={"placeholder": "e.g. Home network - morning"}),
    )
    interface = forms.ChoiceField(label="Network interface")
    packet_count = forms.IntegerField(
        required=False,
        min_value=0,
        max_value=10_000_000,
        initial=0,
        label="Packet limit (0 = until stopped)",
    )
    protocol = forms.ChoiceField(
        choices=[("", "All protocols")] + [(p, p.upper()) for p in Protocol.FILTERABLE],
        required=False,
        label="Protocol filter",
    )
    payload = forms.BooleanField(
        required=False,
        label="Store limited payload previews",
        help_text="Hex + ASCII preview of up to the configured byte limit. OFF by default.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["interface"].choices = self._interface_choices()

    @staticmethod
    def _interface_choices():
        discovered = discover_interfaces()
        if discovered:
            choices = []
            for i in discovered:
                label = i.name
                extras = [i.description or ""] + [ip for ip in i.addresses if ip]
                extras = [e for e in extras if e]
                if extras:
                    label = f"{label} — {', '.join(extras)}"
                choices.append((i.name, label))
            return choices
        stored = NetworkInterface.objects.filter(is_active=True).values_list("name", flat=True)
        return [(name, name) for name in stored] or [("", "No interfaces found")]

    def clean_interface(self) -> str:
        interface = self.cleaned_data["interface"]
        if not interface or interface == "No interfaces found":
            raise forms.ValidationError(
                "No network interfaces are available. On Windows, install Npcap and "
                "restart; on Linux/macOS, run the capture with appropriate permissions."
            )
        return interface

    def clean_protocol(self) -> str:
        value = self.cleaned_data.get("protocol", "")
        try:
            return validate_protocol_filter(value or None) or ""
        except Exception as exc:
            raise forms.ValidationError(str(exc)) from exc

    def clean(self) -> dict:
        cleaned = super().clean()
        if "interface" in self.errors:
            return cleaned
        return cleaned


class PacketFilterForm(forms.Form):
    """Search / filter form for the packet explorer."""

    q = forms.CharField(max_length=200, required=False, label="Search")
    protocol = forms.ChoiceField(
        choices=[("", "All protocols")]
        + [(p, p.upper()) for p in Protocol.FILTERABLE],
        required=False,
        label="Protocol",
    )
    session = forms.ModelChoiceField(
        queryset=CaptureSession.objects.all(), required=False, label="Session"
    )
    source_ip = forms.CharField(max_length=45, required=False, label="Source IP")
    destination_ip = forms.CharField(max_length=45, required=False, label="Destination IP")
    port = forms.IntegerField(min_value=0, max_value=65535, required=False, label="Port")
    date_from = forms.DateField(required=False, widget=forms.DateInput(attrs={"type": "date"}), label="From")
    date_to = forms.DateField(required=False, widget=forms.DateInput(attrs={"type": "date"}), label="To")


class SessionFilterForm(forms.Form):
    """Filter for the capture session list."""

    q = forms.CharField(max_length=200, required=False, label="Search sessions")
    status = forms.ChoiceField(
        choices=[("", "All statuses")] + SessionStatus.CHOICES,
        required=False,
        label="Status",
    )


class DNSFilterForm(forms.Form):
    """Filter for the DNS analysis page."""

    q = forms.CharField(max_length=255, required=False, label="Search query names")
    query_type = forms.ChoiceField(
        choices=[("", "All types")] + [("A", "A"), ("AAAA", "AAAA"), ("MX", "MX"), ("TXT", "TXT"), ("CNAME", "CNAME"), ("NS", "NS"), ("PTR", "PTR")],
        required=False,
        label="Type",
    )


class SettingsForm(forms.Form):
    """Administrator settings form (payload storage + retention)."""

    payload_storage_enabled = forms.BooleanField(required=False, label="Store limited payload previews")
    max_payload_preview_bytes = forms.IntegerField(
        min_value=8, max_value=4096, initial=256, label="Max payload preview bytes"
    )
    retention_days = forms.IntegerField(
        min_value=1, max_value=3650, initial=30, label="Default retention (days)"
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from sniffer.models import payload_preview_max_bytes

        current = get_setting("PAYLOAD_STORAGE_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
        self.fields["payload_storage_enabled"].initial = current
        self.fields["max_payload_preview_bytes"].initial = payload_preview_max_bytes()
        self.fields["retention_days"].initial = int(get_setting("DEFAULT_RETENTION_DAYS", "30") or 30)
