"""Input validation helpers shared across the application."""

from __future__ import annotations

import ipaddress
import re

from django.core.exceptions import ValidationError

_PROTOCOL_LABELS = {"tcp", "udp", "icmp", "icmpv6", "arp", "ipv4", "ipv6", "dns"}
_INTERFACE_NAME_RE = re.compile(r"^[A-Za-z0-9._\- ]{1,128}$")
_DNS_NAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-_]{0,62}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9](?:[A-Za-z0-9\-_]{0,62}[A-Za-z0-9])?)*\.?$"
)


def validate_interface_name(value: str) -> str:
    """Validate a network interface name (OS friendly names are allowed)."""
    value = value.strip()
    if not value:
        raise ValidationError("Interface name is required.")
    if len(value) > 128:
        raise ValidationError("Interface name is too long (max 128 chars).")
    if not _INTERFACE_NAME_RE.match(value):
        raise ValidationError(
            "Interface name contains unsupported characters "
            "(letters, digits, spaces, dots, dashes and underscores only)."
        )
    return value


def validate_protocol_filter(value: str | None) -> str | None:
    """Validate an optional protocol filter label."""
    if value is None:
        return None
    value = value.strip().lower()
    if not value:
        return None
    if value not in _PROTOCOL_LABELS:
        raise ValidationError(
            f"Unsupported protocol filter '{value}'. "
            f"Supported: {', '.join(sorted(_PROTOCOL_LABELS))}."
        )
    return value


def validate_ip(value: str) -> bool:
    """Return True if the value parses as an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def validate_port(value: int) -> bool:
    return 0 <= int(value) <= 65535


def validate_dns_query_name(value: str) -> bool:
    """Heuristic validation for DNS query names."""
    value = value.rstrip(".")
    return bool(_DNS_NAME_RE.match(value))
