"""Dynamic network interface discovery.

Works on Windows (Npcap-friendly names) and POSIX systems.  Interface
discovery is defensive: when Scapy cannot enumerate interfaces (e.g. Npcap
is not installed) it falls back to the OS socket API.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("capture.interfaces")


@dataclass
class InterfaceInfo:
    """Immutable description of one discoverable network interface."""

    name: str
    description: str = ""
    mac_address: str = ""
    addresses: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "mac_address": self.mac_address,
            "addresses": self.addresses,
        }


def discover_interfaces() -> List[InterfaceInfo]:
    """
    Enumerate network interfaces available for packet capture.

    Order of preference:
      1. Scapy (when it can load interface data without Npcap)
      2. Windows ``ipconfig``-style friendly names via ``scapy.arch.windows``
      3. Raw OS socket enumeration (POSIX ``if_nameindex`` / Windows names)

    The caller is responsible for showing a friendly error when no
    interfaces can be found (e.g. Npcap is missing).
    """
    found = _discover_with_scapy()
    if found:
        return found
    return _discover_with_socket()


def _discover_with_scapy() -> List[InterfaceInfo]:
    """Try Scapy's interface database first."""
    try:
        from scapy.all import conf  # type: ignore[import-untyped]
    except ImportError:
        return []

    ifaces = getattr(conf, "ifaces", None)
    if ifaces is None:
        return []

    try:
        values = list(ifaces.values())
    except AttributeError:
        values = list(ifaces)

    result: List[InterfaceInfo] = []
    seen: set = set()
    for iface in values:
        name = getattr(iface, "name", "")
        if not name or name in seen:
            continue
        seen.add(name)
        mac = getattr(iface, "mac", "") or ""
        desc = getattr(iface, "description", "") or getattr(iface, "dummy", "") or ""
        ips = [
            str(ip)
            for ip in (getattr(iface, "ips", {}) or {}).get(4, [])
            if ip
        ]
        result.append(
            InterfaceInfo(name=name, description=desc or "", mac_address=mac, addresses=ips)
        )
    return result


def _discover_with_socket() -> List[InterfaceInfo]:
    """Fall back to plain OS enumeration when Scapy's table is unavailable."""
    try:
        from scapy.arch.windows import get_windows_if_list  # type: ignore[import-untyped]
    except ImportError:  # pragma: no cover
        get_windows_if_list = None

    if get_windows_if_list is not None:
        try:
            rows = get_windows_if_list()
        except Exception:  # noqa: BLE001
            rows = []
        result: List[InterfaceInfo] = []
        for row in rows:
            name = (row.get("name") or "").strip()
            if not name:
                continue
            mac = (row.get("mac") or "").strip()
            ips = [str(ip) for ip in (row.get("ips") or []) if ip]
            result.append(
                InterfaceInfo(
                    name=name,
                    description=name,
                    mac_address=mac,
                    addresses=ips,
                )
            )
        if result:
            return result

    # Raw socket fallback
    try:
        indexes = socket.if_nameindex()
    except (AttributeError, OSError):  # pragma: no cover
        return []
    return [
        InterfaceInfo(name=index_name)
        for _, index_name in indexes
    ]


def is_interface_available(name: str) -> bool:
    """Check whether a requested interface exists on this host."""
    available = {i.name for i in discover_interfaces()}
    return name in available


def refresh_interface_table() -> dict:
    """
    Sync discovered interfaces into the NetworkInterface model.

    Returns a summary dict: {"added": n, "updated": n, "total": n}.
    """
    from django.utils import timezone

    from sniffer.models import NetworkInterface

    discovered = discover_interfaces()
    now = timezone.now()
    added = updated = 0

    for info in discovered:
        existing = NetworkInterface.objects.filter(name=info.name).first()
        if existing is None:
            NetworkInterface.objects.create(
                name=info.name,
                description=info.description[:255],
                mac_address=info.mac_address[:32],
                is_active=True,
                last_seen=now,
            )
            added += 1
        else:
            changed = existing.description != info.description[:255]
            if info.mac_address and existing.mac_address != info.mac_address:
                changed = True
            existing.description = info.description[:255]
            if info.mac_address:
                existing.mac_address = info.mac_address[:32]
            existing.last_seen = now
            if changed:
                existing.save(update_fields=["description", "mac_address", "last_seen"])
            updated += 1

    logger.info("Interface refresh: %d added, %d updated", added, updated)
    return {"added": added, "updated": updated, "total": len(discovered)}
