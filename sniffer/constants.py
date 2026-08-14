"""Constant definitions shared across the application."""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Capture session lifecycle states
# ---------------------------------------------------------------------------
class SessionStatus:
    """Lifecycle states for a capture session (mirrors the UI status pill)."""

    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"

    CHOICES = [
        (RUNNING, "Capturing"),
        (STOPPING, "Stopping"),
        (COMPLETED, "Completed"),
        (FAILED, "Failed"),
    ]


# ---------------------------------------------------------------------------
# Protocol labels used for filtering and display
# ---------------------------------------------------------------------------
class Protocol:
    """Protocol labels recognised by the packet parser."""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ICMPV6 = "ICMPv6"
    ARP = "ARP"
    IP = "IP"
    IPV6 = "IPv6"
    DNS = "DNS"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"

    # Protocols displayed in filter dropdowns / charts.
    FILTERABLE = ["tcp", "udp", "icmp", "icmpv6", "arp", "ipv4", "ipv6", "dns"]

    TRANSPORT_LABELS = {
        "tcp": TCP,
        "udp": UDP,
        "icmp": ICMP,
        "icmpv6": ICMPV6,
    }


# ---------------------------------------------------------------------------
# TCP flag bit mapping (order matches the conventional Wireshark-style
# flag display: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)
# ---------------------------------------------------------------------------
TCP_FLAG_BITS = [
    (0x01, "F"),
    (0x02, "S"),
    (0x04, "R"),
    (0x08, "P"),
    (0x10, "A"),
    (0x20, "U"),
    (0x40, "E"),
    (0x80, "C"),
]


def tcp_flags_to_string(flags_value: int) -> str:
    """Convert a numeric TCP flags value to a compact string, e.g. ``SA``."""
    if not flags_value:
        return ""
    return "".join(letter for bit, letter in TCP_FLAG_BITS if flags_value & bit)


# ---------------------------------------------------------------------------
# DNS query type numbers -> human readable labels
# ---------------------------------------------------------------------------
DNS_QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    17: "RP",
    18: "AFSDB",
    24: "SIG",
    25: "KEY",
    28: "AAAA",
    29: "LOC",
    33: "SRV",
    35: "NAPTR",
    36: "KX",
    37: "CERT",
    39: "DNAME",
    41: "OPT",
    43: "DS",
    44: "SSHFP",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    49: "NSEC3",
    50: "NSEC3PARAM",
    52: "TLSA",
    59: "CDS",
    60: "CDNSKEY",
    62: "CSYNC",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    255: "ANY",
}


def dns_qtype_label(qtype: int | None) -> str:
    """Map a numeric DNS query type to its canonical label."""
    if qtype is None:
        return "UNKNOWN"
    return DNS_QTYPES.get(qtype, str(qtype))


# ---------------------------------------------------------------------------
# DNS response codes -> names
# ---------------------------------------------------------------------------
DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    9: "NOTAUTH",
}


def dns_rcode_label(rcode: int | None) -> str:
    """Map a numeric DNS response code to its canonical name."""
    if rcode is None:
        return ""
    return DNS_RCODES.get(rcode, str(rcode))


# ---------------------------------------------------------------------------
# Application setting keys
# ---------------------------------------------------------------------------
SETTING_PAYLOAD_STORAGE_ENABLED = "PAYLOAD_STORAGE_ENABLED"
SETTING_MAX_PAYLOAD_PREVIEW_BYTES = "MAX_PAYLOAD_PREVIEW_BYTES"
SETTING_DEFAULT_RETENTION_DAYS = "DEFAULT_RETENTION_DAYS"

SETTINGS_REGISTRY = {
    SETTING_PAYLOAD_STORAGE_ENABLED: (
        "Store limited payload previews (hex + ASCII) for captured packets",
        "false",
    ),
    SETTING_MAX_PAYLOAD_PREVIEW_BYTES: (
        "Maximum payload bytes stored per packet preview (8-4096)",
        "256",
    ),
    SETTING_DEFAULT_RETENTION_DAYS: (
        "Default packet retention period in days",
        "30",
    ),
}
