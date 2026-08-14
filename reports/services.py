"""Report generation services.

All exports are generated in memory (never touching the filesystem) and
include session metadata, protocol statistics, top IPs/ports, DNS activity
and passive anomaly indicators.  Payload previews are never exported.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict

from capture.statistics import build_session_statistics
from capture.protocol_analyzer import dns_query_frequency, traffic_over_time

logger = logging.getLogger("reports")


def report_context(session) -> Dict[str, Any]:
    """Assemble the full report dataset for a capture session."""
    stats = build_session_statistics(session)
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "session": {
            "id": session.id,
            "name": session.session_name,
            "interface": session.interface,
            "status": session.status,
            "started_at": session.started_at.isoformat(timespec="seconds")
            if session.started_at
            else None,
            "ended_at": session.ended_at.isoformat(timespec="seconds")
            if session.ended_at
            else None,
            "duration_seconds": round(session.duration, 1),
            "protocol_filter": session.protocol_filter,
            "payload_storage_enabled": session.payload_storage_enabled,
        },
        "statistics": stats.as_dict(),
        "protocol_distribution": [
            {"protocol": label, "count": count}
            for label, count in _protocol_distribution(session)
        ],
        "traffic_timeline": [
            {"bucket": bucket, "packets": pkts, "bytes": size}
            for bucket, pkts, size in traffic_over_time(session, bucket_seconds=60)
        ],
        "dns_top_queries": dns_query_frequency(session, limit=25),
    }


def _protocol_distribution(session):
    from capture.protocol_analyzer import protocol_distribution

    return protocol_distribution(session=session)
