"""CSV report export (in-memory, UTF-8 with BOM for Excel compatibility)."""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, List


def _write_section(writer, title: str) -> None:
    writer.writerow([])
    writer.writerow([title])
    writer.writerow([])


def render_csv(context: Dict[str, Any]) -> str:
    """Render a CSV string from a report context."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    session = context["session"]
    stats = context["statistics"]

    writer.writerow(["CodeAlpha Advanced Network Traffic Analyzer - Session Report"])
    writer.writerow(["Generated", context["generated_at"]])

    _write_section(writer, "Session")
    for key, value in session.items():
        writer.writerow([key.replace("_", " ").capitalize(), value])

    _write_section(writer, "Statistics")
    writer.writerow(["Metric", "Value"])
    for key, value in stats.items():
        if key.startswith("top_") or key == "anomalies":
            continue
        writer.writerow([key.replace("_", " ").capitalize(), value])

    _write_section(writer, "Top source IPs")
    writer.writerow(["IP", "Packets"])
    for ip, total in stats["top_sources"]:
        writer.writerow([ip, total])

    _write_section(writer, "Top destination IPs")
    writer.writerow(["IP", "Packets"])
    for ip, total in stats["top_destinations"]:
        writer.writerow([ip, total])

    _write_section(writer, "Top destination ports")
    writer.writerow(["Port", "Packets"])
    for port, total in stats["top_destination_ports"]:
        writer.writerow([port, total])

    _write_section(writer, "Protocol distribution")
    writer.writerow(["Protocol", "Packets"])
    for row in context["protocol_distribution"]:
        writer.writerow([row["protocol"], row["count"]])

    _write_section(writer, "DNS top queries")
    writer.writerow(["Query", "Type", "Count"])
    for row in context["dns_top_queries"]:
        writer.writerow([row["query_name"], row["query_type"], row["total"]])

    if stats["anomalies"]:
        _write_section(writer, "Potential anomaly indicators (passive heuristics)")
        writer.writerow(["Severity", "Title", "Description"])
        for indicator in stats["anomalies"]:
            writer.writerow([indicator["severity"], indicator["title"], indicator["description"]])

    # BOM so Excel renders UTF-8 correctly.
    return "\ufeff" + buffer.getvalue()
