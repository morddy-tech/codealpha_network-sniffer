# Project Report — CodeAlpha Advanced Network Traffic Analyzer

**Internship:** CodeAlpha — Cybersecurity Internship
**Task:** Task 1 — Basic Network Sniffer
**Repository:** `codealpha_network-sniffer`
**Author:** Ifedayo Matthew

---

## 1. Introduction

The CodeAlpha Advanced Network Traffic Analyzer is a complete, production-quality
passive network monitoring platform built as the Task 1 deliverable of the CodeAlpha
cybersecurity internship. It captures live traffic from an authorized network
interface, extracts protocol metadata using Scapy, stores sanitized records in a
Django ORM database, and presents a professional security-operations-center (SOC)
style dashboard with analytics, packet exploration, DNS analysis, reporting and
passive anomaly indicators.

The project intentionally goes beyond a "tutorial Scapy script" and demonstrates
industry-grade concerns: separation of concerns between capture and web serving,
secure software architecture, privacy-by-design data handling, comprehensive
testing, documentation and responsible ethical boundaries.

## 2. Background

Network monitoring is a core capability of every security operations team. Passive
packet capture and metadata analysis are the foundation of network visibility:
they enable capacity planning, protocol behavior analysis, DNS activity auditing,
anomaly detection and incident investigation — without touching application-layer
payloads.

Most introductory sniffer tutorials simply print packets to the console. This
project demonstrates how such an engine should be productized: persistent storage,
queryable analytics, dashboards, exports, permissions and safe data handling.

## 3. Problem Statement

Internship task: build a "basic network sniffer". The naive interpretation — a
console script that prints Scapy packets — does not demonstrate real-world
engineering skills. The actual problem is:

1. How to capture live traffic without blocking or destabilizing an application.
2. How to extract protocol metadata defensively (packets are untrusted input).
3. How to store and query potentially sensitive network data safely.
4. How to present the data to human analysts through a usable interface.
5. How to do all of this with a secure, testable, maintainable architecture.

## 4. Objectives

- Capture packets from a user-selected network interface with configurable count,
  timeout and protocol filters.
- Parse IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ARP and DNS metadata.
- Persist sanitized metadata with strict payload privacy limits.
- Provide a professional dashboard with charts, metrics and capture status.
- Provide a searchable, filterable, paginated packet explorer.
- Provide DNS analysis, traffic analytics and passive anomaly indicators.
- Generate HTML/CSV/JSON reports per capture session.
- Enforce authentication and staff-only capture controls.
- Ship with comprehensive tests and documentation.

## 5. Scope

**In scope:** passive capture, protocol analysis, metadata storage, dashboard,
explorer, analytics, DNS analysis, reporting, settings, JSON API, Django admin,
security controls, testing, Docker support.

**Out of scope (by design):** all offensive capabilities — injection, packet
modification, credential harvesting, MITM, ARP/DNS poisoning, deauthentication,
exploitation. The tool performs passive observation only.

## 6. System Architecture

```
                    ┌──────────────────────────┐
                    │      Django Web App      │
                    │ Dashboard · Explorer ·   │
                    │ Analytics · Sessions ·   │
                    │ Reports · Settings       │
                    └────────────┬─────────────┘
                                 │ Django ORM
                    ┌────────────┴─────────────┐
                    │      Database (SQLite)   │
                    └────────────┬─────────────┘
                                 ▲ bulk_create / updates
                    ┌────────────┴─────────────┐
                    │   Capture Worker         │
                    │   Scapy · Parser · Stats │
                    └────────────┬─────────────┘
                                 ▼
                        Network Interface
```

The capture worker runs as a background thread (web-started) or a separate
process (CLI/`capture_worker.py`). It never executes inside a Django request
handler, so packet capture can never block the web server. Packets are buffered
and committed in batches of 500 with `bulk_create`; session counters are
persisted on a timer and at completion.

**Why capture is separated from the web application:** packet capture is
long-running, I/O-bound and blocking by nature. Running it inside the request
cycle would freeze the dashboard, tie up server threads, and make the system
unusable under load. The separation also models real SOC tooling, where sensors
are independent of the analysis platform.

## 7. Technology Selection

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Python 3.11+ | Rich networking libraries, fast prototyping, huge security ecosystem |
| Web framework | Django 5/6 | Batteries-included security (auth, CSRF, ORM, admin), industry standard |
| Capture engine | Scapy | De facto standard Python packet library; in-memory packet factories make testing safe and deterministic |
| Database | SQLite default | Zero configuration, file-based, ideal for local/small deployments; models are PostgreSQL-ready |
| Charts | Chart.js 4 (vendored) | Lightweight, offline-capable, beautiful dark-theme charts |
| Frontend | Custom CSS + templates | No build step, unique SOC identity, no external CDN dependency |
| Tests | Django TestCase | Integrated runner, transactional isolation, no network required |

**Why Scapy?** Scapy provides layered packet construction and dissection that is
unmatched in Python, and — critically — it can build packets entirely in memory,
which allows the entire parsing stack to be unit-tested without transmitting a
single byte onto a network.

**Why Django?** Django provides authentication, CSRF protection, a safe ORM,
admin interfaces and battle-tested security defaults out of the box, letting the
project focus on the network-analysis domain rather than web framework plumbing.

**Why SQLite?** The project targets local-first use: a single file database with
no server to install is ideal for internships, labs and personal networks.
Because all models use portable field types and the ORM, switching to PostgreSQL
is a configuration change (`DATABASE_URL`), not a rewrite.

## 8. Database Architecture

Five models (all in `sniffer/models.py`):

- **CaptureSession** — one capture run: name, interface, lifecycle status
  (`running`/`stopping`/`completed`/`failed`), live counters (packets, bytes,
  TCP/UDP/ICMP/DNS/ARP/IPv4/IPv6), capture parameters, error message.
- **Packet** — one sanitized metadata record per packet: timestamp, IPs, ports,
  protocol labels, length, TTL, TCP flags, ICMP type/code, limited payload
  preview fields, IP version flags.
- **DNSQuery** — DNS query metadata: name, type, response code, link to packet.
- **NetworkInterface** — discovered interfaces (dynamic, never hard-coded).
- **ApplicationSetting** — key/value configuration (payload storage toggle,
  preview byte limit, retention days).

Design decisions:

- Every filtered field is indexed (protocol, IPs, ports, session+timestamp).
- Payloads are never stored in full: only a bounded preview (`payload_preview`,
  `payload_hex`), capped by `MAX_PAYLOAD_PREVIEW_BYTES` (default 256, hard max 4096).
- Foreign keys cascade on session deletion for clean data lifecycle management.
- Ports and IPs are stored as strings/ints sized for IPv6 compatibility (45 chars).

## 9. Packet Capture Process

The capture engine (`capture/capture_service.py`) runs `scapy.sniff` inside a
worker thread:

1. An operator (CLI or web, staff-only) selects an interface and options.
2. A `CaptureSession` row is created and the worker starts.
3. Each packet is parsed defensively (`capture/packet_parser.py`); malformed
   packets are logged and skipped, never fatal.
4. Parsed metadata is buffered and committed with `bulk_create` in batches
   (500), optionally accompanied by DNSQuery rows.
5. Counters update live in memory and are persisted on a timer and at finish.
6. A `threading.Event` stop-filter provides graceful stop; timeouts and packet
   counts are honored; failures mark the session `failed` with a human-readable
   error.
7. Interface availability is validated before starting; BPF filters map the
   friendly `--protocol` values to capture-filter expressions.

Permission/interface errors (missing Npcap, denied access, invalid interface)
are converted into clear messages shown in the UI and CLI.

## 10. Packet Analysis

The parser treats every packet as untrusted input:

- Layer presence is checked with `getlayer()` before any attribute access.
- IP version, addresses, TTL/hop-limit, ports, TCP flags, ICMP type/code and
  lengths are extracted where they exist.
- The protocol stack is resolved in order: ARP → ICMP/ICMPv6 → TCP/UDP → IP/IPv6
  → Ethernet type → OTHER/UNKNOWN.
- Payload handling is strictly bounded: hex and ASCII previews of at most the
  configured byte count; the ASCII view maps non-printable bytes to `.`.
- Nothing about the payload content is ever interpreted for credentials or
  decrypted — payloads are a diagnostic preview only.

## 11. Protocol Analysis

- **IPv4 / IPv6:** source, destination, TTL/hop limit, version flags.
- **TCP:** ports, compact flag string (`S`, `SA`, `PA`, ...), length.
- **UDP:** ports.
- **ICMP / ICMPv6:** type and code.
- **ARP:** sender/target addresses.
- **DNS:** query name(s), query type label (A, AAAA, MX, ...), response code
  label (NOERROR, NXDOMAIN, ...), stored in `DNSQuery` rows.

`capture/protocol_analyzer.py` aggregates protocol distribution, traffic
timelines (60-second buckets), packet-size histograms and top-N value lists.
`capture/statistics.py` builds per-session statistics and passive anomaly
indicators (elevated ICMP share, traffic spikes, high-frequency DNS queries,
port concentration, SYN-heavy traffic) — each explicitly labeled as a heuristic
requiring human investigation, never as a definitive IDS verdict.

## 12. Django Application

The web layer (`sniffer/` app) provides:

- Landing page (public) with project documentation and dashboard entry.
- Dashboard (login required) with metric cards, Chart.js graphs, recent
  sessions/packets and top talkers.
- Live Capture page with interface selection, packet limit, protocol filter,
  payload toggle, live status panel and 2-second polling status endpoint.
- Session list/detail with tabs, protocol distribution, timeline, DNS activity,
  top IPs/ports, anomalies and exports.
- Packet explorer with search, filters, pagination and packet detail pages
  including the protocol stack and limited payload preview.
- Traffic analytics and DNS analysis pages.
- Interfaces and staff-only settings pages.
- Reports (HTML/CSV/JSON) generated in memory with validated session IDs and
  authentication.
- Built-in JSON API (`/api/*`) with pagination and authentication.
- Django Admin fully configured for all five models.

Separation of concerns is maintained through forms → filters → selectors →
services → views, keeping the view layer thin and testable.

## 13. Dashboard

A dark SOC-style interface (custom CSS, no framework) with:

- Live capture status pill in the top bar (IDLE/CAPTURING/STOPPING).
- Metric cards for sessions, packets, bytes and DNS queries.
- Charts: protocol distribution (doughnut), packets over time (line), TCP vs
  UDP and IPv4 vs IPv6 (bars), top ports (horizontal bar).
- Tables for recent sessions and packets, top source/destination IPs.
- Responsive layout for desktop, tablet and mobile.

Chart data is embedded via Django's `json_script` and parsed client-side —
never string-interpolated — and Chart.js is vendored locally for offline use.

## 14. Security Controls

- Authentication required for all pages except the landing page; capture
  controls, settings, interface refresh and session deletion are staff-only.
- CSRF protection (Django middleware + HTTPONLY CSRF cookie), XSS-safe
  templates, no raw SQL, input validation on every form.
- Security headers: CSP, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy, optional HSTS.
- Login and capture actions are rate-limited (in-memory cache).
- Payload previews disabled by default, hard byte cap, never exported,
  never sent to third parties.
- Secrets only from environment / `.env`; `.env.example` documents all
  variables; `SECRET_KEY` is mandatory in production.
- `DEBUG=False` default; `ALLOWED_HOSTS`, cookie security flags configurable.
- Logging excludes passwords, keys and payload contents.

## 15. Testing

102 tests across `tests/`:

- `test_models.py` — ORM behavior, lifecycle, cascades, settings, indexes.
- `test_packet_parser.py` — TCP/UDP/ICMP/ICMPv6/ARP/IPv6/DNS parsing, TCP flag
  strings, malformed packets, payload truncation and ASCII escaping.
- `test_protocol_analyzer.py` — distributions, top-N, timelines, size
  histograms, DNS frequency, session statistics, anomaly detection.
- `test_capture.py` — full capture lifecycle with injected in-memory packet
  sources: storage, counts, DNS persistence, payload gating, malformed input,
  worker failures, graceful stop, registry cleanup.
- `test_views.py` — auth, permissions, filters, pagination, settings, rate limit.
- `test_reports.py` — CSV/JSON/HTML content, login requirements, 404s,
  no-payload guarantee.
- `test_api.py` — authentication, pagination, filtering, payload exposure rules.

**No test transmits packets onto a real network** — all packets come from
factories in `tests/test_factories.py` built in memory with Scapy.

## 16. Results

- All 102 tests pass; Django system checks pass with zero issues.
- `list_interfaces` correctly discovers host interfaces dynamically.
- A real capture attempt in an environment without Npcap fails gracefully with
  a clear message ("Packet capture requires Npcap/WinPcap...") and the session
  is marked `failed` — no fake data is ever produced.
- Dashboard, authentication, explorer, analytics, reports, admin and API all
  verified live against the dev server.

## 17. Limitations

- Live capture on Windows requires Npcap; on Linux/macOS it requires raw-socket
  privileges for the capture process.
- Web-started captures live in the Django process (single-process dev server);
  a production multi-process deployment would use the CLI worker or a queue.
- SQLite is single-writer; heavy deployments should use PostgreSQL.
- Payload previews are deliberately limited; full payload dumps are out of
  scope by design.

## 18. Ethical Considerations

This project is passive and defensive:

- It never transmits, modifies or injects packets.
- It does not implement credential harvesting, session hijacking, MITM,
  deauthentication or any other offensive technique.
- Payload data is minimized by default, size-limited and never exported or
  shared with third parties.
- External threat-intelligence lookups are optional, disabled by default, and
  would require explicit administrator action per IP.
- The README and dashboard state prominently: monitor only networks you own
  or are explicitly authorized to monitor.

## 19. Future Improvements

- PostgreSQL production deployment; Redis/Celery for distributed capture.
- WebSocket live packet streaming.
- PCAP import/export.
- Optional, admin-controlled threat-intelligence reputation lookups.
- GeoIP visualization; machine-learning anomaly detection.
- Multi-sensor deployments and role-based SOC workflows.

## 20. Learning Outcomes

- Real packet capture with Scapy and defensive protocol parsing.
- Django architecture: models, ORM, views, forms, admin, templates, static
  assets, management commands, security middleware.
- Thread-safe capture worker design, batching and graceful lifecycle handling.
- Database design with indexing, choices, cascades and privacy-aware schemas.
- Security engineering: authz boundaries, rate limiting, headers, secrets
  management, data minimization.
- Frontend integration: Chart.js, polling, responsive dark-theme UI.
- Testing strategy: deterministic in-memory packet factories, transactional
  isolation, full-stack view/API/report tests.

## 21. Conclusion

The CodeAlpha Advanced Network Traffic Analyzer fulfills Task 1 at a professional
standard. It delivers a working, secure, tested and documented network sniffer
that demonstrates the difference between a script and a platform: independent
capture architecture, privacy-safe storage, rich analytics, reporting, strict
authorization and honest handling of environment limitations. It is ready to
run locally, containerized, or as the foundation for further SOC tooling.
