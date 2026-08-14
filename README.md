<div align="center">

# CodeAlpha Network Traffic Analyzer

### CodeAlpha Internship · Task 1 — Basic Network Sniffer

**Real-Time Network Traffic Capture, Analysis & Security Monitoring**

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Django](https://img.shields.io/badge/Django-5.x%2F6.x-092E20?logo=django)
![Scapy](https://img.shields.io/badge/Scapy-2.6%2B-1B6AC6)
![License](https://img.shields.io/badge/License-MIT-green)

</div>

---

## ⚠️ Ethical Use — Read First

This is a **passive** network monitoring and analysis platform. It captures
packet metadata, inspects protocol information and computes traffic
statistics. It implements **no** offensive capability: no injection, no
packet modification, no credential harvesting, no MITM, no ARP/DNS poisoning.

> **Only monitor networks and devices that you own or have explicit
> authorization to monitor.** Unauthorized network interception is illegal in
> most jurisdictions.

---

## Overview

A production-grade, internship-level cybersecurity project: a Django-based
web platform that captures live network traffic with Scapy in a background
worker, parses protocol metadata defensively, stores sanitized records via the
Django ORM, and presents a professional dark-themed SOC dashboard with
analytics, packet exploration, DNS analysis, reporting, and passive anomaly
indicators.

It is **not** a tutorial Scapy script. Packet capture is fully separated from
the web server, data is stored with privacy-safe limits, and the whole stack
is tested, documented and Docker-ready.

---

## Core Features

| Area | What it does |
|------|--------------|
| **Live capture** | Background capture worker; interface selection, packet limits, timeouts, BPF protocol filters; web page and CLI control |
| **Protocol analysis** | IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ARP, DNS metadata extraction with defensive layer handling |
| **Dashboard** | Metric cards + Chart.js graphs: protocol distribution, traffic timeline, TCP vs UDP, IPv4 vs IPv6, top ports, recent sessions/packets |
| **Packet explorer** | Search, protocol/session/IP/port/date filters, pagination, packet detail pages with protocol stack and payload preview |
| **DNS analysis** | Query names, types, response codes, frequency, first/last seen, search & filters |
| **Traffic analytics** | Top IPs/ports, packet-size histogram, volume over time, passive anomaly indicators |
| **Reporting** | Per-session HTML, CSV and JSON exports (payloads never exported) |
| **Privacy controls** | Payload previews OFF by default, strict byte limit, configurable retention, session deletion |
| **Built-in JSON API** | Sessions, packets, statistics, DNS, interfaces — paginated, authenticated, payload-safe |
| **Django Admin** | Fully configured for sessions, packets, DNS queries, interfaces and settings |

## Supported Protocols

`IPv4` · `IPv6` · `TCP` · `UDP` · `ICMP` · `ICMPv6` · `ARP` · `DNS`

## Architecture

```
Browser ──► Django Web App ──► Django ORM ──► SQLite (or PostgreSQL)
                 ▲                                ▲
                 └─────────── Capture Worker (Scapy) ──► Network Interface
```

The capture worker runs **outside** the web server request/response cycle, so
packet capture can never block the dashboard. Both sides share only the
database. See [`docs/architecture.md`](docs/architecture.md).

## Technology Stack

- **Python 3.11+**, **Django 5/6**, **Scapy** for capture & parsing
- **SQLite** by default; models are PostgreSQL-ready via `DATABASE_URL`
- **Chart.js 4** (vendored locally — no CDN dependency)
- Custom dark SOC-style CSS (no frontend framework required)
- Django's test framework (102 tests) — no real network traffic in tests

## Project Structure

```
codealpha_network-sniffer/
├── manage.py
├── requirements.txt / requirements-dev.txt
├── .env.example / .gitignore / LICENSE
├── config/            # settings, urls, wsgi, asgi
├── core/              # security middleware, rate limiting, validators
├── sniffer/           # models, views, forms, filters, selectors, services,
│                      # admin, templates, static assets, management commands
├── capture/           # packet parser, protocol analyzer, statistics,
│                      # interface manager, capture service
├── reports/           # CSV / JSON / HTML export services
├── tests/             # model, parser, analyzer, capture, view, report, API tests
├── templates/         # base layout
├── docs/              # project report, architecture, installation, security
├── Dockerfile / docker-compose.yml
└── capture_worker.py  # standalone worker entrypoint
```

## Installation

### 1. Prerequisites

- **Python 3.11+**
- **Npcap** on Windows (https://npcap.com) — required for live packet capture
- On **Linux**: the capture user needs privileges for raw sockets
  (see *Linux Setup* below)

### 2. Clone and prepare

```bash
git clone https://github.com/morddy-tech/codealpha_network-sniffer.git
cd codealpha_network-sniffer

python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure the environment

```bash
cp .env.example .env
```

Edit `.env` and set a real `SECRET_KEY`:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

### 4. Database, admin user, run

```bash
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open http://127.0.0.1:8000/ — sign in, and use the **Live Capture** page or
the CLI worker.

> **No fake data.** The dashboard shows real captured data only. If nothing
> has been captured yet it shows "No capture data available."

## Windows Setup

1. Install **Npcap** (https://npcap.com) and restart your machine.
2. Open a terminal **as Administrator** to capture traffic.
3. `python manage.py list_interfaces` to see discoverable interfaces
   (friendly names like `Wi-Fi`, `Ethernet` are supported).
4. Capture with either the web page or:
   ```bash
   python manage.py capture --interface "Wi-Fi" --count 200
   ```

## Linux Setup

Raw-socket capture requires privileges. Prefer granting the capture user
CAP_NET_RAW instead of running everything as root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
python manage.py list_interfaces
python manage.py capture --interface eth0 --count 200
```

The Django web app itself does **not** need elevated privileges.

## macOS Setup

Install [libpcap](https://formulae.brew.sh/formula/libpcap) (`brew install
libpcap`), then run the capture command with `sudo` for the capture phase only.

## Usage Examples

```bash
# List discoverable interfaces
python manage.py list_interfaces

# Capture 200 packets from Wi-Fi
python manage.py capture --interface "Wi-Fi" --count 200

# TCP-only capture, 500 packets, with payload previews
python manage.py capture --interface eth0 --protocol tcp --count 500 --payload

# Time-limited capture
python manage.py capture --interface eth0 --timeout 30

# Standalone worker (same engine, own process)
python capture_worker.py --interface "Wi-Fi" --count 100

# Analyze a session (summary + anomaly indicators)
python manage.py analyze_session 1

# Data retention (nothing is ever deleted automatically)
python manage.py cleanup_packets --older-than 30 --dry-run
python manage.py cleanup_packets --older-than 30

# Run the test suite (in-memory packets, no network activity)
python manage.py test
```

## Dashboard URLs

| Page | URL |
|------|-----|
| Landing page | `/` |
| Dashboard | `/dashboard/` |
| Live Capture | `/capture/` |
| Capture Sessions | `/sessions/` |
| Packet Explorer | `/packets/` |
| Traffic Analytics | `/analytics/` |
| DNS Analysis | `/analytics/dns/` |
| Interfaces | `/interfaces/` |
| Settings (staff) | `/settings/` |
| Reports | `/reports/session/<id>/html|csv|json/` |
| JSON API | `/api/sessions/`, `/api/packets/`, `/api/statistics/`, `/api/dns/`, `/api/interfaces/` |
| Django Admin | `/admin/` |

## Testing

```bash
python manage.py test        # 102 tests: models, parser, protocols, capture,
                             # views, permissions, filters, reports, API
```

All packet tests use in-memory Scapy packets built by factories in
`tests/test_factories.py` — **no packet is ever transmitted onto a real
network** by the test suite.

## Security

See [`docs/security.md`](docs/security.md) for the full discussion. Highlights:

- Authentication required for everything except the landing page; capture
  controls, settings and deletions are staff-only
- CSRF protection, security headers (CSP, nosniff, frame-ancestors, HSTS),
  rate-limited login and capture endpoints
- Payload previews **disabled by default**, strictly capped
  (`MAX_PAYLOAD_PREVIEW_BYTES=256`), never exported
- Secrets only from environment/`.env` — nothing secret is committed
- ORM queries only, input validation on every form, no raw SQL
- Passive anomaly indicators are clearly labeled heuristics, not IDS verdicts

## Docker

```bash
docker compose up --build
```

The web app runs fully in Docker. **Live packet capture from a container
requires host networking and privileges** (e.g. `network_mode: host` and
`CAP_NET_RAW`) and differs per OS — the compose file ships the web app by
default; run the capture worker on the host when necessary. The application
always runs directly on the host without Docker.

## Limitations

- Live capture requires Npcap (Windows) or raw-socket privileges (Linux/macOS)
- The capture status registry is in-process: web-started captures are visible
  to the Django process that started them (single-process dev server)
- SQLite is single-writer; heavy production deployments should move to
  PostgreSQL via `DATABASE_URL`
- Payload previews are deliberately limited — full payload dumps are out of
  scope by design

## Future Improvements

- PostgreSQL production deployment
- Redis/Celery for distributed capture management
- WebSocket live packet streaming
- PCAP import/export
- Optional threat-intelligence integrations (explicit, admin-controlled only)
- GeoIP visualization
- Machine-learning anomaly detection
- Multi-sensor deployments

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Sniffing... not available at layer 2` | Install Npcap on Windows, restart |
| `Permission denied` on capture | Run the capture with appropriate privileges |
| `Interface ... was not found` | Run `python manage.py list_interfaces` |
| `SECRET_KEY is not set` | Set it in `.env` |
| Charts missing | Ensure `sniffer/static/sniffer/vendor/chart.umd.min.js` exists (vendored) |
| Static files 404 | `python manage.py collectstatic` |

## CodeAlpha Submission

- **Project:** CodeAlpha Network Traffic Analyzer
- **Task:** Task 1 — Basic Network Sniffer
- **Repo:** `codealpha_network-sniffer`
- **Report:** [`docs/project-report.md`](docs/project-report.md)

## Author

Ifedayo Matthew — CodeAlpha cybersecurity internship project.

## License

MIT — see [LICENSE](LICENSE). Use ethically: monitor only what you own or are
explicitly authorized to monitor.
