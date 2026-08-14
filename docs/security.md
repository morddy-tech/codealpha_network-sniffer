# Security Guide

This document explains the security model of the CodeAlpha Advanced Network
Traffic Analyzer.

## Ethical Packet Capture

The tool is **passive by construction**:

- It only reads packets; it never transmits, injects or modifies traffic.
- It implements no offensive features: no credential harvesting, session
  hijacking, MITM, ARP/DNS poisoning, deauthentication or exploitation.
- Capture is restricted to interfaces explicitly selected by an authorized
  operator.

> Only monitor networks and devices that you own or have explicit authorization
> to monitor. Unauthorized interception is illegal in most jurisdictions.

## Authorization

- **Authentication** is required for everything except the public landing
  page (`/`).
- **Staff-only** actions: starting/stopping captures, deleting sessions,
  changing settings, refreshing interface detection.
- Regular (non-staff) authenticated users can view the dashboard, explorer,
  analytics and reports.
- All checks happen server-side in views; the UI merely hides what the server
  denies.

## Data Minimization

- Only packet **metadata** is stored by default: IPs, ports, protocols,
  lengths, flags, TTL, DNS names.
- **Payload previews are disabled by default** (`PAYLOAD_STORAGE_ENABLED=False`).
- When enabled, previews are capped at `MAX_PAYLOAD_PREVIEW_BYTES` (default
  256, hard ceiling 4096) for both hex and ASCII views.
- The parser never interprets payload content (no password/credential
  extraction) and never attempts decryption.
- Reports and the JSON API never include payload fields.
- No captured data is sent to third parties; optional threat-intelligence
  lookups are disabled by default and would be explicit, per-IP, staff-only.

## Payload Limitations

| Layer | Rule |
|-------|------|
| Storage | OFF by default; toggleable per session and globally |
| Size | Hard-capped at 4096 bytes (configurable, default 256) |
| Format | Hex preview + escaped ASCII preview, always truncated |
| Export | Never included in CSV/JSON/HTML reports or the API list endpoint |
| Interpretation | Never analyzed for secrets, never decrypted |

## Authentication

- Django's built-in authentication with hashed passwords.
- Login view wrapped in a per-IP rate limiter (default 10 attempts/minute).
- Session cookies are `HttpOnly`; set `SESSION_COOKIE_SECURE` and
  `CSRF_COOKIE_SECURE=True` when serving over HTTPS.
- `LOGIN_URL`/`LOGIN_REDIRECT_URL` configured; logout is a POST form.

## CSRF

- Django's CSRF middleware is active on all state-changing views.
- CSRF cookie is `HttpOnly`; `CSRF_TRUSTED_ORIGINS` is configurable.
- All delete/start/stop/settings actions require the CSRF token.

## XSS

- All templates auto-escape variable output (Django's default behavior).
- Chart data is embedded with `{% json_script %}` and parsed client-side —
  never string-interpolated into JavaScript.
- A Content-Security-Policy is applied: scripts and styles only from `self`.

## SQL Injection

- The application uses the Django ORM exclusively — no raw SQL anywhere.
- User input passes through typed Django forms (integers, dates, choices)
  before reaching querysets.

## Secret Management

- No secrets are committed. `.env` is gitignored; `.env.example` documents
  every variable without values.
- `SECRET_KEY` is required in production (the app refuses to start without it
  when `DEBUG=False`).
- Threat-intelligence API keys, if ever used, come from the environment only.

## API Security

- All `/api/*` endpoints require authentication (JSON 401 otherwise).
- Pagination is bounded (`page_size` capped at 100).
- Filters are validated through the same forms as the UI.
- Packet payload previews are exposed only on the single-packet detail
  endpoint, and only when the owning session enabled payload storage.

## Data Retention

- Nothing is deleted automatically.
- `python manage.py cleanup_packets --older-than N` deletes sessions (and
  their packets) older than N days; `--dry-run` previews first.
- Administrators can delete individual sessions from the UI with a
  confirmation step; deletion cascades to packets and DNS rows.
- `DELETE` semantics: rows are physically removed (no soft-delete ghosts of
  payload data remain).

## Export Security

- Reports require authentication and validate the session ID (404 for unknown).
- Content-Disposition headers force download; content types are exact.
- No filesystem paths are involved — all exports render in memory.
- Payload fields are excluded from every export format.

## Logging

- Application logs capture start/stop, errors, admin actions and auth events.
- Logs never include passwords, API keys, or packet payload contents.
- Logging is configured with rotating file handlers (5 MB × 3 backups) plus
  console output.

## Threat-Intelligence Privacy

- The integration is OFF by default (`THREAT_INTEL_ENABLED=False`).
- When enabled, lookups would be explicit, administrator-initiated, per-IP
  reputation checks only — never automatic bulk submission of captured IPs.
- API keys are environment variables only.

## Deployment Hardening Checklist

- [ ] `DEBUG=False`
- [ ] Strong `SECRET_KEY` from environment
- [ ] `ALLOWED_HOSTS` lists only real hostnames
- [ ] HTTPS in front; `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE=True`
- [ ] `python manage.py collectstatic` (and optionally
      `STATICFILES_MANIFEST=True`)
- [ ] Run the web app unprivileged; grant capture privileges only to the
      capture worker
- [ ] Configure retention and run `cleanup_packets` on a schedule if needed
- [ ] Keep payload storage disabled unless required
