# Installation Guide

This guide covers local installation and running on Windows, Linux and macOS.

## Prerequisites

- Python 3.11 or newer (3.14 recommended)
- pip
- A network interface you own or are authorized to monitor
- **Windows:** [Npcap](https://npcap.com) (required for live capture)
- **Linux/macOS:** privileges for raw packet sockets (see below)

## 1. Get the code

```bash
git clone https://github.com/morddy-tech/codealpha_network-sniffer.git
cd codealpha_network-sniffer
```

## 2. Create and activate a virtual environment

```bash
python -m venv .venv
```

Windows (PowerShell):

```powershell
.venv\Scripts\Activate.ps1
```

Linux / macOS:

```bash
source .venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

Development extras (pytest, coverage):

```bash
pip install -r requirements-dev.txt
```

## 4. Environment configuration

```bash
cp .env.example .env
```

Then edit `.env`:

- `SECRET_KEY` — generate one:
  ```bash
  python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
  ```
- `DEBUG=True` during development only.
- `ALLOWED_HOSTS=localhost,127.0.0.1,[::1]` for local use.
- Leave `PAYLOAD_STORAGE_ENABLED=False` unless you explicitly need payload
  previews (max 4096 bytes).

## 5. Database

By default the app uses SQLite — nothing to install.

```bash
python manage.py migrate
```

To use PostgreSQL instead, set `DATABASE_URL` in `.env`, e.g.:

```
DATABASE_URL=postgres://user:password@localhost:5432/sniffer
```

No code changes are required.

## 6. Create an administrator

```bash
python manage.py createsuperuser
```

The superuser (staff) can start/stop captures, delete sessions and edit
settings. Regular users can view analytics only.

## 7. Run the web application

```bash
python manage.py runserver
```

Open http://127.0.0.1:8000/ — sign in and click **Open Dashboard**.

## 8. Verify the environment

```bash
python manage.py check          # system checks
python manage.py list_interfaces
python manage.py test           # 102 tests, no network activity
```

## Windows specifics

1. Install **Npcap** from https://npcap.com (accept default options) and
   restart the machine.
2. Run capture commands from an **Administrator** terminal (or grant the
   account the required capability).
3. Interface names are dynamic — never hard-code them:
   ```bash
   python manage.py list_interfaces
   python manage.py capture --interface "Wi-Fi" --count 200
   ```

## Linux specifics

Raw-socket capture requires privileges. Prefer a capability instead of root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

or run the capture commands with `sudo` only (the Django web app needs no
privileges):

```bash
sudo python manage.py capture --interface eth0 --count 200
```

## macOS specifics

```bash
brew install libpcap
```

Run the capture command with `sudo` for the capture phase:

```bash
sudo python manage.py capture --interface en0 --count 200
```

## Start a capture

From the web (staff): **Live Capture** page → choose interface → Start.

From the CLI:

```bash
python manage.py capture --interface "Wi-Fi" --count 100
python manage.py capture --interface eth0 --protocol tcp --count 500
python capture_worker.py --interface "Wi-Fi" --count 100
```

Watch the dashboard fill with real captured traffic.

## Data retention

```bash
# Preview what would be deleted
python manage.py cleanup_packets --older-than 30 --dry-run

# Actually delete sessions older than 30 days
python manage.py cleanup_packets --older-than 30
```

Nothing is ever deleted automatically.

## Docker (web app only)

```bash
docker compose up --build
```

Live capture from a container requires host networking and privileges, and
differs per OS. Run the capture worker on the host when capturing.
