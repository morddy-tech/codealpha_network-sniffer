"""
Django settings for the CodeAlpha Advanced Network Traffic Analyzer.

All secrets and environment-specific values are read from the environment
(or a local ``.env`` file loaded via python-dotenv). No secret values are
committed to the repository.
"""

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

# Load variables from a local .env file when present (e.g. development).
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover - dotenv is a runtime dependency
    pass

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name: str, default: bool = False) -> bool:
    """Parse a boolean environment variable."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    """Parse an integer environment variable with a safe fallback."""
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get("SECRET_KEY")
DEBUG = env_bool("DJANGO_DEBUG", env_bool("DEBUG", False))

if not SECRET_KEY:
    if DEBUG:
        # Local-development-only fallback so the project runs out of the box.
        # Never use this key outside of local development.
        SECRET_KEY = "dev-only-insecure-key-do-not-use-in-production"
    else:
        raise ImproperlyConfigured(
            "SECRET_KEY is not set. Set it in the environment or a .env file."
        )

ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]"
    ).split(",")
    if h.strip()
]

# CSRF / session hardening (enable when serving over HTTPS)
CSRF_TRUSTED_ORIGINS = [
    o.strip()
    for o in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",")
    if o.strip()
]
SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", False)
SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
CSRF_COOKIE_SECURE = env_bool("CSRF_COOKIE_SECURE", False)
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_HTTPONLY = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https") if SECURE_SSL_REDIRECT else None
SECURE_HSTS_SECONDS = 31536000 if SECURE_SSL_REDIRECT else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = SECURE_SSL_REDIRECT
SECURE_HSTS_PRELOAD = SECURE_SSL_REDIRECT
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
    "sniffer",
    "reports",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "core.middleware.SecurityHeadersMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "sniffer.context_processors.capture_status",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# Default: SQLite (zero configuration). DATABASE_URL can switch to
# PostgreSQL without touching application code:
#   sqlite:///path/to/db.sqlite3
#   postgres://user:password@host:5432/dbname
DATABASE_URL = os.environ.get("DATABASE_URL", "")

if DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("POSTGRES_DB", "sniffer"),
            "USER": os.environ.get("POSTGRES_USER", "sniffer"),
            "PASSWORD": os.environ.get("POSTGRES_PASSWORD", ""),
            "HOST": os.environ.get("POSTGRES_HOST", "localhost"),
            "PORT": os.environ.get("POSTGRES_PORT", "5432"),
        }
    }
elif DATABASE_URL.startswith("sqlite://"):
    db_path = DATABASE_URL[len("sqlite://") :].strip()
    if not db_path:
        db_path = str(BASE_DIR / "db.sqlite3")
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": db_path,
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "home"

# ---------------------------------------------------------------------------
# Internationalization
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        # CompressedStaticFilesStorage works without a collectstatic manifest,
        # which keeps `runserver` and tests working on a clean checkout.
        # Set STATICFILES_MANIFEST=True in production to enable
        # CompressedManifestStaticFilesStorage (requires `collectstatic`).
        "BACKEND": (
            "whitenoise.storage.CompressedManifestStaticFilesStorage"
            if env_bool("STATICFILES_MANIFEST", False)
            else "whitenoise.storage.CompressedStaticFilesStorage"
        ),
    },
}

# During development, serve static files live from their source directories
# so CSS/JS edits take effect without re-running collectstatic. In production
# (DEBUG=False) WhiteNoise serves the collected STATIC_ROOT instead.
WHITENOISE_USE_FINDERS = DEBUG

# ---------------------------------------------------------------------------
# Packet capture configuration
# ---------------------------------------------------------------------------
# Privacy controls. Payload previews are OFF by default; the maximum stored
# payload preview size is small and strictly enforced by the parser.
PAYLOAD_STORAGE_ENABLED = env_bool("PAYLOAD_STORAGE_ENABLED", False)
MAX_PAYLOAD_PREVIEW_BYTES = min(
    env_int("MAX_PAYLOAD_PREVIEW_BYTES", 256), 4096
)

CAPTURE_STATS_INTERVAL_SECONDS = 2  # how often worker stats are persisted
CAPTURE_COMMIT_BATCH_SIZE = 500     # packets written per bulk_create batch
# A session whose worker has not reported a heartbeat within this many
# seconds is considered stale (the worker process died without finalizing).
CAPTURE_STALE_AFTER_SECONDS = 15
# How long stop() waits for the worker thread to exit before force-closing.
CAPTURE_STOP_GRACE_SECONDS = 10

# ---------------------------------------------------------------------------
# Optional threat intelligence (OFF by default, never mandatory)
# ---------------------------------------------------------------------------
THREAT_INTEL_ENABLED = env_bool("THREAT_INTEL_ENABLED", False)
THREAT_INTEL_API_KEY = os.environ.get("THREAT_INTEL_API_KEY", "")

# ---------------------------------------------------------------------------
# Rate limiting (in-memory; suitable for single-process development).
# ---------------------------------------------------------------------------
RATE_LIMIT_CACHE = "default"
LOGIN_RATE_LIMIT_PER_MINUTE = 10
CAPTURE_ACTION_RATE_LIMIT_PER_MINUTE = 15

# ---------------------------------------------------------------------------
# Caches
# ---------------------------------------------------------------------------
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "sniffer-cache",
    }
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_DIR = Path(os.environ.get("LOG_DIR", BASE_DIR / "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{asctime} {levelname} {name} {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },
        "app_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "sniffer.log",
            "maxBytes": 5 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console", "app_file"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console", "app_file"],
            "level": "INFO",
            "propagate": False,
        },
        "capture": {
            "handlers": ["console", "app_file"],
            "level": "INFO",
            "propagate": False,
        },
        "core": {
            "handlers": ["console", "app_file"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
