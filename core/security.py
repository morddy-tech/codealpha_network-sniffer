"""Security helpers: rate limiting and permission decorators."""

from __future__ import annotations

import hashlib
import logging
from functools import wraps
from typing import Callable

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden

logger = logging.getLogger("core")


def rate_limit(cache_key_builder: Callable, limit: int, window_seconds: int = 60):
    """
    Simple sliding-window-ish rate limiter built on Django's cache.

    :param cache_key_builder: callable(request) -> str cache key
    :param limit: maximum allowed requests within the window
    :param window_seconds: length of the window in seconds
    """

    def decorator(view_func):
        @wraps(view_func)
        def wrapped(request, *args, **kwargs):
            key = cache_key_builder(request)
            if key is None:
                return view_func(request, *args, **kwargs)

            current = cache.get(key, 0)
            if current >= limit:
                logger.warning("Rate limit exceeded for %s (limit %d)", key, limit)
                return HttpResponseForbidden(
                    "Too many requests. Please slow down and try again shortly."
                )
            cache.set(key, current + 1, window_seconds)
            return view_func(request, *args, **kwargs)

        return wrapped

    return decorator


def client_ip_builder(request) -> str:
    """Cache key built from the client IP (respecting reverse proxies)."""
    ip = request.META.get("REMOTE_ADDR", "unknown")
    # Trust X-Forwarded-For only when running behind a configured proxy.
    if settings.SECURE_PROXY_SSL_HEADER and request.META.get("HTTP_X_FORWARDED_FOR"):
        ip = request.META["HTTP_X_FORWARDED_FOR"].split(",")[0].strip()
    digest = hashlib.sha256(ip.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"rate:{digest}:{request.path}"


def ip_rate_limit(limit: int, window_seconds: int = 60):
    """Rate limit a view per client IP."""
    return rate_limit(
        lambda request: client_ip_builder(request) if request else None,
        limit,
        window_seconds,
    )
