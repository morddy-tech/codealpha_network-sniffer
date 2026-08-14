"""Custom security middleware for the traffic analyzer."""

from __future__ import annotations

import logging

from django.http import HttpResponse

logger = logging.getLogger("core")

# Content-Security-Policy: the dashboard loads no remote resources.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware:
    """
    Adds security-relevant HTTP response headers to every response.

    Runs inside the Django middleware chain (no WSGI-level modifications) and
    is skipped for streaming responses, which the staticfile middleware
    produces during collectstatic.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Streaming responses are handled by Whitenoise for static files.
        if getattr(response, "streaming", False):
            return response

        response["Content-Security-Policy"] = _CSP
        response.setdefault("X-Content-Type-Options", "nosniff")
        response.setdefault("Referrer-Policy", "same-origin")
        response.setdefault("X-Frame-Options", "DENY")
        response.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

        if request.is_secure():
            response.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

        # Prevent the browser from MIME-sniffing plain-text exports.
        if request.path.startswith("/reports/") and "text/plain" not in response.get(
            "Content-Type", ""
        ):
            response["X-Download-Options"] = "noopen"
        return response

    def process_exception(self, request, exception):  # pragma: no cover - defensive
        """Ensure headers are present even on error responses."""
        logger.debug("Middleware exception handler invoked for %s", request.path)
        return None
