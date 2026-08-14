"""Root URL configuration for the Advanced Network Traffic Analyzer."""
from django.conf import settings
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from core.security import ip_rate_limit

urlpatterns = [
    path("admin/", admin.site.urls),
    path(
        "accounts/login/",
        ip_rate_limit(limit=settings.LOGIN_RATE_LIMIT_PER_MINUTE, window_seconds=60)(
            auth_views.LoginView.as_view(template_name="registration/login.html")
        ),
        name="login",
    ),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", include("sniffer.urls")),
]
