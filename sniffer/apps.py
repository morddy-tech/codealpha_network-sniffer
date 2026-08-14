"""Django app configuration for the sniffer application."""

from django.apps import AppConfig


class SnifferConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "sniffer"
    verbose_name = "Network Traffic Analyzer"
