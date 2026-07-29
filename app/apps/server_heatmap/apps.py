from django.apps import AppConfig


class ServerHeatmapConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.server_heatmap"
    verbose_name = "Mapa de calor de servidores"

    def ready(self):
        from . import rule_revisions  # noqa: F401
