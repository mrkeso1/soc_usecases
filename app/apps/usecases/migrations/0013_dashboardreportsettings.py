# Generated manually for dashboard PDF report settings.

from django.db import migrations, models
from django.db.models import Q


def keep_latest_active_dashboard_report_settings(apps, schema_editor):
    DashboardReportSettings = apps.get_model("usecases", "DashboardReportSettings")
    active_ids = list(
        DashboardReportSettings.objects.filter(is_active=True)
        .order_by("-id")
        .values_list("id", flat=True)
    )
    if len(active_ids) > 1:
        DashboardReportSettings.objects.filter(id__in=active_ids[1:]).update(is_active=False)


class Migration(migrations.Migration):

    dependencies = [
        ("usecases", "0012_add_manage_lifecycle_controls_permission"),
    ]

    operations = [
        migrations.CreateModel(
            name="DashboardReportSettings",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(default="Reporte principal", max_length=100, unique=True)),
                ("is_active", models.BooleanField(default=True)),
                ("logo", models.ImageField(blank=True, upload_to="dashboard_reports/logos/", verbose_name="Logo")),
                ("report_title", models.CharField(default="Reporte ejecutivo SOC", max_length=160, verbose_name="Título")),
                ("report_subtitle", models.CharField(blank=True, default="Cobertura ATT&CK y D3FEND sobre casos de uso en producción", max_length=255, verbose_name="Subtítulo")),
                ("footer_text", models.CharField(blank=True, default="SOC Use Cases Manager", max_length=255, verbose_name="Pie de página")),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Configuración reporte dashboard",
                "verbose_name_plural": "Configuraciones reporte dashboard",
            },
        ),
        migrations.RunPython(keep_latest_active_dashboard_report_settings, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="dashboardreportsettings",
            constraint=models.UniqueConstraint(condition=Q(is_active=True), fields=("is_active",), name="unique_active_dashboard_report_settings"),
        ),
    ]
