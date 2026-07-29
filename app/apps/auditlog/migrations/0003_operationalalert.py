import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("auditlog", "0002_alter_auditlog_options"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="OperationalAlert",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("code", models.CharField(db_index=True, max_length=100, verbose_name="Código")),
                ("fingerprint", models.CharField(db_index=True, max_length=255, verbose_name="Huella")),
                ("severity", models.CharField(choices=[("info", "Informativa"), ("warning", "Advertencia"), ("error", "Error"), ("critical", "Crítica")], default="warning", max_length=20, verbose_name="Severidad")),
                ("status", models.CharField(choices=[("open", "Abierta"), ("acknowledged", "Reconocida"), ("resolved", "Resuelta")], db_index=True, default="open", max_length=20, verbose_name="Estado")),
                ("title", models.CharField(max_length=255, verbose_name="Título")),
                ("message", models.TextField(verbose_name="Mensaje")),
                ("context", models.JSONField(blank=True, default=dict, verbose_name="Contexto")),
                ("occurrences", models.PositiveIntegerField(default=1, verbose_name="Ocurrencias")),
                ("first_seen_at", models.DateTimeField(auto_now_add=True, verbose_name="Primera detección")),
                ("last_seen_at", models.DateTimeField(auto_now=True, verbose_name="Última detección")),
                ("last_notified_at", models.DateTimeField(blank=True, null=True, verbose_name="Última notificación")),
                ("acknowledged_at", models.DateTimeField(blank=True, null=True, verbose_name="Reconocida")),
                ("resolved_at", models.DateTimeField(blank=True, null=True, verbose_name="Resuelta")),
                ("acknowledged_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="acknowledged_operational_alerts", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "verbose_name": "Alerta operativa",
                "verbose_name_plural": "Alertas operativas",
                "ordering": ["-last_seen_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="operationalalert",
            constraint=models.UniqueConstraint(
                condition=models.Q(("status__in", ["open", "acknowledged"])),
                fields=("fingerprint",),
                name="uniq_active_operational_alert_fingerprint",
            ),
        ),
    ]
