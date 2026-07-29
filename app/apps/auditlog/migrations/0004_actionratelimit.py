import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("auditlog", "0003_operationalalert"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ActionRateLimit",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("scope", models.CharField(max_length=100, verbose_name="Acción protegida")),
                ("window_started_at", models.DateTimeField(verbose_name="Inicio de ventana")),
                ("request_count", models.PositiveIntegerField(default=0, verbose_name="Solicitudes aceptadas")),
                ("blocked_count", models.PositiveIntegerField(default=0, verbose_name="Solicitudes bloqueadas")),
                ("last_request_at", models.DateTimeField(verbose_name="Última solicitud")),
                ("updated_at", models.DateTimeField(auto_now=True, verbose_name="Actualizado")),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="action_rate_limits",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="Usuario",
                    ),
                ),
            ],
            options={
                "verbose_name": "Límite de acción",
                "verbose_name_plural": "Límites de acciones",
                "ordering": ["-last_request_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="actionratelimit",
            constraint=models.UniqueConstraint(
                fields=("user", "scope"),
                name="uniq_action_rate_limit_user_scope",
            ),
        ),
        migrations.AddIndex(
            model_name="actionratelimit",
            index=models.Index(
                fields=["scope", "last_request_at"],
                name="auditlog_ac_scope_a0823c_idx",
            ),
        ),
    ]
