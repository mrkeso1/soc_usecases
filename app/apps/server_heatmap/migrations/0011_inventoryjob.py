import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("server_heatmap", "0010_serverassetdisableevent"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="InventoryJob",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("job_type", models.CharField(choices=[("full_sync", "Actualizar AD y SIEM"), ("reprocess", "Cruzar inventario almacenado"), ("apply_filters", "Aplicar filtros")], db_index=True, max_length=30, verbose_name="Tipo")),
                ("idempotency_key", models.CharField(max_length=100, unique=True, verbose_name="Clave de idempotencia")),
                ("status", models.CharField(choices=[("pending", "Pendiente"), ("running", "En ejecución"), ("retrying", "Reintentando"), ("completed", "Finalizado"), ("failed", "Fallido"), ("cancelled", "Cancelado")], db_index=True, default="pending", max_length=20, verbose_name="Estado")),
                ("payload", models.JSONField(blank=True, default=dict, verbose_name="Parámetros")),
                ("result", models.JSONField(blank=True, default=dict, verbose_name="Resultado")),
                ("progress", models.JSONField(blank=True, default=dict, verbose_name="Progreso")),
                ("attempts", models.PositiveSmallIntegerField(default=0, verbose_name="Intentos")),
                ("max_attempts", models.PositiveSmallIntegerField(default=3, verbose_name="Máximo de intentos")),
                ("rerun_requested", models.BooleanField(default=False, verbose_name="Repetición solicitada")),
                ("available_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now, verbose_name="Disponible desde")),
                ("started_at", models.DateTimeField(blank=True, null=True, verbose_name="Inicio")),
                ("heartbeat_at", models.DateTimeField(blank=True, null=True, verbose_name="Último heartbeat")),
                ("lease_expires_at", models.DateTimeField(blank=True, db_index=True, null=True, verbose_name="Vencimiento de lease")),
                ("finished_at", models.DateTimeField(blank=True, null=True, verbose_name="Fin")),
                ("worker_id", models.CharField(blank=True, max_length=150, verbose_name="Worker")),
                ("last_error", models.TextField(blank=True, verbose_name="Último error")),
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Creado")),
                ("updated_at", models.DateTimeField(auto_now=True, verbose_name="Actualizado")),
                ("requested_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="server_inventory_jobs", to=settings.AUTH_USER_MODEL, verbose_name="Solicitado por")),
            ],
            options={
                "verbose_name": "Trabajo de inventario",
                "verbose_name_plural": "Trabajos de inventario",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="inventoryjob",
            constraint=models.UniqueConstraint(
                condition=models.Q(("status__in", ["pending", "running", "retrying"])),
                fields=("job_type",),
                name="uniq_active_inventory_job_type",
            ),
        ),
        migrations.AddIndex(
            model_name="inventoryjob",
            index=models.Index(fields=["status", "available_at"], name="server_heat_status_3cbb5d_idx"),
        ),
    ]
