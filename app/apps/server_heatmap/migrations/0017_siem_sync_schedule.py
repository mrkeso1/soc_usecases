import datetime

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("server_heatmap", "0016_alter_inventoryjob_job_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="serverinventoryconfiguration",
            name="siem_sync_enabled",
            field=models.BooleanField(
                default=False,
                help_text="Descarga y procesa automáticamente el archivo configurado en SERVER_INVENTORY_SIEM_URL.",
                verbose_name="Sincronización SIEM automática",
            ),
        ),
        migrations.AddField(
            model_name="serverinventoryconfiguration",
            name="siem_sync_interval_days",
            field=models.PositiveSmallIntegerField(
                default=1,
                help_text="1 = todos los días; 2 = día por medio; 7 = semanal.",
                verbose_name="Periodicidad SIEM (días)",
            ),
        ),
        migrations.AddField(
            model_name="serverinventoryconfiguration",
            name="siem_sync_last_enqueued_at",
            field=models.DateTimeField(
                blank=True,
                editable=False,
                null=True,
                verbose_name="Última sincronización SIEM programada",
            ),
        ),
        migrations.AddField(
            model_name="serverinventoryconfiguration",
            name="siem_sync_time",
            field=models.TimeField(
                default=datetime.time(2, 0),
                help_text="Se interpreta en la zona horaria configurada por el sistema.",
                verbose_name="Horario de sincronización SIEM",
            ),
        ),
        migrations.AlterField(
            model_name="inventoryjob",
            name="job_type",
            field=models.CharField(
                choices=[
                    ("full_sync", "Actualizar AD y SIEM"),
                    ("reprocess", "Cruzar inventario almacenado"),
                    ("apply_filters", "Aplicar filtros"),
                    ("network_diagnostic", "Diagnosticar conectividad"),
                    ("siem_sync", "Actualizar archivo SIEM"),
                ],
                db_index=True,
                max_length=30,
                verbose_name="Tipo",
            ),
        ),
    ]
