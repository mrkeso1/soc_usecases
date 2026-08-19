from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("server_heatmap", "0020_inventory_discovery_metrics"),
    ]

    operations = [
        migrations.AddField(
            model_name="serverasset",
            name="is_siem_only_approved",
            field=models.BooleanField(
                db_index=True,
                default=False,
                help_text=(
                    "Excepción aprobada manualmente para equipos que existen en SIEM "
                    "pero no forman parte de Active Directory."
                ),
                verbose_name="Solo SIEM aprobado",
            ),
        ),
        migrations.AddField(
            model_name="serverasset",
            name="siem_exception_approved_at",
            field=models.DateTimeField(
                blank=True,
                editable=False,
                null=True,
                verbose_name="Fecha de aprobación Solo SIEM",
            ),
        ),
        migrations.AddField(
            model_name="serverasset",
            name="siem_exception_reason",
            field=models.TextField(blank=True, verbose_name="Motivo de aprobación Solo SIEM"),
        ),
        migrations.AddField(
            model_name="serverasset",
            name="siem_exception_approved_by",
            field=models.ForeignKey(
                blank=True,
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="approved_siem_only_servers",
                to=settings.AUTH_USER_MODEL,
                verbose_name="Aprobado por",
            ),
        ),
        migrations.AddField(
            model_name="serverasset",
            name="siem_exception_observation",
            field=models.ForeignKey(
                blank=True,
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="approved_siem_only_assets",
                to="server_heatmap.inventoryobservation",
                verbose_name="Observación SIEM de aprobación",
            ),
        ),
    ]
