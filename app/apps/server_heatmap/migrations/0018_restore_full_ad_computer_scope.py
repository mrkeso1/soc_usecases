from django.db import migrations, models


def restore_full_ad_scope(apps, schema_editor):
    configuration = apps.get_model(
        "server_heatmap",
        "ServerInventoryConfiguration",
    )
    configuration.objects.update(ad_active_days=0)


class Migration(migrations.Migration):

    dependencies = [
        ("server_heatmap", "0017_siem_sync_schedule"),
    ]

    operations = [
        migrations.AlterField(
            model_name="serverinventoryconfiguration",
            name="ad_active_days",
            field=models.PositiveSmallIntegerField(
                default=0,
                help_text=(
                    "Use 0 para importar todos los objetos Computer, como en el mapa "
                    "de calor original. Un valor mayor sólo incluye cuentas habilitadas "
                    "cuya última actividad en Active Directory esté dentro de ese período."
                ),
                verbose_name="Actividad máxima en AD (días)",
            ),
        ),
        migrations.AlterField(
            model_name="serverinventoryconfiguration",
            name="retention_days",
            field=models.PositiveSmallIntegerField(
                default=90,
                help_text=(
                    "Después de una sincronización AD exitosa sólo se eliminan equipos "
                    "que ya no aparecen en AD y superan este período. Use 0 para no eliminar."
                ),
                verbose_name="Eliminar equipos sin conexión después de (días)",
            ),
        ),
        migrations.RunPython(
            restore_full_ad_scope,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
