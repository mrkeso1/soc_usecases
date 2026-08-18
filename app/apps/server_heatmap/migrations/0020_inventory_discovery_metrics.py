from django.db import migrations, models
from django.db.models import Min


def backfill_first_seen(apps, schema_editor):
    ServerAsset = apps.get_model("server_heatmap", "ServerAsset")
    InventoryObservation = apps.get_model("server_heatmap", "InventoryObservation")

    earliest = {
        (row["asset_id"], row["source"]): row["first_seen"]
        for row in InventoryObservation.objects.exclude(asset_id=None)
        .values("asset_id", "source")
        .annotate(first_seen=Min("created_at"))
    }

    pending_updates = []
    for asset in ServerAsset.objects.all().iterator():
        ad_first_seen = earliest.get((asset.pk, "ad"))
        siem_first_seen = earliest.get((asset.pk, "siem"))

        if ad_first_seen or asset.in_active_directory or asset.ad_last_seen_at:
            asset.ad_first_seen_at = ad_first_seen or asset.created_at
        if siem_first_seen or asset.in_siem or asset.siem_last_seen_at:
            asset.siem_first_seen_at = siem_first_seen or asset.created_at

        if asset.ad_first_seen_at or asset.siem_first_seen_at:
            pending_updates.append(asset)

    if pending_updates:
        ServerAsset.objects.bulk_update(
            pending_updates,
            ["ad_first_seen_at", "siem_first_seen_at"],
            batch_size=500,
        )


class Migration(migrations.Migration):

    dependencies = [
        ("server_heatmap", "0019_serverasset_is_critical"),
    ]

    operations = [
        migrations.AddField(
            model_name="serverasset",
            name="ad_first_seen_at",
            field=models.DateTimeField(
                blank=True,
                db_index=True,
                editable=False,
                null=True,
                verbose_name="Primera detección AD",
            ),
        ),
        migrations.AddField(
            model_name="serverasset",
            name="siem_first_seen_at",
            field=models.DateTimeField(
                blank=True,
                db_index=True,
                editable=False,
                null=True,
                verbose_name="Primera detección SIEM",
            ),
        ),
        migrations.AddField(
            model_name="serverinventoryconfiguration",
            name="dashboard_default_environment",
            field=models.CharField(
                default="PROD",
                help_text="Use ALL para mostrar todos los ambientes inicialmente.",
                max_length=80,
                verbose_name="Ambiente predeterminado del dashboard",
            ),
        ),
        migrations.AddField(
            model_name="serverinventoryconfiguration",
            name="dashboard_enabled_only",
            field=models.BooleanField(
                default=True,
                verbose_name="Mostrar sólo equipos habilitados en el dashboard",
            ),
        ),
        migrations.AddField(
            model_name="serverinventoryconfiguration",
            name="dashboard_page_size",
            field=models.PositiveSmallIntegerField(
                default=25,
                verbose_name="Filas por página en el dashboard",
            ),
        ),
        migrations.AddField(
            model_name="serverinventoryconfiguration",
            name="dashboard_period_days",
            field=models.PositiveSmallIntegerField(
                default=7,
                help_text="Cantidad de días usada inicialmente para medir descubrimientos e ingestas.",
                verbose_name="Período predeterminado del dashboard (días)",
            ),
        ),
        migrations.AddField(
            model_name="serverinventoryconfiguration",
            name="ingestion_sla_days",
            field=models.PositiveSmallIntegerField(
                default=3,
                help_text=(
                    "Un equipo pendiente supera el SLA cuando pasa esta cantidad de días "
                    "sin aparecer en SIEM."
                ),
                verbose_name="SLA máximo de ingesta (días)",
            ),
        ),
        migrations.RunPython(backfill_first_seen, migrations.RunPython.noop),
    ]
