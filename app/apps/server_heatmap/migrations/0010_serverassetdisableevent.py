import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("server_heatmap", "0009_inventoryfilterrule_inventoryfilterdecision"),
    ]

    operations = [
        migrations.CreateModel(
            name="ServerAssetDisableEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("hostname", models.CharField(max_length=255, verbose_name="Hostname registrado")),
                ("justification", models.TextField(verbose_name="Justificación")),
                ("previous_enabled", models.BooleanField(default=True, verbose_name="Estado anterior")),
                ("new_enabled", models.BooleanField(default=False, verbose_name="Estado nuevo")),
                ("source_ip", models.GenericIPAddressField(blank=True, null=True, verbose_name="IP de origen")),
                ("user_agent", models.CharField(blank=True, max_length=500, verbose_name="Navegador")),
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Fecha")),
                ("actor", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="server_disable_events", to=settings.AUTH_USER_MODEL, verbose_name="Usuario")),
                ("asset", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="disable_events", to="server_heatmap.serverasset", verbose_name="Equipo")),
            ],
            options={
                "verbose_name": "Deshabilitación de servidor",
                "verbose_name_plural": "Deshabilitaciones de servidores",
                "ordering": ["-created_at"],
            },
        ),
    ]
