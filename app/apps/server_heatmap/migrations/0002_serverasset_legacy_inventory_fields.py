from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("server_heatmap", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="serverasset",
            name="inventory_source",
            field=models.CharField(blank=True, max_length=40, verbose_name="Origen del inventario"),
        ),
        migrations.AddField(
            model_name="serverasset",
            name="legacy_classification",
            field=models.CharField(blank=True, max_length=80, verbose_name="Clasificación anterior"),
        ),
        migrations.AddField(
            model_name="serverasset",
            name="organizational_unit",
            field=models.CharField(blank=True, max_length=500, verbose_name="Unidad organizativa (OU)"),
        ),
        migrations.AddField(
            model_name="serverasset",
            name="os_name",
            field=models.CharField(blank=True, max_length=180, verbose_name="Sistema operativo informado"),
        ),
        migrations.AddField(
            model_name="serverasset",
            name="siem_groups",
            field=models.TextField(blank=True, verbose_name="Grupos SIEM"),
        ),
    ]
