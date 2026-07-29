from django.db import migrations, models


ACTION_CHOICES = [
    ("exclude", "Deshabilitar"),
    ("include", "Habilitar"),
    ("classify", "Clasificar"),
]


class Migration(migrations.Migration):
    dependencies = [
        ("server_heatmap", "0014_serverasset_is_excluded_by_rule"),
    ]

    operations = [
        migrations.AlterField(
            model_name="inventoryfilterdecision",
            name="action",
            field=models.CharField(
                choices=ACTION_CHOICES,
                max_length=20,
                verbose_name="Acción",
            ),
        ),
        migrations.AlterField(
            model_name="inventoryfilterrule",
            name="action",
            field=models.CharField(
                choices=ACTION_CHOICES,
                max_length=20,
                verbose_name="Acción",
            ),
        ),
    ]
