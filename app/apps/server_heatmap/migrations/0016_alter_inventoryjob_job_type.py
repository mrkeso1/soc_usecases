from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("server_heatmap", "0015_rename_exclude_action_label"),
    ]

    operations = [
        migrations.AlterField(
            model_name="inventoryjob",
            name="job_type",
            field=models.CharField(
                choices=[
                    ("full_sync", "Actualizar AD y SIEM"),
                    ("reprocess", "Cruzar inventario almacenado"),
                    ("apply_filters", "Aplicar filtros"),
                    ("network_diagnostic", "Diagnosticar conectividad"),
                ],
                db_index=True,
                max_length=30,
                verbose_name="Tipo",
            ),
        ),
    ]
