from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("server_heatmap", "0013_unify_inventory_rules_and_retention"),
    ]

    operations = [
        migrations.AddField(
            model_name="serverasset",
            name="is_excluded_by_rule",
            field=models.BooleanField(
                default=False,
                editable=False,
                help_text=(
                    "Se recalcula automáticamente al aplicar las reglas de inventario. "
                    "No reemplaza una deshabilitación manual."
                ),
                verbose_name="Excluido por regla",
            ),
        ),
    ]
