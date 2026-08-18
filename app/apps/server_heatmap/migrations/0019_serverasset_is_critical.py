from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("server_heatmap", "0018_restore_full_ad_computer_scope"),
    ]

    operations = [
        migrations.AddField(
            model_name="serverasset",
            name="is_critical",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "Marca manual independiente de la sección, el ambiente y "
                    "las fuentes de inventario."
                ),
                verbose_name="Servidor crítico",
            ),
        ),
    ]
