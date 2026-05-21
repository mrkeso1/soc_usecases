# Generated manually for business-rule validations.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("usecases", "0021_alter_d3fend_options_alter_mitreattack_options_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="usecase",
            name="disabled_reason",
            field=models.TextField(
                "Motivo de deshabilitación",
                blank=True,
                default="",
                help_text="Motivo obligatorio cuando el caso de uso se deshabilita.",
            ),
        ),
    ]
