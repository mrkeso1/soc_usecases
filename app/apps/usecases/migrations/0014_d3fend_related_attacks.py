from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("usecases", "0013_dashboardreportsettings"),
    ]

    operations = [
        migrations.AddField(
            model_name="d3fend",
            name="related_attacks",
            field=models.ManyToManyField(
                blank=True,
                help_text="Relación inferida por D3FEND entre esta técnica defensiva y técnicas ATT&CK.",
                related_name="related_d3fends",
                to="usecases.mitreattack",
                verbose_name="ATT&CK relacionados por D3FEND",
            ),
        ),
    ]
