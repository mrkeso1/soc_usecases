from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("mitre", "0005_mitreattacksyncsettings_d3fend_catalog_base_url_and_more")]

    operations = [
        migrations.AddField(
            model_name="mitreattack",
            name="description",
            field=models.TextField(blank=True, default="", verbose_name="Descripción"),
        ),
        migrations.CreateModel(
            name="MitreAttackTactic",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("external_id", models.CharField(max_length=20, unique=True, verbose_name="ID ATT&CK")),
                ("short_name", models.CharField(max_length=100, unique=True, verbose_name="Nombre corto")),
                ("name", models.CharField(max_length=255, verbose_name="Nombre")),
                ("description", models.TextField(blank=True, default="", verbose_name="Descripción")),
            ],
            options={"verbose_name": "Táctica MITRE ATT&CK", "verbose_name_plural": "Tácticas MITRE ATT&CK", "ordering": ["external_id"]},
        ),
    ]
