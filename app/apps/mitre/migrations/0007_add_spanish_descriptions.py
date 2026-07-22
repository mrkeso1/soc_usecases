from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("mitre", "0006_mitreattack_description_mitreattacktactic")]

    operations = [
        migrations.AddField(
            model_name="mitreattack",
            name="translated_description",
            field=models.TextField(blank=True, default="", verbose_name="Descripción en castellano"),
        ),
        migrations.AddField(
            model_name="mitreattacktactic",
            name="translated_description",
            field=models.TextField(blank=True, default="", verbose_name="Descripción en castellano"),
        ),
        migrations.AddField(
            model_name="d3fend",
            name="translated_description",
            field=models.TextField(blank=True, default="", help_text="Traducción local importada. No es sobrescrita por la sincronización oficial.", verbose_name="Descripción en castellano"),
        ),
    ]
