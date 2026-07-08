from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("usecases", "0028_usecase_full_rule_text_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="usecase",
            name="device",
            field=models.CharField(blank=True, max_length=255, verbose_name="Dispositivo"),
        ),
        migrations.AlterField(
            model_name="usecase",
            name="group_name",
            field=models.CharField(blank=True, max_length=255, verbose_name="Grupo"),
        ),
    ]
