from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("mitre", "0003_alter_mitreattacksyncsettings_last_run_at_and_more"),
        ("usecases", "0030_usecase_case_code"),
    ]

    operations = [
        migrations.AddField(
            model_name="usecase",
            name="d3fend_exclusions",
            field=models.ManyToManyField(
                blank=True,
                related_name="excluded_from_use_cases",
                to="mitre.d3fend",
                verbose_name="D3FEND excluido para este caso",
            ),
        ),
    ]
