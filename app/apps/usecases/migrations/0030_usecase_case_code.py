from django.db import migrations, models


def populate_case_code(apps, schema_editor):
    UseCase = apps.get_model("usecases", "UseCase")
    for item in UseCase.objects.filter(case_code="").only("id", "name", "case_code"):
        item.case_code = (item.name or "").strip()
        item.save(update_fields=["case_code"])


def clear_case_code(apps, schema_editor):
    UseCase = apps.get_model("usecases", "UseCase")
    UseCase.objects.update(case_code="")


class Migration(migrations.Migration):

    dependencies = [
        ("usecases", "0029_expand_usecase_group_device_lengths"),
    ]

    operations = [
        migrations.AddField(
            model_name="usecase",
            name="case_code",
            field=models.CharField(blank=True, db_index=True, default="", max_length=255, verbose_name="Identificador"),
        ),
        migrations.RunPython(populate_case_code, clear_case_code),
    ]
