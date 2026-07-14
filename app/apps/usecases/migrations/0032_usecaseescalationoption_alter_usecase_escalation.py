from django.db import migrations, models


def seed_default_escalations(apps, schema_editor):
    UseCaseEscalationOption = apps.get_model("usecases", "UseCaseEscalationOption")
    defaults = [
        ("IRT", 10),
        ("SOC", 20),
        ("Otro", 30),
    ]
    for name, position in defaults:
        UseCaseEscalationOption.objects.get_or_create(
            name=name,
            defaults={"position": position, "is_active": True},
        )


def unseed_default_escalations(apps, schema_editor):
    UseCaseEscalationOption = apps.get_model("usecases", "UseCaseEscalationOption")
    UseCaseEscalationOption.objects.filter(name__in=["IRT", "SOC", "Otro"]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("usecases", "0031_usecase_d3fend_exclusions"),
    ]

    operations = [
        migrations.CreateModel(
            name="UseCaseEscalationOption",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=100, unique=True, verbose_name="Nombre")),
                ("is_active", models.BooleanField(default=True, verbose_name="Activo")),
                ("position", models.PositiveIntegerField(default=100, verbose_name="Orden")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Escalamiento",
                "verbose_name_plural": "Escalamientos",
                "ordering": ["position", "name"],
            },
        ),
        migrations.AlterField(
            model_name="usecase",
            name="escalation",
            field=models.CharField(blank=True, max_length=100, verbose_name="Escalamiento"),
        ),
        migrations.RunPython(seed_default_escalations, unseed_default_escalations),
    ]
