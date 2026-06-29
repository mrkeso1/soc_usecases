from django.db import migrations, models


SOURCE_TYPES = [
    ("siem", "SIEM"),
    ("edr", "EDR"),
    ("firewall", "Firewall"),
    ("identity", "Identidad"),
    ("cloud", "Cloud"),
    ("network", "Red"),
    ("application", "Aplicacion"),
    ("other", "Otro"),
]


def seed_source_types(apps, schema_editor):
    SourceType = apps.get_model("sources", "SourceType")
    for code, name in SOURCE_TYPES:
        SourceType.objects.get_or_create(
            code=code,
            defaults={"name": name, "is_active": True},
        )


def unseed_source_types(apps, schema_editor):
    SourceType = apps.get_model("sources", "SourceType")
    SourceType.objects.filter(code__in=[code for code, _name in SOURCE_TYPES]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("sources", "0004_remove_sourcecategory_unique_source_category_parent_name_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="SourceType",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("code", models.SlugField(max_length=40, unique=True, verbose_name="Codigo")),
                ("name", models.CharField(max_length=80, unique=True, verbose_name="Nombre")),
                ("description", models.TextField(blank=True, verbose_name="Descripcion")),
                ("is_active", models.BooleanField(default=True, verbose_name="Activo")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Tipo de fuente",
                "verbose_name_plural": "Tipos de fuentes",
                "ordering": ["name"],
            },
        ),
        migrations.AlterField(
            model_name="eventsource",
            name="source_type",
            field=models.CharField(default="other", max_length=40, verbose_name="Tipo"),
        ),
        migrations.RunPython(seed_source_types, unseed_source_types),
    ]
