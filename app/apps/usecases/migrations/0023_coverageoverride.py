# Generated manually for SOC Use Cases Manager

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("usecases", "0022_usecase_disabled_reason"),
    ]

    operations = [
        migrations.CreateModel(
            name="CoverageOverride",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("framework", models.CharField(choices=[("ATTACK", "ATT&CK"), ("D3FEND", "D3FEND")], max_length=12, verbose_name="Framework")),
                ("object_type", models.CharField(choices=[("tactic", "Táctica ATT&CK"), ("technique", "Técnica"), ("category", "Categoría D3FEND")], max_length=20, verbose_name="Tipo de objeto")),
                ("object_key", models.CharField(max_length=160, verbose_name="Clave")),
                ("object_name", models.CharField(blank=True, default="", max_length=255, verbose_name="Nombre")),
                ("status", models.CharField(choices=[("enabled", "Habilitada"), ("fulfilled", "Cumplida por herramienta"), ("disabled", "Deshabilitada / no aplica")], default="enabled", max_length=20, verbose_name="Estado")),
                ("reason", models.TextField(blank=True, default="", help_text="Obligatorio si se marca como cumplida por herramienta o deshabilitada/no aplica.", verbose_name="Motivo / evidencia")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("updated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="coverage_overrides_updated", to=settings.AUTH_USER_MODEL, verbose_name="Actualizado por")),
            ],
            options={
                "verbose_name": "Override de cobertura",
                "verbose_name_plural": "Overrides de cobertura",
                "ordering": ["framework", "object_type", "object_key"],
            },
        ),
        migrations.AddConstraint(
            model_name="coverageoverride",
            constraint=models.UniqueConstraint(fields=("framework", "object_type", "object_key"), name="unique_coverage_override_target"),
        ),
    ]
