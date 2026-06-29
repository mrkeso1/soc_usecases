# Generated manually for app split without physical table changes.

from django.db import migrations, models


CONTENT_TYPE_MOVES = [
    ("usecases", "dashboardreportsettings", "dashboard"),
    ("usecases", "lifecyclesettings", "lifecycle"),
    ("usecases", "lifecyclereview", "lifecycle"),
    ("usecases", "mitreattack", "mitre"),
    ("usecases", "d3fend", "mitre"),
    ("usecases", "coverageoverride", "mitre"),
    ("usecases", "mitreattacksyncsettings", "mitre"),
]


def move_content_types(apps, schema_editor):
    ContentType = apps.get_model("contenttypes", "ContentType")
    for old_app, model, new_app in CONTENT_TYPE_MOVES:
        old = ContentType.objects.filter(app_label=old_app, model=model).first()
        if not old:
            continue
        target = ContentType.objects.filter(app_label=new_app, model=model).first()
        if target:
            old.permission_set.update(content_type=target)
            old.delete()
            continue
        old.app_label = new_app
        old.save(update_fields=["app_label"])


def reverse_content_types(apps, schema_editor):
    ContentType = apps.get_model("contenttypes", "ContentType")
    for old_app, model, new_app in CONTENT_TYPE_MOVES:
        current = ContentType.objects.filter(app_label=new_app, model=model).first()
        if current:
            current.app_label = old_app
            current.save(update_fields=["app_label"])


class Migration(migrations.Migration):

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("dashboard", "0001_initial"),
        ("lifecycle", "0001_initial"),
        ("mitre", "0001_initial"),
        ("usecases", "0025_alter_mitreattacksyncsettings_options"),
    ]

    operations = [
        migrations.RunPython(move_content_types, reverse_content_types),
        migrations.SeparateDatabaseAndState(
            database_operations=[],
            state_operations=[
                migrations.AlterField(
                    model_name="usecase",
                    name="blocking_type",
                    field=models.CharField(blank=True, choices=[("Manual", "Manual"), ("AutomÃ¡tico", "AutomÃ¡tico"), ("SemiautomÃ¡tico", "SemiautomÃ¡tico")], max_length=20, verbose_name="Tipo de bloqueo"),
                ),
                migrations.AlterField(
                    model_name="usecase",
                    name="d3fends",
                    field=models.ManyToManyField(blank=True, related_name="use_cases", to="mitre.d3fend", verbose_name="D3FEND relacionado"),
                ),
                migrations.AlterField(
                    model_name="usecase",
                    name="disabled_reason",
                    field=models.TextField(blank=True, default="", help_text="Motivo obligatorio cuando el caso de uso se deshabilita.", verbose_name="Motivo de deshabilitaciÃ³n"),
                ),
                migrations.AlterField(
                    model_name="usecase",
                    name="last_review_date",
                    field=models.DateField(blank=True, null=True, verbose_name="Ãšltima revisiÃ³n"),
                ),
                migrations.AlterField(
                    model_name="usecase",
                    name="last_validation_date",
                    field=models.DateField(blank=True, null=True, verbose_name="Ãšltima validaciÃ³n"),
                ),
                migrations.AlterField(
                    model_name="usecase",
                    name="mitre_attacks",
                    field=models.ManyToManyField(blank=True, related_name="use_cases", to="mitre.mitreattack", verbose_name="MITRE ATT&CK relacionado"),
                ),
                migrations.AlterField(
                    model_name="usecase",
                    name="next_review_date",
                    field=models.DateField(blank=True, null=True, verbose_name="PrÃ³xima revisiÃ³n"),
                ),
                migrations.AlterField(
                    model_name="usecase",
                    name="production_date",
                    field=models.DateField(blank=True, null=True, verbose_name="Fecha puesta en producciÃ³n"),
                ),
                migrations.AlterField(
                    model_name="usecase",
                    name="sent_to_ho",
                    field=models.CharField(blank=True, choices=[("SÃ­", "SÃ­"), ("No", "No")], max_length=3, verbose_name="EnvÃ­o HO"),
                ),
                migrations.AlterField(
                    model_name="usecase",
                    name="status",
                    field=models.CharField(blank=True, choices=[("Test", "Test"), ("ProducciÃ³n", "ProducciÃ³n"), ("Desarrollo", "Desarrollo"), ("Baja", "Baja"), ("Propuesta", "Propuesta")], max_length=20, verbose_name="Estado"),
                ),
                migrations.AlterField(
                    model_name="usecase",
                    name="validation_result",
                    field=models.CharField(choices=[("Nada", "Nada"), ("OK", "OK"), ("Advertencia", "Advertencia"), ("FallÃ³", "FallÃ³")], default="Nada", max_length=20, verbose_name="Resultado"),
                ),
                migrations.AlterField(
                    model_name="usecase",
                    name="validation_status",
                    field=models.CharField(choices=[("Finalizado", "Finalizado"), ("En progreso", "En progreso"), ("No realizado", "No realizado")], default="No realizado", max_length=20, verbose_name="Estado de validaciÃ³n"),
                ),
                migrations.DeleteModel(name="DashboardReportSettings"),
                migrations.DeleteModel(name="LifecycleSettings"),
                migrations.DeleteModel(name="MitreAttackSyncSettings"),
                migrations.DeleteModel(name="LifecycleReview"),
                migrations.DeleteModel(name="CoverageOverride"),
                migrations.DeleteModel(name="D3Fend"),
                migrations.DeleteModel(name="MitreAttack"),
            ],
        ),
    ]
