# Generated manually for lifecycle review history and active policy guard.

import datetime
from django.conf import settings
from django.db import migrations, models
from django.db.models import Q
import django.db.models.deletion


def keep_latest_active_lifecycle_settings(apps, schema_editor):
    LifecycleSettings = apps.get_model("usecases", "LifecycleSettings")
    active_ids = list(
        LifecycleSettings.objects.filter(is_active=True)
        .order_by("-id")
        .values_list("id", flat=True)
    )
    if len(active_ids) > 1:
        LifecycleSettings.objects.filter(id__in=active_ids[1:]).update(is_active=False)


class Migration(migrations.Migration):

    dependencies = [
        ("usecases", "0010_usecase_lifecycle_control_owner_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="LifecycleReview",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("status", models.CharField(default="Finalizado", max_length=20, verbose_name="Estado")),
                ("result", models.CharField(blank=True, default="", max_length=20, verbose_name="Resultado")),
                ("notes", models.TextField(blank=True, verbose_name="Notas")),
                ("checked_at", models.DateField(default=datetime.date.today, verbose_name="Fecha control")),
                ("next_review_date", models.DateField(blank=True, null=True, verbose_name="Próximo control")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("completed_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="lifecycle_reviews_completed", to=settings.AUTH_USER_MODEL, verbose_name="Finalizado por")),
                ("control_owner", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="lifecycle_reviews_owned", to=settings.AUTH_USER_MODEL, verbose_name="Responsable control")),
                ("use_case", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="lifecycle_reviews", to="usecases.usecase", verbose_name="Caso de uso")),
            ],
            options={
                "verbose_name": "Historial de revisión",
                "verbose_name_plural": "Historial de revisiones",
                "ordering": ["-checked_at", "-created_at"],
            },
        ),
        migrations.RunPython(keep_latest_active_lifecycle_settings, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="lifecyclesettings",
            constraint=models.UniqueConstraint(condition=Q(is_active=True), fields=("is_active",), name="unique_active_lifecycle_settings"),
        ),
    ]
