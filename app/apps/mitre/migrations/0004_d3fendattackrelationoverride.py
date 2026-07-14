from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("mitre", "0003_alter_mitreattacksyncsettings_last_run_at_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="D3FendAttackRelationOverride",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "action",
                    models.CharField(
                        choices=[("exclude", "Excluir relacion")],
                        default="exclude",
                        max_length=20,
                        verbose_name="Accion",
                    ),
                ),
                (
                    "reason",
                    models.TextField(
                        help_text="Explica por que esta relacion oficial no aplica al modelo SOC local.",
                        verbose_name="Motivo",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "attack",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="d3fend_relation_overrides",
                        to="mitre.mitreattack",
                        verbose_name="ATT&CK",
                    ),
                ),
                (
                    "d3fend",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="attack_relation_overrides",
                        to="mitre.d3fend",
                        verbose_name="D3FEND",
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="d3fend_attack_relation_overrides_updated",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="Actualizado por",
                    ),
                ),
            ],
            options={
                "verbose_name": "Override relacion D3FEND-ATT&CK",
                "verbose_name_plural": "Overrides relaciones D3FEND-ATT&CK",
                "db_table": "usecases_d3fend_attack_relationoverride",
                "ordering": ["d3fend__code", "attack__external_id"],
            },
        ),
        migrations.AddConstraint(
            model_name="d3fendattackrelationoverride",
            constraint=models.UniqueConstraint(
                fields=("d3fend", "attack"),
                name="unique_d3fend_attack_relation_override",
            ),
        ),
    ]
