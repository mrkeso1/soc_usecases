import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def seed_rule_baselines(apps, schema_editor):
    NamingRule = apps.get_model("server_heatmap", "ServerNamingRule")
    FilterRule = apps.get_model("server_heatmap", "InventoryFilterRule")
    Category = apps.get_model("server_heatmap", "ServerCategory")
    Revision = apps.get_model("server_heatmap", "InventoryRuleRevision")
    categories = dict(Category.objects.values_list("id", "name"))
    revisions = []

    naming_fields = (
        "name",
        "pattern",
        "match_type",
        "os_family",
        "server_type",
        "category_id",
        "priority",
        "is_active",
        "notes",
    )
    for rule in NamingRule.objects.all().iterator():
        snapshot = {field: getattr(rule, field) for field in naming_fields}
        snapshot["category"] = categories.get(rule.category_id, "")
        revisions.append(
            Revision(
                rule_type="naming",
                rule_object_id=rule.pk,
                rule_name=rule.name,
                version=1,
                action="baseline",
                before_snapshot={},
                after_snapshot=snapshot,
                changed_fields=sorted(snapshot),
            )
        )

    filter_fields = (
        "name",
        "source",
        "field",
        "operator",
        "pattern",
        "action",
        "category_id",
        "os_family",
        "environment_value",
        "priority",
        "is_active",
        "reason",
    )
    for rule in FilterRule.objects.all().iterator():
        snapshot = {field: getattr(rule, field) for field in filter_fields}
        snapshot["category"] = categories.get(rule.category_id, "")
        revisions.append(
            Revision(
                rule_type="filter",
                rule_object_id=rule.pk,
                rule_name=rule.name,
                version=1,
                action="baseline",
                before_snapshot={},
                after_snapshot=snapshot,
                changed_fields=sorted(snapshot),
            )
        )

    Revision.objects.bulk_create(revisions, batch_size=500)


class Migration(migrations.Migration):
    dependencies = [
        ("server_heatmap", "0011_inventoryjob"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="InventoryRuleRevision",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "rule_type",
                    models.CharField(
                        choices=[
                            ("naming", "Regla de nomenclatura"),
                            ("filter", "Filtro de inventario"),
                        ],
                        max_length=20,
                        verbose_name="Tipo de regla",
                    ),
                ),
                ("rule_object_id", models.PositiveBigIntegerField(verbose_name="ID original")),
                ("rule_name", models.CharField(max_length=140, verbose_name="Nombre de la regla")),
                ("version", models.PositiveIntegerField(verbose_name="Versión")),
                (
                    "action",
                    models.CharField(
                        choices=[
                            ("baseline", "Estado inicial"),
                            ("created", "Creación"),
                            ("updated", "Modificación"),
                            ("deleted", "Eliminación"),
                        ],
                        max_length=20,
                        verbose_name="Acción",
                    ),
                ),
                ("before_snapshot", models.JSONField(blank=True, default=dict, verbose_name="Valores anteriores")),
                ("after_snapshot", models.JSONField(blank=True, default=dict, verbose_name="Valores nuevos")),
                ("changed_fields", models.JSONField(blank=True, default=list, verbose_name="Campos modificados")),
                ("request_id", models.CharField(blank=True, max_length=128, verbose_name="ID de solicitud")),
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Fecha")),
                (
                    "changed_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="inventory_rule_revisions",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="Modificado por",
                    ),
                ),
            ],
            options={
                "verbose_name": "Versión de regla de inventario",
                "verbose_name_plural": "Versiones de reglas de inventario",
                "ordering": ["-created_at", "-id"],
            },
        ),
        migrations.AddConstraint(
            model_name="inventoryrulerevision",
            constraint=models.UniqueConstraint(
                fields=("rule_type", "rule_object_id", "version"),
                name="uniq_inventory_rule_revision_version",
            ),
        ),
        migrations.AddIndex(
            model_name="inventoryrulerevision",
            index=models.Index(
                fields=["rule_type", "rule_object_id", "-version"],
                name="server_heat_rule_ty_ccbb00_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="inventoryrulerevision",
            index=models.Index(
                fields=["changed_by", "-created_at"],
                name="server_heat_changed_745781_idx",
            ),
        ),
        migrations.RunPython(seed_rule_baselines, migrations.RunPython.noop),
    ]
