from django.db import migrations, models


def _available_name(FilterRule, original_name, legacy_id):
    candidate = original_name[:140]
    if not FilterRule.objects.filter(name=candidate).exists():
        return candidate
    suffix = f" (nomenclatura {legacy_id})"
    return f"{original_name[:140 - len(suffix)]}{suffix}"


def migrate_naming_rules(apps, schema_editor):
    NamingRule = apps.get_model("server_heatmap", "ServerNamingRule")
    FilterRule = apps.get_model("server_heatmap", "InventoryFilterRule")
    Revision = apps.get_model("server_heatmap", "InventoryRuleRevision")

    for legacy in NamingRule.objects.order_by("priority", "id").iterator():
        existing = FilterRule.objects.filter(
            legacy_naming_rule_id=legacy.pk,
        ).first()
        if existing:
            continue
        rule = FilterRule.objects.create(
            name=_available_name(FilterRule, legacy.name, legacy.pk),
            source="both",
            field="hostname",
            operator="regex" if legacy.match_type == "regex" else "wildcard",
            pattern=legacy.pattern,
            action="classify",
            category_id=legacy.category_id,
            os_family=legacy.os_family,
            server_type_value=legacy.server_type,
            priority=legacy.priority,
            is_active=legacy.is_active,
            reason=legacy.notes,
            legacy_naming_rule_id=legacy.pk,
        )
        snapshot = {
            "name": rule.name,
            "source": rule.source,
            "field": rule.field,
            "operator": rule.operator,
            "pattern": rule.pattern,
            "action": rule.action,
            "category_id": rule.category_id,
            "category": rule.category.name if rule.category_id else "",
            "os_family": rule.os_family,
            "server_type_value": rule.server_type_value,
            "environment_value": rule.environment_value,
            "priority": rule.priority,
            "is_active": rule.is_active,
            "reason": rule.reason,
        }
        Revision.objects.create(
            rule_type="filter",
            rule_object_id=rule.pk,
            rule_name=rule.name,
            version=1,
            action="baseline",
            before_snapshot={},
            after_snapshot=snapshot,
            changed_fields=sorted(snapshot),
        )


def restore_legacy_only(apps, schema_editor):
    FilterRule = apps.get_model("server_heatmap", "InventoryFilterRule")
    FilterRule.objects.filter(legacy_naming_rule_id__isnull=False).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("server_heatmap", "0012_inventoryrulerevision"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="inventoryfilterrule",
            options={
                "ordering": ["priority", "name"],
                "verbose_name": "Regla de inventario",
                "verbose_name_plural": "Reglas de inventario",
            },
        ),
        migrations.AlterModelOptions(
            name="servernamingrule",
            options={
                "ordering": ["priority", "name"],
                "verbose_name": "Nomenclatura anterior",
                "verbose_name_plural": "Nomenclaturas anteriores",
            },
        ),
        migrations.AlterField(
            model_name="inventoryrulerevision",
            name="rule_type",
            field=models.CharField(
                choices=[
                    ("naming", "Nomenclatura anterior"),
                    ("filter", "Regla de inventario"),
                ],
                max_length=20,
                verbose_name="Tipo de regla",
            ),
        ),
        migrations.AlterField(
            model_name="serverasset",
            name="classification_source",
            field=models.CharField(
                choices=[
                    ("auto", "Automática por reglas"),
                    ("manual", "Manual"),
                ],
                default="auto",
                max_length=20,
                verbose_name="Origen de clasificación",
            ),
        ),
        migrations.AddField(
            model_name="inventoryfilterrule",
            name="legacy_naming_rule_id",
            field=models.PositiveBigIntegerField(
                blank=True,
                editable=False,
                help_text="Referencia de transición para reglas migradas desde el motor anterior.",
                null=True,
                unique=True,
                verbose_name="ID de nomenclatura anterior",
            ),
        ),
        migrations.AddField(
            model_name="inventoryfilterrule",
            name="server_type_value",
            field=models.CharField(
                blank=True,
                choices=[
                    ("ad", "Domain Controllers"),
                    ("application", "Aplicaciones"),
                    ("database", "Base de datos"),
                    ("fileserver", "File server"),
                    ("web", "Web"),
                    ("mail", "Correo"),
                    ("security", "Seguridad"),
                    ("network", "Red / infraestructura"),
                    ("other", "Otro"),
                    ("unknown", "Sin identificar"),
                ],
                max_length=30,
                verbose_name="Tipo interno asignado",
            ),
        ),
        migrations.AddField(
            model_name="serverinventoryconfiguration",
            name="inventory_history_days",
            field=models.PositiveSmallIntegerField(
                default=180,
                help_text=(
                    "El mantenimiento elimina ejecuciones y observaciones más antiguas, "
                    "pero siempre conserva la última ejecución de cada origen. Use 0 para no eliminar."
                ),
                verbose_name="Conservar ejecuciones de inventario (días)",
            ),
        ),
        migrations.AddField(
            model_name="serverinventoryconfiguration",
            name="job_history_days",
            field=models.PositiveSmallIntegerField(
                default=90,
                help_text=(
                    "El mantenimiento elimina trabajos finalizados, fallidos o cancelados más antiguos. "
                    "Los trabajos activos nunca se eliminan. Use 0 para no eliminar."
                ),
                verbose_name="Conservar trabajos finalizados (días)",
            ),
        ),
        migrations.RunPython(migrate_naming_rules, restore_legacy_only),
    ]
