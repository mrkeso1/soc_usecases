from django.db import transaction
from django.db.models.signals import post_save, pre_delete, pre_save
from django.dispatch import receiver

from apps.auditlog.logging_context import actor_id_context, request_id_context

from .models import (
    InventoryFilterRule,
    InventoryRuleRevision,
    ServerCategory,
    ServerNamingRule,
)


NAMING_FIELDS = (
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
FILTER_FIELDS = (
    "name",
    "source",
    "field",
    "operator",
    "pattern",
    "action",
    "category_id",
    "os_family",
    "server_type_value",
    "environment_value",
    "priority",
    "is_active",
    "reason",
)


def rule_type_for(instance):
    if isinstance(instance, ServerNamingRule):
        return InventoryRuleRevision.TYPE_NAMING
    if isinstance(instance, InventoryFilterRule):
        return InventoryRuleRevision.TYPE_FILTER
    raise TypeError(f"Tipo de regla no versionable: {type(instance)!r}")


def snapshot_rule(instance):
    fields = NAMING_FIELDS if isinstance(instance, ServerNamingRule) else FILTER_FIELDS
    snapshot = {field: getattr(instance, field) for field in fields}
    snapshot["category"] = instance.category.name if instance.category_id else ""
    return snapshot


def changed_fields(before, after):
    keys = set(before) | set(after)
    return sorted(key for key in keys if before.get(key) != after.get(key))


def record_rule_revision(instance, *, action, before=None, after=None):
    before = before or {}
    after = after or {}
    differences = changed_fields(before, after)
    if action == InventoryRuleRevision.ACTION_UPDATED and not differences:
        return None

    rule_type = rule_type_for(instance)
    rule_name = after.get("name") or before.get("name") or instance.name
    with transaction.atomic():
        latest = (
            InventoryRuleRevision.objects.select_for_update()
            .filter(rule_type=rule_type, rule_object_id=instance.pk)
            .order_by("-version")
            .first()
        )
        version = latest.version + 1 if latest else 1
        return InventoryRuleRevision.objects.create(
            rule_type=rule_type,
            rule_object_id=instance.pk,
            rule_name=rule_name,
            version=version,
            action=action,
            before_snapshot=before,
            after_snapshot=after,
            changed_fields=differences,
            changed_by_id=actor_id_context.get(),
            request_id=request_id_context.get(),
        )


def _capture_before(sender, instance, raw=False, **kwargs):
    if raw or not instance.pk:
        instance._revision_before_snapshot = {}
        return
    previous = sender.objects.select_related("category").filter(pk=instance.pk).first()
    instance._revision_before_snapshot = snapshot_rule(previous) if previous else {}


def _capture_after(sender, instance, created, raw=False, **kwargs):
    if raw:
        return
    before = getattr(instance, "_revision_before_snapshot", {})
    after = snapshot_rule(instance)
    record_rule_revision(
        instance,
        action=(
            InventoryRuleRevision.ACTION_CREATED
            if created
            else InventoryRuleRevision.ACTION_UPDATED
        ),
        before=before,
        after=after,
    )


def _capture_delete(sender, instance, **kwargs):
    record_rule_revision(
        instance,
        action=InventoryRuleRevision.ACTION_DELETED,
        before=snapshot_rule(instance),
        after={},
    )


pre_save.connect(
    _capture_before,
    sender=ServerNamingRule,
    dispatch_uid="server_naming_rule_revision_before",
)
post_save.connect(
    _capture_after,
    sender=ServerNamingRule,
    dispatch_uid="server_naming_rule_revision_after",
)
pre_delete.connect(
    _capture_delete,
    sender=ServerNamingRule,
    dispatch_uid="server_naming_rule_revision_delete",
)
pre_save.connect(
    _capture_before,
    sender=InventoryFilterRule,
    dispatch_uid="inventory_filter_rule_revision_before",
)
post_save.connect(
    _capture_after,
    sender=InventoryFilterRule,
    dispatch_uid="inventory_filter_rule_revision_after",
)
pre_delete.connect(
    _capture_delete,
    sender=InventoryFilterRule,
    dispatch_uid="inventory_filter_rule_revision_delete",
)


@receiver(
    pre_delete,
    sender=ServerCategory,
    dispatch_uid="inventory_rule_revision_category_delete",
)
def capture_category_removal(sender, instance, **kwargs):
    related_rules = [
        *instance.naming_rules.select_related("category"),
        *instance.inventory_filter_rules.select_related("category"),
    ]
    for rule in related_rules:
        before = snapshot_rule(rule)
        after = {**before, "category_id": None, "category": ""}
        record_rule_revision(
            rule,
            action=InventoryRuleRevision.ACTION_UPDATED,
            before=before,
            after=after,
        )
