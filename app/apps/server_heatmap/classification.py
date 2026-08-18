from .inventory_filters import load_compiled_filters
from .models import InventoryFilterRule, ServerAsset


def active_classification_rules():
    rules = InventoryFilterRule.objects.filter(
        is_active=True,
        action=InventoryFilterRule.ACTION_CLASSIFY,
        field=InventoryFilterRule.FIELD_HOSTNAME,
    )
    return load_compiled_filters(rules=rules)


def classify_hostname(hostname: str, *, rules=None) -> dict:
    result = {
        "os_family": ServerAsset.OS_UNKNOWN,
        "server_type": ServerAsset.TYPE_UNKNOWN,
        "category": None,
        "matched_rules": [],
    }
    for compiled in active_classification_rules() if rules is None else rules:
        rule = compiled.rule
        if not compiled.matches(hostname):
            continue
        result["matched_rules"].append(rule.name)
        if rule.os_family and result["os_family"] == ServerAsset.OS_UNKNOWN:
            result["os_family"] = rule.os_family
        if (
            rule.server_type_value
            and result["server_type"] == ServerAsset.TYPE_UNKNOWN
        ):
            result["server_type"] = rule.server_type_value
        if rule.category and result["category"] is None:
            result["category"] = rule.category
        if (
            result["os_family"] != ServerAsset.OS_UNKNOWN
            and (result["category"] is not None or result["server_type"] != ServerAsset.TYPE_UNKNOWN)
        ):
            break
    return result


def apply_automatic_classification(
    asset: ServerAsset,
    *,
    save=True,
    rules=None,
) -> ServerAsset:
    # Precedencia absoluta: una clasificación manual nunca puede ser
    # reemplazada por AD, SIEM, reglas ni reprocesamientos automáticos.
    if asset.classification_source == ServerAsset.CLASSIFICATION_MANUAL:
        return asset
    classification = classify_hostname(asset.hostname, rules=rules)
    if classification["os_family"] != ServerAsset.OS_UNKNOWN:
        asset.os_family = classification["os_family"]
    if classification["server_type"] != ServerAsset.TYPE_UNKNOWN:
        asset.server_type = classification["server_type"]
    if classification["category"] is not None:
        asset.category = classification["category"]
    if save:
        asset.save(update_fields=["os_family", "server_type", "category", "updated_at"])
    return asset
