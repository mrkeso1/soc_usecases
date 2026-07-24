import re

from .models import ServerAsset, ServerNamingRule


def classify_hostname(hostname: str) -> dict:
    result = {"os_family": ServerAsset.OS_UNKNOWN, "server_type": ServerAsset.TYPE_UNKNOWN, "matched_rules": []}
    for rule in ServerNamingRule.objects.filter(is_active=True).order_by("priority", "name"):
        try:
            matched = re.search(rule.pattern, hostname or "", flags=re.IGNORECASE)
        except re.error:
            continue
        if not matched:
            continue
        result["matched_rules"].append(rule.name)
        if rule.os_family and result["os_family"] == ServerAsset.OS_UNKNOWN:
            result["os_family"] = rule.os_family
        if rule.server_type and result["server_type"] == ServerAsset.TYPE_UNKNOWN:
            result["server_type"] = rule.server_type
        if result["os_family"] != ServerAsset.OS_UNKNOWN and result["server_type"] != ServerAsset.TYPE_UNKNOWN:
            break
    return result


def apply_automatic_classification(asset: ServerAsset, *, save=True) -> ServerAsset:
    if asset.classification_source != ServerAsset.CLASSIFICATION_AUTO:
        return asset
    classification = classify_hostname(asset.hostname)
    if classification["os_family"] != ServerAsset.OS_UNKNOWN:
        asset.os_family = classification["os_family"]
    if classification["server_type"] != ServerAsset.TYPE_UNKNOWN:
        asset.server_type = classification["server_type"]
    if save:
        asset.save(update_fields=["os_family", "server_type", "updated_at"])
    return asset
