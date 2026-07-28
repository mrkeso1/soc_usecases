import fnmatch
import re

from .models import ServerAsset, ServerNamingRule


def active_naming_rules():
    return list(ServerNamingRule.objects.filter(is_active=True).order_by("priority", "name"))


def classify_hostname(hostname: str, *, rules=None) -> dict:
    result = {
        "os_family": ServerAsset.OS_UNKNOWN,
        "server_type": ServerAsset.TYPE_UNKNOWN,
        "category": None,
        "matched_rules": [],
    }
    for rule in active_naming_rules() if rules is None else rules:
        if rule.match_type == ServerNamingRule.MATCH_WILDCARD:
            matched = fnmatch.fnmatch((hostname or "").lower(), rule.pattern.lower())
        else:
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
    force=False,
) -> ServerAsset:
    if not force and asset.classification_source != ServerAsset.CLASSIFICATION_AUTO:
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
