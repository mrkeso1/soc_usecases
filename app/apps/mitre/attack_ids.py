import re

from django.db import models


ATTACK_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def normalize_attack_id(value: str) -> str:
    return str(value or "").strip().upper()


def parent_attack_id(value: str) -> str:
    attack_id = normalize_attack_id(value)
    if "." not in attack_id:
        return ""
    return attack_id.split(".", 1)[0]


def is_subtechnique_id(value: str) -> bool:
    attack_id = normalize_attack_id(value)
    return bool(ATTACK_TECHNIQUE_ID_RE.match(attack_id) and "." in attack_id)


def attack_family_query(external_ids) -> models.Q:
    """Build a query that matches selected ATT&CK IDs and their parent/sub-technique family."""
    normalized_ids = {
        normalize_attack_id(external_id)
        for external_id in external_ids or []
        if normalize_attack_id(external_id)
    }
    query = models.Q(pk__in=[])

    if normalized_ids:
        query |= models.Q(external_id__in=normalized_ids)

    parent_ids = {
        parent_attack_id(external_id)
        for external_id in normalized_ids
        if is_subtechnique_id(external_id)
    }
    parent_ids.discard("")
    if parent_ids:
        query |= models.Q(external_id__in=parent_ids)

    for external_id in normalized_ids:
        if ATTACK_TECHNIQUE_ID_RE.match(external_id) and not is_subtechnique_id(external_id):
            query |= models.Q(external_id__startswith=f"{external_id}.")

    return query


def resolve_attack_from_lookup(attack_id: str, attack_lookup: dict):
    """Resolve an ATT&CK ID against a lookup, falling back from sub-technique to parent."""
    normalized_id = normalize_attack_id(attack_id)
    if not normalized_id:
        return None

    attack = attack_lookup.get(normalized_id)
    if attack:
        return attack

    parent_id = parent_attack_id(normalized_id)
    if parent_id:
        return attack_lookup.get(parent_id)

    return None
