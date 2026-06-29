CONTROL_FIELDS = [
    "code",
    "name",
    "objective",
    "description",
    "mitigated_risk",
    "classification",
    "source_id",
    "status",
    "deployed_at",
    "control_conditions",
    "evidence",
    "owner",
    "review_frequency_days",
    "next_review_at",
]


def snapshot_control(control):
    data = {}
    for field in CONTROL_FIELDS:
        value = getattr(control, field)
        data[field] = str(value) if value is not None else ""
    data["use_cases"] = ", ".join(control.use_cases.order_by("name").values_list("name", flat=True)) if control.pk else ""
    return data


def diff_snapshots(previous, current):
    changes = {}
    for key, new_value in current.items():
        old_value = previous.get(key, "")
        if str(old_value) != str(new_value):
            changes[key] = {"old": old_value, "new": new_value}
    return changes


def record_control_change(control, previous_snapshot, actor, action):
    from .models import ControlInventoryChange, ControlVersion

    current_snapshot = snapshot_control(control)
    changes = {"created": {"old": "", "new": control.name}} if action == "created" else diff_snapshots(previous_snapshot, current_snapshot)
    if action == "updated" and not changes:
        return None

    if action == "updated":
        control.version += 1
        control.save(update_fields=["version", "updated_at"])

    version = ControlVersion.objects.create(
        control=control,
        version=control.version,
        changes=changes,
        snapshot=current_snapshot,
        created_by=actor if getattr(actor, "is_authenticated", False) else None,
    )
    ControlInventoryChange.objects.create(
        action=action,
        control=control,
        control_code=control.code,
        control_name=control.name,
        control_version=control.version,
        changes=changes,
        actor=actor if getattr(actor, "is_authenticated", False) else None,
    )
    return version

