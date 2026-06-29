def serialize_mitre(usecase) -> str:
    return ", ".join(
        f"{item.external_id} - {item.name}" if item.name else str(item.external_id)
        for item in usecase.mitre_attacks.all().order_by("external_id", "name")
    )


def serialize_d3fend(usecase) -> str:
    inferred = getattr(usecase, "inferred_d3fends", None)
    if inferred is None:
        inferred = usecase.inferred_d3fends_queryset()

    return ", ".join(
        f"{item.code} - {item.name}" if item.name else str(item.code)
        for item in inferred
    )


def serialize_user(user) -> str:
    if not user:
        return ""

    full_name = ""
    if hasattr(user, "get_full_name"):
        full_name = (user.get_full_name() or "").strip()

    username = (getattr(user, "username", "") or "").strip()

    if full_name and username:
        return f"{full_name} ({username})"
    return full_name or username or str(user)


def serialize_rule_conditions(usecase) -> str:
    return " | ".join(
        (
            f"{item.position}. {item.get_condition_type_display()}: "
            f"{item.field_name} {item.get_operator_display()} {item.value}"
        ).strip()
        for item in usecase.rule_conditions.all().order_by("position", "id")
    )


def snapshot_usecase(usecase) -> dict:
    return {
        "name": usecase.name,
        "group_name": usecase.group_name,
        "device": usecase.device,
        "case_type": usecase.case_type,
        "objective": usecase.objective,
        "blocking_type": usecase.blocking_type,
        "owner_name": usecase.owner_name,
        "lifecycle_control_owner": serialize_user(usecase.lifecycle_control_owner),
        "monitoring": usecase.monitoring,
        "status": usecase.status,
        "created_or_adjusted_at": usecase.created_or_adjusted_at,
        "production_date": usecase.production_date,
        "mitre_attacks": serialize_mitre(usecase),
        "d3fends": serialize_d3fend(usecase),
        "severity": usecase.severity,
        "escalation": usecase.escalation,
        "sent_to_ho": usecase.sent_to_ho,
        "ho_flag": usecase.ho_flag,
        "last_validation_date": usecase.last_validation_date,
        "validation_status": usecase.validation_status,
        "validation_result": usecase.validation_result,
        "is_enabled": usecase.is_enabled,
        "disabled_reason": usecase.disabled_reason,
        "last_review_date": usecase.last_review_date,
        "next_review_date": usecase.next_review_date,
        "comments": usecase.comments,
        "full_rule_text": usecase.full_rule_text,
        "functional_description": usecase.functional_description,
        "rule_conditions": serialize_rule_conditions(usecase),
    }
