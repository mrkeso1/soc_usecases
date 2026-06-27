from dataclasses import dataclass, field

from django.db import transaction

from apps.mitre.models import MitreAttack

from .models import UseCase, UseCaseChangeLog
from .permissions import can_manage_usecases, resolve_user_roles


PRODUCTION_STATUS = UseCase.STATUS_PRODUCTION


@dataclass
class BulkUpdateResult:
    updated_count: int = 0
    errors: list[str] = field(default_factory=list)


def parse_csv_ids(raw_value: str) -> list[int]:
    if not raw_value:
        return []
    return [int(x) for x in raw_value.split(",") if x.strip().isdigit()]


def parse_posted_usecase_ids(post_data) -> list[int]:
    if "changed_ids" in post_data:
        return parse_csv_ids(post_data.get("changed_ids", ""))
    return [int(x) for x in post_data.getlist("uc_ids") if str(x).isdigit()]


def update_usecases_bulk(
    *,
    user,
    post_data,
    parse_date,
    validate_usecase,
    snapshot_usecase,
) -> BulkUpdateResult:
    usecase_ids = parse_posted_usecase_ids(post_data)
    result = BulkUpdateResult()
    if not usecase_ids:
        return result

    usecases = (
        UseCase.objects
        .filter(pk__in=usecase_ids, status__iexact=PRODUCTION_STATUS)
        .prefetch_related("mitre_attacks", "d3fends")
        .order_by("name")
    )

    roles = resolve_user_roles(user)

    with transaction.atomic():
        for usecase in usecases:
            if not can_manage_usecases(user, usecase, _roles=roles):
                continue

            pk = str(usecase.pk)
            old_data = snapshot_usecase(usecase)
            saved_last_review = usecase.last_review_date
            saved_next_review = usecase.next_review_date

            scalar_changes = {
                "owner_name": post_data.get(f"owner_name_{pk}", "").strip(),
                "severity": post_data.get(f"severity_{pk}", "").strip(),
                "last_validation_date": parse_date(
                    post_data.get(f"last_validation_date_{pk}", "").strip()
                ),
                "is_enabled": post_data.get(f"is_enabled_{pk}") == "on",
            }
            if f"status_{pk}" in post_data:
                scalar_changes["status"] = post_data.get(f"status_{pk}", "").strip()
            if f"validation_status_{pk}" in post_data:
                scalar_changes["validation_status"] = post_data.get(f"validation_status_{pk}", "").strip()
            if f"validation_result_{pk}" in post_data:
                scalar_changes["validation_result"] = post_data.get(f"validation_result_{pk}", "").strip()
            if f"disabled_reason_{pk}" in post_data:
                scalar_changes["disabled_reason"] = post_data.get(f"disabled_reason_{pk}", "").strip()

            changed_fields = []
            for field_name, new_value in scalar_changes.items():
                if getattr(usecase, field_name) != new_value:
                    setattr(usecase, field_name, new_value)
                    changed_fields.append(field_name)

            usecase.last_review_date = saved_last_review
            usecase.next_review_date = saved_next_review

            current_mitre_ids = {item.id for item in usecase.mitre_attacks.all()}
            posted_mitre_ids = set(parse_csv_ids(post_data.get(f"mitre_attack_ids_{pk}", "")))

            errors = validate_usecase(usecase, mitre_ids=posted_mitre_ids)
            if errors:
                result.errors.append(f"{usecase.name}: " + " ".join(errors))
                continue

            m2m_changed = False
            if current_mitre_ids != posted_mitre_ids:
                usecase.mitre_attacks.set(MitreAttack.objects.filter(id__in=posted_mitre_ids))
                m2m_changed = True
            if usecase.sync_d3fends_from_attacks():
                m2m_changed = True

            if changed_fields or m2m_changed:
                usecase.updated_by = user
                if changed_fields:
                    usecase.save()
                else:
                    usecase.save(update_fields=["updated_by", "updated_at"])
                new_data = snapshot_usecase(usecase)
                UseCaseChangeLog.create_diff(usecase, old_data, new_data, user)
                result.updated_count += 1

    return result
