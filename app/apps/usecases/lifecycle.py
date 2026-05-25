"""Lifecycle review period helpers."""

from collections import Counter
from datetime import date, timedelta

from django.contrib.auth import get_user_model

from .models import LifecycleReview, UseCase, UseCaseChangeLog
from .permissions import (
    can_assign_lifecycle_owner,
    can_finish_lifecycle_review,
    is_lifecycle_admin,
    resolve_user_roles,
)

# Current business cadence: three checkpoints per year.
LIFECYCLE_CHECKPOINTS = [(4, 30), (8, 31), (12, 31)]


def current_lifecycle_window(today: date):
    """Return the active lifecycle review window for a given date."""
    checkpoints = [date(today.year, month, day) for month, day in LIFECYCLE_CHECKPOINTS]
    for index, checkpoint in enumerate(checkpoints):
        if today <= checkpoint:
            start = date(today.year, 1, 1) if index == 0 else checkpoints[index - 1] + timedelta(days=1)
            return start, checkpoint
    start = checkpoints[-1] + timedelta(days=1)
    end = date(today.year + 1, 4, 30)
    return start, end


def build_lifecycle_management_context(user, query_params, *, today=None):
    today = today or date.today()
    cycle_start, cycle_end = current_lifecycle_window(today)
    only_pending = query_params.get("only_pending") == "1"
    lifecycle_admin = is_lifecycle_admin(user)

    usecases = list(
        UseCase.objects
        .select_related("lifecycle_control_owner")
        .filter(status__iexact=UseCase.STATUS_PRODUCTION)
        .order_by("name")
    )

    User = get_user_model()
    lifecycle_users = (
        User.objects.filter(is_active=True).order_by("username")
        if lifecycle_admin else User.objects.none()
    )

    roles = resolve_user_roles(user)
    can_assign = can_assign_lifecycle_owner(user, _roles=roles)
    rows = []
    completed_in_cycle = 0
    owner_pending_counter = Counter()

    for uc in usecases:
        last_check = uc.last_validation_date
        completed = bool(last_check and cycle_start <= last_check <= cycle_end)
        if completed:
            completed_in_cycle += 1

        review_days = uc.days_until_review
        if review_days is None:
            review_badge, review_level = "Sin fecha", "neutral"
        elif review_days < 0:
            review_badge, review_level = f"Vencido ({abs(review_days)}d)", "danger"
        elif review_days <= 15:
            review_badge, review_level = f"Por vencer ({review_days}d)", "warn"
        else:
            review_badge, review_level = f"Al dia ({review_days}d)", "ok"

        is_pending = not completed
        if is_pending:
            owner_key = (
                uc.lifecycle_control_owner.get_full_name() or uc.lifecycle_control_owner.username
                if uc.lifecycle_control_owner else "Sin responsable de control"
            )
            owner_pending_counter[owner_key] += 1

        if only_pending and not is_pending:
            continue

        if lifecycle_admin:
            can_finish_row = True
        else:
            can_finish_row = (
                not roles["is_readonly"]
                and (roles["is_analyst"] or user.has_perm("usecases.add_lifecyclereview"))
                and uc.lifecycle_control_owner_id == user.id
            )

        rows.append({
            "usecase": uc,
            "last_check": last_check,
            "next_check": uc.next_review_date,
            "owner": uc.lifecycle_control_owner,
            "task_status": "Finalizada" if completed else "Pendiente",
            "is_pending": is_pending,
            "can_finish": can_finish_row,
            "can_assign_owner": can_assign,
            "review_badge": review_badge,
            "review_level": review_level,
        })

    total = len(usecases)
    pending = total - completed_in_cycle

    return {
        "rows": rows,
        "cycle_start": cycle_start,
        "cycle_end": cycle_end,
        "summary_total": total,
        "summary_completed": completed_in_cycle,
        "summary_pending": pending,
        "summary_days_left": (cycle_end - today).days,
        "only_pending": only_pending,
        "owner_pending_summary": owner_pending_counter.most_common(5),
        "lifecycle_users": lifecycle_users,
        "can_manage_lifecycle": lifecycle_admin,
        "lifecycle_scope_label": (
            "Solo casos en Produccion" if lifecycle_admin
            else "Solo casos en Produccion - solo podes finalizar los asignados a vos"
        ),
    }


def mark_lifecycle_review_done(usecase, user, post_data, snapshot_usecase):
    old_data = snapshot_usecase(usecase)
    if can_assign_lifecycle_owner(user):
        owner_id = post_data.get("lifecycle_control_owner", "").strip()
        if owner_id.isdigit():
            usecase.lifecycle_control_owner_id = int(owner_id)
        elif owner_id == "":
            usecase.lifecycle_control_owner = None

    checked_at = date.today()
    usecase.last_validation_date = checked_at
    usecase.set_lifecycle_review_dates(checked_at)
    usecase.validation_status = UseCase.VALIDATION_STATUS_FINISHED
    usecase.updated_by = user
    usecase.save()

    LifecycleReview.objects.create(
        use_case=usecase,
        control_owner=usecase.lifecycle_control_owner,
        completed_by=user,
        status=usecase.validation_status,
        result=usecase.validation_result,
        checked_at=checked_at,
        next_review_date=usecase.next_review_date,
    )
    UseCaseChangeLog.create_diff(usecase, old_data, snapshot_usecase(usecase), user)


def assign_lifecycle_owner(usecase, user, post_data, snapshot_usecase):
    old_data = snapshot_usecase(usecase)
    owner_id = post_data.get("lifecycle_control_owner", "").strip()
    if owner_id.isdigit():
        usecase.lifecycle_control_owner_id = int(owner_id)
    else:
        usecase.lifecycle_control_owner = None
    usecase.updated_by = user
    usecase.save()
    UseCaseChangeLog.create_diff(usecase, old_data, snapshot_usecase(usecase), user)
