"""Lifecycle review period helpers."""

from collections import Counter
from datetime import date, timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.usecases.models import UseCase, UseCaseChangeLog

from .models import (
    DetectionMetric,
    LifecycleCycle,
    LifecyclePeriod,
    LifecyclePeriodMember,
    LifecycleReview,
    LifecycleTransition,
)
from apps.usecases.permissions import (
    can_assign_lifecycle_owner,
    can_finish_lifecycle_review,
    is_lifecycle_admin,
    resolve_user_roles,
)

PERIOD_LABELS = {1: "Enero - Abril", 2: "Mayo - Agosto", 3: "Septiembre - Diciembre"}


def report_key_for_period(period):
    return f"period_{period}"


def required_report_keys(periods):
    return tuple(report_key_for_period(period["period"]) for period in periods) + ("annual",)


def period_key(year, period):
    return f"Cuatrimestral {year}-C{period}"


def period_bounds(year, period):
    start_month = ((period - 1) * 4) + 1
    start = date(year, start_month, 1)
    if period == 3:
        next_start = date(year + 1, 1, 1)
    else:
        next_start = date(year, start_month + 4, 1)
    return start, next_start


def default_period_seed(year):
    rows = []
    for period, label in PERIOD_LABELS.items():
        start, next_start = period_bounds(year, period)
        rows.append({
            "period": period,
            "label": label,
            "start_date": start,
            "end_date": next_start - timedelta(days=1),
        })
    return rows


def ensure_configured_periods(cycle):
    periods = list(cycle.configured_periods.filter(is_active=True).order_by("period", "start_date"))
    if periods:
        return periods
    LifecyclePeriod.objects.bulk_create(
        [
            LifecyclePeriod(
                cycle=cycle,
                period=row["period"],
                label=row["label"],
                start_date=row["start_date"],
                end_date=row["end_date"],
            )
            for row in default_period_seed(cycle.year)
        ],
        ignore_conflicts=True,
    )
    return list(cycle.configured_periods.filter(is_active=True).order_by("period", "start_date"))


def current_period(today):
    cycle = LifecycleCycle.objects.filter(year=today.year).first()
    if cycle:
        for item in ensure_configured_periods(cycle):
            if item.start_date <= today <= item.end_date:
                return item.period
        future = [item for item in ensure_configured_periods(cycle) if item.start_date > today]
        if future:
            return future[0].period
    if today.month <= 4:
        return 1
    if today.month <= 8:
        return 2
    return 3


def _production_queryset():
    return (
        UseCase.objects
        .select_related("lifecycle_control_owner")
        .prefetch_related("mitre_attacks", "source_links__source")
        .filter(status__iexact=UseCase.STATUS_PRODUCTION)
    )


def _period_reviewed_ids(year, period):
    return set(
        LifecycleReview.objects
        .filter(review_type=period_key(year, period))
        .values_list("use_case_id", flat=True)
        .distinct()
    )


def ensure_cycle(year=None, *, actor=None):
    requested_year = year or date.today().year
    cycle = LifecycleCycle.objects.filter(year=requested_year).first()
    if cycle:
        return cycle
    return LifecycleCycle.objects.create(
        year=requested_year,
        started_by=actor if getattr(actor, "is_authenticated", False) else None,
    )


def next_configured_deadline(after=None, *, include_current=True):
    today = after or date.today()
    cycle = ensure_cycle(today.year)
    periods = ensure_configured_periods(cycle)
    for item in periods:
        if include_current and item.start_date <= today <= item.end_date:
            return item.end_date
        if item.end_date > today:
            return item.end_date
    next_cycle = ensure_cycle(today.year + 1)
    next_periods = ensure_configured_periods(next_cycle)
    return next_periods[0].end_date if next_periods else None


def _period_member_ids(year, period):
    return set(
        LifecyclePeriodMember.objects
        .filter(year=year, period=period)
        .values_list("use_case_id", flat=True)
    )


@transaction.atomic
def ensure_period_members(year, period):
    existing = _period_member_ids(year, period)
    if existing:
        return existing
    use_case_ids = list(_production_queryset().values_list("id", flat=True))
    LifecyclePeriodMember.objects.bulk_create(
        [
            LifecyclePeriodMember(year=year, period=period, use_case_id=use_case_id)
            for use_case_id in use_case_ids
        ],
        ignore_conflicts=True,
    )
    return set(use_case_ids)


def lifecycle_state(year, *, today=None):
    today = today or date.today()
    cycle = ensure_cycle(year or today.year)
    year = cycle.year
    configured_periods = ensure_configured_periods(cycle)
    periods = []
    active_period = None
    previous_complete = True

    for configured in configured_periods:
        period = configured.period
        start = configured.start_date
        end = configured.end_date
        enabled = previous_complete and cycle.status == LifecycleCycle.STATUS_ACTIVE
        member_ids = ensure_period_members(year, period) if enabled else _period_member_ids(year, period)
        total_cases = len(member_ids)
        reviewed_ids = _period_reviewed_ids(year, period)
        reviewed_count = len(reviewed_ids.intersection(member_ids))
        complete = total_cases > 0 and reviewed_count >= total_cases
        pending = max(total_cases - reviewed_count, 0) if enabled or complete else 0
        progress = round((reviewed_count / total_cases) * 100) if total_cases and (enabled or complete) else 0

        if complete:
            state = "Completo"
        elif cycle.status == LifecycleCycle.STATUS_CLOSED:
            state = "Cerrado"
        elif enabled and total_cases == 0:
            state = "Sin casos"
        elif enabled and today > end:
            state = "Vencido"
        elif enabled:
            state = "Habilitado"
        else:
            state = "Bloqueado"

        if enabled and not complete and active_period is None:
            active_period = period

        periods.append({
            "period": period,
            "label": configured.label,
            "start": start,
            "end": end,
            "total_use_cases": total_cases if enabled or complete else 0,
            "reviewed_use_cases": reviewed_count if enabled or complete else 0,
            "pending_use_cases": pending,
            "total_reviews": LifecycleReview.objects.filter(review_type=period_key(year, period)).count() if enabled or complete else 0,
            "enabled": enabled,
            "complete": complete,
            "state": state,
            "progress": progress,
        })
        previous_complete = previous_complete and complete

    if active_period is not None:
        active = next((item for item in periods if item["period"] == active_period), None)
        if active and active["enabled"] and not active["complete"]:
            pending_ids = _period_member_ids(year, active_period) - _period_reviewed_ids(year, active_period)
            if pending_ids:
                UseCase.objects.filter(id__in=pending_ids).update(next_review_date=active["end"])

    required_keys = required_report_keys(periods)
    return {
        "cycle": cycle,
        "year": year,
        "active_period": active_period or (periods[0]["period"] if periods else current_period(today)),
        "periods": periods,
        "annual_ready": all(item["complete"] for item in periods),
        "total_use_cases": sum(item["total_use_cases"] for item in periods),
        "report_exports": cycle.report_exports or {},
        "reports_ready": all((cycle.report_exports or {}).get(key) for key in required_keys),
        "required_report_keys": required_keys,
        "can_start_new_cycle": (
            cycle.status == LifecycleCycle.STATUS_ACTIVE
            and all(item["complete"] for item in periods)
            and all((cycle.report_exports or {}).get(key) for key in required_keys)
            and today.year > cycle.year
        ),
        "next_cycle_year": max(today.year, cycle.year + 1),
    }


@transaction.atomic
def mark_report_export(year, key):
    cycle = ensure_cycle(year)
    exports = dict(cycle.report_exports or {})
    exports[key] = timezone.now().isoformat()
    cycle.report_exports = exports
    cycle.save(update_fields=["report_exports"])
    return cycle


@transaction.atomic
def reset_period(year, period, *, actor=None):
    period = int(period)
    cycle = ensure_cycle(year)
    configured_periods = ensure_configured_periods(cycle)
    affected_periods = [item.period for item in configured_periods if item.period >= period]
    review_types = [period_key(year, item) for item in affected_periods]
    deleted_reviews = LifecycleReview.objects.filter(review_type__in=review_types).count()
    deleted_members = LifecyclePeriodMember.objects.filter(year=year, period__gte=period).count()
    DetectionMetric.objects.filter(period_key__in=review_types).delete()
    LifecycleReview.objects.filter(review_type__in=review_types).delete()
    LifecyclePeriodMember.objects.filter(year=year, period__gte=period).delete()
    exports = dict(cycle.report_exports or {})
    for item in affected_periods:
        exports.pop(report_key_for_period(item), None)
    exports.pop("annual", None)
    cycle.report_exports = exports
    cycle.save(update_fields=["report_exports"])
    LifecycleTransition.objects.create(
        cycle=cycle,
        transition_type=LifecycleTransition.TYPE_PERIOD_RESET,
        period=period,
        period_key=f"{year}-C{period}+",
        from_state="periodo con datos",
        to_state="periodo pendiente",
        reason="Reset manual del periodo y periodos posteriores.",
        actor=actor if getattr(actor, "is_authenticated", False) else None,
        metadata={
            "affected_periods": affected_periods,
            "deleted_reviews": deleted_reviews,
            "deleted_members": deleted_members,
        },
    )
    return cycle


@transaction.atomic
def start_new_cycle(actor=None):
    current = ensure_cycle()
    state = lifecycle_state(current.year)
    if not state["annual_ready"]:
        raise ValueError("Todos los periodos configurados deben estar completos.")
    if not state["reports_ready"]:
        raise ValueError("Antes de iniciar un nuevo ciclo deben descargarse los reportes obligatorios.")
    today = date.today()
    if today.year <= current.year:
        raise ValueError(f"El siguiente ciclo se habilita al comenzar {current.year + 1}.")
    if LifecycleCycle.objects.filter(year=today.year).exists():
        raise ValueError(f"El ciclo {today.year} ya existe.")

    current.status = LifecycleCycle.STATUS_CLOSED
    current.closed_at = timezone.now()
    current.closed_by = actor if getattr(actor, "is_authenticated", False) else None
    current.save(update_fields=["status", "closed_at", "closed_by"])
    LifecycleTransition.objects.create(
        cycle=current,
        transition_type=LifecycleTransition.TYPE_CYCLE_CLOSED,
        from_state=LifecycleCycle.STATUS_ACTIVE,
        to_state=LifecycleCycle.STATUS_CLOSED,
        reason=f"Cierre formal del ciclo {current.year}.",
        actor=actor if getattr(actor, "is_authenticated", False) else None,
    )
    cycle = LifecycleCycle.objects.create(
        year=today.year,
        started_by=actor if getattr(actor, "is_authenticated", False) else None,
    )
    LifecycleTransition.objects.create(
        cycle=cycle,
        transition_type=LifecycleTransition.TYPE_CYCLE_STARTED,
        from_state="sin ciclo",
        to_state=LifecycleCycle.STATUS_ACTIVE,
        reason=f"Inicio formal del ciclo {cycle.year}.",
        actor=actor if getattr(actor, "is_authenticated", False) else None,
    )
    periods = ensure_configured_periods(cycle)
    if periods:
        ensure_period_members(cycle.year, periods[0].period)
    return cycle


def build_lifecycle_management_context(user, query_params, *, today=None):
    today = today or date.today()
    lifecycle_admin = is_lifecycle_admin(user)
    state = lifecycle_state(today.year, today=today)
    active_period = state["active_period"]
    active_state = next(item for item in state["periods"] if item["period"] == active_period)
    review_type = period_key(state["year"], active_period)
    reviewed_ids = _period_reviewed_ids(state["year"], active_period)
    active_member_ids = _period_member_ids(state["year"], active_period)
    report_labels = {
        report_key_for_period(period["period"]): period["label"]
        for period in state["periods"]
    }
    report_labels["annual"] = "Anual"
    report_exports = state.get("report_exports", {})
    downloadable_report_keys = {
        report_key_for_period(period["period"])
        for period in state["periods"]
        if period["complete"]
    }
    if state["annual_ready"]:
        downloadable_report_keys.add("annual")
    report_statuses = [
        {
            "key": key,
            "label": report_labels.get(key, key),
            "done": bool(report_exports.get(key)),
            "exported_at": report_exports.get(key),
            "available": key in downloadable_report_keys,
        }
        for key in state["required_report_keys"]
    ]

    User = get_user_model()
    lifecycle_users = (
        User.objects.filter(is_active=True).order_by("username")
        if lifecycle_admin else User.objects.none()
    )

    roles = resolve_user_roles(user)
    can_assign = can_assign_lifecycle_owner(user, _roles=roles)
    rows = []
    owner_pending_counter = Counter()
    q = query_params.get("q", "").strip()
    bucket = query_params.get("bucket", "all")
    if bucket not in ("all", "pending", "reviewed"):
        bucket = "all"

    usecases = _production_queryset().filter(id__in=active_member_ids).order_by("name")
    if q:
        usecases = usecases.filter(
            Q(name__icontains=q)
            | Q(group_name__icontains=q)
            | Q(device__icontains=q)
            | Q(severity__icontains=q)
            | Q(source_links__source__name__icontains=q)
            | Q(source_links__source__code__icontains=q)
        ).distinct()

    for uc in usecases:
        latest_review = (
            LifecycleReview.objects
            .filter(use_case=uc)
            .order_by("-checked_at", "-created_at")
            .first()
        )
        period_review = (
            LifecycleReview.objects
            .filter(use_case=uc, review_type=review_type)
            .order_by("-created_at")
            .first()
        )
        is_reviewed = uc.id in reviewed_ids
        if bucket == "pending" and is_reviewed:
            continue
        if bucket == "reviewed" and not is_reviewed:
            continue
        review_days = uc.days_until_review
        if review_days is None:
            review_badge, review_level = "Sin fecha", "neutral"
        elif review_days < 0:
            review_badge, review_level = f"Vencido ({abs(review_days)}d)", "danger"
        elif review_days <= 15:
            review_badge, review_level = f"Por vencer ({review_days}d)", "warn"
        else:
            review_badge, review_level = f"Al dia ({review_days}d)", "ok"

        is_pending = not is_reviewed
        if is_pending:
            owner_key = (
                uc.lifecycle_control_owner.get_full_name() or uc.lifecycle_control_owner.username
                if uc.lifecycle_control_owner else "Sin responsable de control"
            )
            owner_pending_counter[owner_key] += 1

        if lifecycle_admin:
            can_finish_row = active_state["enabled"] and not active_state["complete"]
        else:
            can_finish_row = (
                active_state["enabled"]
                and not active_state["complete"]
                and not roles["is_readonly"]
                and (roles["is_analyst"] or user.has_perm("usecases.add_lifecyclereview"))
                and uc.lifecycle_control_owner_id == user.id
            )

        control_checks = lifecycle_completion_checks(uc)
        source_names = [link.source.display_name for link in uc.source_links.all()]

        rows.append({
            "usecase": uc,
            "last_check": uc.last_validation_date,
            "next_check": uc.next_review_date,
            "owner": uc.lifecycle_control_owner,
            "task_status": "Revisado" if is_reviewed else "Pendiente",
            "is_pending": is_pending,
            "is_reviewed": is_reviewed,
            "period_review": period_review,
            "latest_review": latest_review,
            "can_finish": can_finish_row,
            "can_assign_owner": can_assign,
            "control_checks": control_checks,
            "controls_ready": all(item["ok"] for item in control_checks),
            "review_badge": review_badge,
            "review_level": review_level,
            "source_names": source_names,
            "source_label": ", ".join(source_names) if source_names else "Sin fuente vinculada",
        })

    paginator = Paginator(rows, 20)
    queue = paginator.get_page(query_params.get("page"))

    return {
        "rows": queue,
        "queue": queue,
        "state": state,
        "active_state": active_state,
        "active_period": active_period,
        "active_review_type": review_type,
        "bucket": bucket,
        "q": q,
        "summary_total": active_state["total_use_cases"],
        "summary_completed": active_state["reviewed_use_cases"],
        "summary_pending": active_state["pending_use_cases"],
        "summary_progress": active_state["progress"],
        "summary_days_left": max((active_state["end"] - today).days, 0),
        "owner_pending_summary": owner_pending_counter.most_common(5),
        "lifecycle_users": lifecycle_users,
        "validation_result_choices": [
            (LifecycleReview.RESULT_CURRENT, "Vigente"),
            (LifecycleReview.RESULT_CURRENT_WITH_IMPROVEMENTS, "Vigente con mejoras"),
            (LifecycleReview.RESULT_UPDATE_REQUIRED, "Requiere actualizacion"),
            (LifecycleReview.RESULT_OBSOLETE, "Obsoleta"),
            (LifecycleReview.RESULT_RETIREMENT_RECOMMENDED, "Baja recomendada"),
        ],
        "can_manage_lifecycle": lifecycle_admin,
        "can_export_lifecycle_reports": (
            roles["is_admin"]
            or roles["is_analyst"]
            or (not roles["is_readonly"] and user.has_perm("reports.export_reports"))
        ),
        "report_labels": report_labels,
        "report_statuses": report_statuses,
        "lifecycle_scope_label": (
            "Solo casos en Produccion" if lifecycle_admin
            else "Solo casos en Produccion - solo podes finalizar los asignados a vos"
        ),
    }


def lifecycle_completion_checks(usecase):
    return [
        {
            "label": "Responsable",
            "ok": bool(usecase.lifecycle_control_owner_id),
            "detail": "Responsable de control asignado",
        },
        {
            "label": "Produccion",
            "ok": bool(usecase.production_date),
            "detail": "Fecha de puesta en producción cargada",
        },
        {
            "label": "ATT&CK",
            "ok": usecase.mitre_attacks.exists(),
            "detail": "Al menos una tecnica ATT&CK asociada",
        },
        {
            "label": "Fuentes",
            "ok": usecase.source_links.exists(),
            "detail": "Al menos una fuente de eventos vinculada",
        },
        {
            "label": "Habilitación",
            "ok": bool(usecase.is_enabled or (usecase.disabled_reason or "").strip()),
            "detail": "Habilitado o con motivo de deshabilitacion",
        },
    ]


def lifecycle_completion_errors(usecase, post_data):
    errors = []
    result = (post_data.get("validation_result") or "").strip()
    notes = (post_data.get("notes") or "").strip()
    valid_results = {
        LifecycleReview.RESULT_CURRENT,
        LifecycleReview.RESULT_CURRENT_WITH_IMPROVEMENTS,
        LifecycleReview.RESULT_UPDATE_REQUIRED,
        LifecycleReview.RESULT_OBSOLETE,
        LifecycleReview.RESULT_RETIREMENT_RECOMMENDED,
    }
    if result not in valid_results:
        errors.append("Resultado del control obligatorio.")
    if not notes:
        errors.append("Notas o evidencia del control obligatorias.")
    trigger_count = _parse_positive_int(post_data.get("trigger_count", "0"))
    true_incidents = _parse_positive_int(post_data.get("true_incidents", "0"))
    false_positives = _parse_positive_int(post_data.get("false_positives", "0"))
    if trigger_count is None:
        errors.append("La cantidad de alertas debe ser cero o mayor.")
    if true_incidents is None:
        errors.append("Los incidentes reales deben ser cero o mayor.")
    if false_positives is None:
        errors.append("Los falsos positivos deben ser cero o mayor.")
    if (
        trigger_count is not None
        and true_incidents is not None
        and false_positives is not None
        and true_incidents + false_positives > trigger_count
    ):
        errors.append("La suma de incidentes reales y falsos positivos no puede superar la cantidad de alertas.")
    return errors


def _parse_positive_int(value):
    value = "" if value is None else str(value).strip()
    if value == "":
        return 0
    if not value.isdigit():
        return None
    return int(value)


def _review_period_number(review_type, checked_at):
    marker = "-C"
    if marker in review_type:
        raw = review_type.rsplit(marker, 1)[-1]
        if raw.isdigit():
            return int(raw)
    return current_period(checked_at)


def _state_label(usecase):
    return f"{usecase.validation_status or '-'} / {usecase.validation_result or '-'}"


def _metric_status_payload(review):
    classified = review.true_incidents + review.false_positives
    precision = DetectionMetric.precision_from_counts(review.true_incidents, review.false_positives)
    check_values = [
        review.logic_valid,
        review.sources_active,
        review.event_ids_valid,
        review.fields_exist,
    ]
    quality = (Decimal(sum(1 for value in check_values if value)) / Decimal(len(check_values))) * Decimal("100")
    penalty = Decimal("0")
    if review.requires_tuning:
        penalty += Decimal("10")
    if review.requires_optimization:
        penalty += Decimal("8")
    if review.requires_retirement:
        penalty += Decimal("25")
    if classified <= 0:
        effectiveness = Decimal("0.0")
    else:
        effectiveness = ((precision * Decimal("0.65")) + (quality * Decimal("0.35")) - penalty)
        effectiveness = max(Decimal("0.0"), min(Decimal("100.0"), effectiveness)).quantize(Decimal("0.1"))
    return {
        "precision_rate": precision,
        "effectiveness_score": effectiveness,
        "health_status": DetectionMetric.health_from_score(effectiveness, has_classified_alerts=classified > 0),
    }


def _sync_detection_metric(review, user):
    period = _review_period_number(review.review_type, review.checked_at)
    start, next_start = period_bounds(review.checked_at.year, period)
    payload = _metric_status_payload(review)
    metric, _ = DetectionMetric.objects.update_or_create(
        use_case=review.use_case,
        period_key=review.review_type,
        source=DetectionMetric.SOURCE_LIFECYCLE_REVIEW,
        defaults={
            "review": review,
            "period_start": start,
            "period_end": next_start - timedelta(days=1),
            "measured_at": review.checked_at,
            "trigger_count": review.trigger_count,
            "true_incidents": review.true_incidents,
            "false_positives": review.false_positives,
            "notes": review.notes,
            "created_by": user if getattr(user, "is_authenticated", False) else None,
            **payload,
        },
    )
    return metric


def mark_lifecycle_review_done(usecase, user, post_data, snapshot_usecase):
    old_data = snapshot_usecase(usecase)
    old_state = _state_label(usecase)
    if can_assign_lifecycle_owner(user):
        owner_id = post_data.get("lifecycle_control_owner", "").strip()
        if owner_id.isdigit():
            usecase.lifecycle_control_owner_id = int(owner_id)
        elif owner_id == "":
            usecase.lifecycle_control_owner = None

    checked_at = date.today()
    result = (post_data.get("validation_result") or "").strip()
    notes = (post_data.get("notes") or "").strip()
    trigger_count = _parse_positive_int(post_data.get("trigger_count")) or 0
    true_incidents = _parse_positive_int(post_data.get("true_incidents")) or 0
    false_positives = _parse_positive_int(post_data.get("false_positives")) or 0
    usecase.last_validation_date = checked_at
    usecase.set_lifecycle_review_dates(checked_at)
    usecase.validation_status = UseCase.VALIDATION_STATUS_FINISHED
    usecase.validation_result = _map_review_result_to_validation_result(result)
    usecase.updated_by = user
    usecase.save()

    review_type = post_data.get("review_type") or period_key(checked_at.year, current_period(checked_at))
    review, _ = LifecycleReview.objects.update_or_create(
        use_case=usecase,
        review_type=review_type,
        defaults={
            "control_owner": usecase.lifecycle_control_owner,
            "completed_by": user,
            "status": usecase.validation_status,
            "result": result,
            "notes": notes,
            "checked_at": checked_at,
            "next_review_date": usecase.next_review_date,
            "trigger_count": trigger_count,
            "true_incidents": true_incidents,
            "false_positives": false_positives,
            "alert_triggered_90d": trigger_count > 0,
            "logic_valid": post_data.get("logic_valid") == "on",
            "sources_active": post_data.get("sources_active") == "on",
            "event_ids_valid": post_data.get("event_ids_valid") == "on",
            "fields_exist": post_data.get("fields_exist") == "on",
            "requires_tuning": post_data.get("requires_tuning") == "on",
            "requires_optimization": post_data.get("requires_optimization") == "on",
            "requires_retirement": post_data.get("requires_retirement") == "on",
        },
    )
    metric = _sync_detection_metric(review, user)
    LifecycleTransition.objects.create(
        use_case=usecase,
        review=review,
        transition_type=LifecycleTransition.TYPE_REVIEW_COMPLETED,
        period=_review_period_number(review.review_type, checked_at),
        period_key=review.review_type,
        from_state=old_state,
        to_state=_state_label(usecase),
        reason=result,
        actor=user if getattr(user, "is_authenticated", False) else None,
        metadata={
            "metric_id": metric.pk,
            "trigger_count": trigger_count,
            "true_incidents": true_incidents,
            "false_positives": false_positives,
            "effectiveness_score": str(metric.effectiveness_score),
            "health_status": metric.health_status,
        },
    )
    UseCaseChangeLog.create_diff(usecase, old_data, snapshot_usecase(usecase), user)


def _map_review_result_to_validation_result(result):
    if result == LifecycleReview.RESULT_CURRENT:
        return UseCase.VALIDATION_RESULT_OK
    if result in {
        LifecycleReview.RESULT_CURRENT_WITH_IMPROVEMENTS,
        LifecycleReview.RESULT_UPDATE_REQUIRED,
    }:
        return UseCase.VALIDATION_RESULT_WARNING
    return UseCase.VALIDATION_RESULT_FAILED


def assign_lifecycle_owner(usecase, user, post_data, snapshot_usecase):
    old_data = snapshot_usecase(usecase)
    old_owner = usecase.lifecycle_control_owner
    owner_id = post_data.get("lifecycle_control_owner", "").strip()
    if owner_id.isdigit():
        usecase.lifecycle_control_owner_id = int(owner_id)
    else:
        usecase.lifecycle_control_owner = None
    usecase.updated_by = user
    usecase.save()
    if getattr(old_owner, "pk", None) != usecase.lifecycle_control_owner_id:
        LifecycleTransition.objects.create(
            use_case=usecase,
            transition_type=LifecycleTransition.TYPE_OWNER_CHANGED,
            from_state=str(old_owner or "Sin responsable"),
            to_state=str(usecase.lifecycle_control_owner or "Sin responsable"),
            reason="Asignacion manual de responsable lifecycle.",
            actor=user if getattr(user, "is_authenticated", False) else None,
            metadata={"old_owner_id": getattr(old_owner, "pk", None), "new_owner_id": usecase.lifecycle_control_owner_id},
        )
    UseCaseChangeLog.create_diff(usecase, old_data, snapshot_usecase(usecase), user)
