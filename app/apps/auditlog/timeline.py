from dataclasses import dataclass

from django.core.paginator import Paginator
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_date

from apps.controls.models import ControlInventoryChange
from apps.lifecycle.models import DetectionMetric, LifecycleReview, LifecycleTransition
from apps.reports.models import ReportDownload
from apps.sigma_tools.models import SigmaConversion
from apps.usecases.models import UseCaseChangeLog

from .models import AuditLog


AREA_ALL = "all"
AREA_SECURITY = "security"
AREA_INVENTORY = "inventory"
AREA_LIFECYCLE = "lifecycle"
AREA_CONTROLS = "controls"
AREA_REPORTS = "reports"
AREA_SIGMA = "sigma"

AREA_CHOICES = [
    (AREA_ALL, "Todo"),
    (AREA_SECURITY, "Seguridad"),
    (AREA_INVENTORY, "Inventario"),
    (AREA_LIFECYCLE, "Ciclo de vida"),
    (AREA_CONTROLS, "Controles"),
    (AREA_REPORTS, "Reportes"),
    (AREA_SIGMA, "Sigma"),
]

AREA_META = {
    AREA_SECURITY: {"label": "Seguridad", "badge": "bad", "permission": "auditlog.view_security_audit"},
    AREA_INVENTORY: {"label": "Inventario", "badge": "accent", "permission": "auditlog.view_inventory_audit"},
    AREA_LIFECYCLE: {"label": "Ciclo de vida", "badge": "good", "permission": "auditlog.view_lifecycle_audit"},
    AREA_CONTROLS: {"label": "Controles", "badge": "warn", "permission": "auditlog.view_controls_audit"},
    AREA_REPORTS: {"label": "Reportes", "badge": "accent", "permission": "auditlog.view_reports_audit"},
    AREA_SIGMA: {"label": "Sigma", "badge": "good", "permission": "auditlog.view_sigma_audit"},
}

ACTION_BADGES = {
    "login": "good",
    "logout": "accent",
    "login_failed": "bad",
    "web_action": "accent",
    "usecase_changed": "warn",
    "detection_metric": "accent",
    "lifecycle_review": "good",
    "lifecycle_transition": "warn",
    "report_download": "accent",
    "epl_to_sigma": "good",
    "sigma_to_target": "good",
    "control_created": "good",
    "control_updated": "warn",
    "control_deleted": "bad",
}

DOMAIN_AUDIT_ACTIONS = {
    "control_created",
    "control_updated",
    "control_deleted",
    "sigma_epl_converted",
    "sigma_rule_converted",
    "report_download",
}

ACTION_LABELS = {
    "login": "Inicio de sesion",
    "logout": "Cierre de sesion",
    "login_failed": "Inicio fallido",
    "web_action": "Accion web",
}


@dataclass
class AuditTimelineItem:
    source: str
    pk: int
    area: str
    area_label: str
    occurred_at: object
    action: str
    action_label: str
    actor: object
    entity_type: str
    entity_id: str
    summary: str
    details: list
    ip_address: str = ""
    area_badge: str = "accent"
    action_badge: str = ""
    object_url: str = ""
    object_label: str = ""

    @property
    def detail_url_source(self):
        return self.source


def build_audit_timeline_context(query_params, user=None, paginate=True):
    q = (query_params.get("q") or "").strip()
    area = (query_params.get("area") or AREA_ALL).strip()
    allowed_areas = allowed_audit_areas(user)
    if area not in allowed_areas:
        area = AREA_ALL
    start_date = parse_date((query_params.get("start") or "").strip())
    end_date = parse_date((query_params.get("end") or "").strip())

    items = _collect_items(area, allowed_areas=allowed_areas)
    if q:
        normalized = q.casefold()
        items = [item for item in items if _item_text(item).casefold().find(normalized) >= 0]
    if start_date:
        items = [item for item in items if timezone.localtime(item.occurred_at).date() >= start_date]
    if end_date:
        items = [item for item in items if timezone.localtime(item.occurred_at).date() <= end_date]

    items.sort(key=lambda item: item.occurred_at, reverse=True)
    page = None
    if paginate:
        paginator = Paginator(items, 50)
        page = paginator.get_page(query_params.get("page"))

    all_items = _collect_items(AREA_ALL, allowed_areas=allowed_areas)
    return {
        "items": page if paginate else items,
        "page_obj": page,
        "q": q,
        "selected_area": area,
        "selected_start": start_date.isoformat() if start_date else "",
        "selected_end": end_date.isoformat() if end_date else "",
        "area_choices": [(value, label) for value, label in AREA_CHOICES if value in allowed_areas],
        "total_events": len(all_items),
        "filtered_events": len(items),
        "security_events": sum(1 for item in all_items if item.area == AREA_SECURITY),
        "business_events": sum(1 for item in all_items if item.area != AREA_SECURITY),
        "active_actors": len({str(item.actor_id) for item in all_items if getattr(item, "actor_id", None)}),
    }


def allowed_audit_areas(user):
    if user is None:
        return {value for value, _ in AREA_CHOICES}
    if getattr(user, "is_superuser", False) or getattr(user, "is_staff", False) or user.groups.filter(name="Admin").exists():
        return {value for value, _ in AREA_CHOICES}
    allowed = {AREA_ALL}
    if user.has_perm("auditlog.view_auditlog"):
        allowed.update(value for value, _ in AREA_CHOICES)
        return allowed
    for area, meta in AREA_META.items():
        if user.has_perm(meta["permission"]):
            allowed.add(area)
    return allowed


def get_timeline_item(source, pk):
    builders = {
        "audit": _auditlog_item,
        "usecase_change": _usecase_change_item,
        "control_change": _control_change_item,
        "detection_metric": _detection_metric_item,
        "lifecycle_review": _lifecycle_review_item,
        "lifecycle_transition": _lifecycle_transition_item,
        "report_download": _report_download_item,
        "sigma_conversion": _sigma_conversion_item,
    }
    if source not in builders:
        return None
    return builders[source](pk)


def _collect_items(area, allowed_areas=None):
    allowed_areas = allowed_areas or {value for value, _ in AREA_CHOICES}
    collectors = []
    if AREA_SECURITY in allowed_areas and area in (AREA_ALL, AREA_SECURITY):
        collectors.append(_auditlog_items)
    if AREA_INVENTORY in allowed_areas and area in (AREA_ALL, AREA_INVENTORY):
        collectors.append(_usecase_change_items)
    if AREA_CONTROLS in allowed_areas and area in (AREA_ALL, AREA_CONTROLS):
        collectors.append(_control_change_items)
    if AREA_LIFECYCLE in allowed_areas and area in (AREA_ALL, AREA_LIFECYCLE):
        collectors.append(_lifecycle_review_items)
        collectors.append(_lifecycle_transition_items)
        collectors.append(_detection_metric_items)
    if AREA_REPORTS in allowed_areas and area in (AREA_ALL, AREA_REPORTS):
        collectors.append(_report_download_items)
    if AREA_SIGMA in allowed_areas and area in (AREA_ALL, AREA_SIGMA):
        collectors.append(_sigma_conversion_items)

    items = []
    for collector in collectors:
        items.extend(collector())
    return items


def _item_text(item):
    values = [
        item.area_label,
        item.action_label,
        item.entity_type,
        item.entity_id,
        item.summary,
        str(item.actor or ""),
        item.ip_address,
    ]
    values.extend(f"{label} {value}" for label, value in item.details)
    return " ".join(values)


def _actor_id(actor):
    return getattr(actor, "pk", None)


def _item(**kwargs):
    area = kwargs.get("area")
    action = kwargs.get("action")
    kwargs.setdefault("area_badge", AREA_META.get(area, {}).get("badge", "accent"))
    kwargs.setdefault("action_badge", ACTION_BADGES.get(action, ""))
    item = AuditTimelineItem(**kwargs)
    item.actor_id = _actor_id(item.actor)
    return item


def _safe_reverse(name, *args):
    try:
        return reverse(name, args=args)
    except Exception:
        return ""


def _auditlog_items():
    return [
        _auditlog_to_item(log)
        for log in AuditLog.objects.select_related("actor").exclude(action__in=DOMAIN_AUDIT_ACTIONS)[:250]
    ]


def _auditlog_item(pk):
    return _auditlog_to_item(AuditLog.objects.select_related("actor").filter(pk=pk).first())


def _auditlog_to_item(log):
    if log is None:
        return None
    action_label = ACTION_LABELS.get(log.action, log.action.replace("_", " ").capitalize())
    return _item(
        source="audit",
        pk=log.pk,
        area=AREA_SECURITY,
        area_label="Seguridad",
        occurred_at=log.created_at,
        action=log.action,
        action_label=action_label,
        actor=log.actor,
        entity_type=log.entity_type or "-",
        entity_id=log.entity_id or "",
        summary=action_label,
        details=[
            ("IP", log.ip_address or "-"),
            ("User-Agent", log.user_agent or "-"),
            ("Detalles", log.details or {}),
        ],
        ip_address=log.ip_address or "",
        action_badge=ACTION_BADGES.get(log.action, "accent"),
    )


def _usecase_change_items():
    return [_usecase_change_to_item(change) for change in UseCaseChangeLog.objects.select_related("use_case", "changed_by")[:250]]


def _usecase_change_item(pk):
    return _usecase_change_to_item(UseCaseChangeLog.objects.select_related("use_case", "changed_by").filter(pk=pk).first())


def _usecase_change_to_item(change):
    if change is None:
        return None
    return _item(
        source="usecase_change",
        pk=change.pk,
        area=AREA_INVENTORY,
        area_label="Inventario",
        occurred_at=change.changed_at,
        action="usecase_changed",
        action_label="Caso modificado",
        actor=change.changed_by,
        entity_type="Caso de uso",
        entity_id=f"CU{change.use_case_id:04d}",
        summary=f"{change.use_case.name} - {change.field_label}",
        details=[
            ("Campo", change.field_label),
            ("Valor anterior", change.old_value or "-"),
            ("Valor nuevo", change.new_value or "-"),
        ],
        object_url=_safe_reverse("usecase_detail", change.use_case_id),
        object_label="Abrir caso",
    )


def _control_change_items():
    return [_control_change_to_item(change) for change in ControlInventoryChange.objects.select_related("control", "actor")[:250]]


def _control_change_item(pk):
    return _control_change_to_item(ControlInventoryChange.objects.select_related("control", "actor").filter(pk=pk).first())


def _control_change_to_item(change):
    if change is None:
        return None
    return _item(
        source="control_change",
        pk=change.pk,
        area=AREA_CONTROLS,
        area_label="Controles",
        occurred_at=change.created_at,
        action=f"control_{change.action}",
        action_label={
            "created": "Control creado",
            "updated": "Control modificado",
            "deleted": "Control eliminado",
        }.get(change.action, f"Control {change.action}"),
        actor=change.actor,
        entity_type="Control",
        entity_id=change.control_code or "",
        summary=f"{change.control_code} - {change.control_name}",
        details=[
            ("Versión", change.control_version or "-"),
            ("Cambios", change.changes or {}),
        ],
        object_url=_safe_reverse("control_detail", change.control_id) if change.control_id else "",
        object_label="Abrir control" if change.control_id else "",
    )


def _lifecycle_review_items():
    return [_lifecycle_review_to_item(review) for review in LifecycleReview.objects.select_related("use_case", "completed_by", "control_owner")[:250]]


def _lifecycle_review_item(pk):
    return _lifecycle_review_to_item(LifecycleReview.objects.select_related("use_case", "completed_by", "control_owner").filter(pk=pk).first())


def _lifecycle_review_to_item(review):
    if review is None:
        return None
    return _item(
        source="lifecycle_review",
        pk=review.pk,
        area=AREA_LIFECYCLE,
        area_label="Ciclo de vida",
        occurred_at=review.created_at,
        action="lifecycle_review",
        action_label="Revision registrada",
        actor=review.completed_by,
        entity_type="Caso de uso",
        entity_id=f"CU{review.use_case_id:04d}",
        summary=f"{review.use_case.name} - {review.result or review.status}",
        details=[
            ("Período", review.review_type or "-"),
            ("Fecha control", review.checked_at),
            ("Responsable", review.control_owner or "-"),
            ("Alertas", review.trigger_count),
            ("Notas", review.notes or "-"),
        ],
        object_url=_safe_reverse("usecase_detail", review.use_case_id),
        object_label="Abrir caso",
    )


def _lifecycle_transition_items():
    return [
        _lifecycle_transition_to_item(transition)
        for transition in LifecycleTransition.objects.select_related("use_case", "actor", "review", "cycle")[:250]
    ]


def _lifecycle_transition_item(pk):
    return _lifecycle_transition_to_item(
        LifecycleTransition.objects.select_related("use_case", "actor", "review", "cycle").filter(pk=pk).first()
    )


def _lifecycle_transition_to_item(transition):
    if transition is None:
        return None
    use_case_id = transition.use_case_id
    return _item(
        source="lifecycle_transition",
        pk=transition.pk,
        area=AREA_LIFECYCLE,
        area_label="Ciclo de vida",
        occurred_at=transition.created_at,
        action="lifecycle_transition",
        action_label=transition.get_transition_type_display(),
        actor=transition.actor,
        entity_type="Lifecycle",
        entity_id=f"CU{use_case_id:04d}" if use_case_id else transition.period_key or str(transition.cycle or ""),
        summary=f"{transition.from_state or '-'} -> {transition.to_state or '-'}",
        details=[
            ("Periodo", transition.period_key or "-"),
            ("Motivo", transition.reason or "-"),
            ("Metadata", transition.metadata or {}),
        ],
        object_url=_safe_reverse("usecase_detail", use_case_id) if use_case_id else _safe_reverse("lifecycle_management"),
        object_label="Abrir caso" if use_case_id else "Abrir lifecycle",
    )


def _detection_metric_items():
    return [
        _detection_metric_to_item(metric)
        for metric in DetectionMetric.objects.select_related("use_case", "created_by", "review")[:250]
    ]


def _detection_metric_item(pk):
    return _detection_metric_to_item(
        DetectionMetric.objects.select_related("use_case", "created_by", "review").filter(pk=pk).first()
    )


def _detection_metric_to_item(metric):
    if metric is None:
        return None
    return _item(
        source="detection_metric",
        pk=metric.pk,
        area=AREA_LIFECYCLE,
        area_label="Ciclo de vida",
        occurred_at=metric.updated_at,
        action="detection_metric",
        action_label="Metrica de deteccion",
        actor=metric.created_by,
        entity_type="Caso de uso",
        entity_id=f"CU{metric.use_case_id:04d}",
        summary=f"{metric.use_case.name} - efectividad {metric.effectiveness_score}%",
        details=[
            ("Periodo", metric.period_key or "-"),
            ("Alertas", metric.trigger_count),
            ("Incidentes reales", metric.true_incidents),
            ("Falsos positivos", metric.false_positives),
            ("Precision", f"{metric.precision_rate}%"),
            ("Efectividad", f"{metric.effectiveness_score}%"),
            ("Estado", metric.get_health_status_display()),
        ],
        object_url=_safe_reverse("usecase_detail", metric.use_case_id),
        object_label="Abrir caso",
    )


def _report_download_items():
    return [_report_download_to_item(download) for download in ReportDownload.objects.select_related("generated_by")[:250]]


def _report_download_item(pk):
    return _report_download_to_item(ReportDownload.objects.select_related("generated_by").filter(pk=pk).first())


def _report_download_to_item(download):
    if download is None:
        return None
    return _item(
        source="report_download",
        pk=download.pk,
        area=AREA_REPORTS,
        area_label="Reportes",
        occurred_at=download.created_at,
        action="report_download",
        action_label="Reporte descargado",
        actor=download.generated_by,
        entity_type="Reporte",
        entity_id=download.report_type,
        summary=download.filename,
        details=[
            ("Tipo", download.get_report_type_display()),
            ("Archivo", download.filename),
        ],
        object_url=_safe_reverse("report_index"),
        object_label="Abrir reportes",
    )


def _sigma_conversion_items():
    return [_sigma_conversion_to_item(conversion) for conversion in SigmaConversion.objects.select_related("use_case", "created_by")[:250]]


def _sigma_conversion_item(pk):
    return _sigma_conversion_to_item(SigmaConversion.objects.select_related("use_case", "created_by").filter(pk=pk).first())


def _sigma_conversion_to_item(conversion):
    if conversion is None:
        return None
    return _item(
        source="sigma_conversion",
        pk=conversion.pk,
        area=AREA_SIGMA,
        area_label="Sigma",
        occurred_at=conversion.created_at,
        action=conversion.mode,
        action_label=conversion.get_mode_display(),
        actor=conversion.created_by,
        entity_type="Conversión",
        entity_id=conversion.target or "sigma",
        summary=conversion.use_case.name if conversion.use_case else conversion.get_mode_display(),
        details=[
            ("Caso", conversion.use_case.name if conversion.use_case else "-"),
            ("Destino", conversion.get_target_display() if conversion.target else "-"),
            ("Entrada", conversion.input_text[:500]),
            ("Salida", conversion.output_text[:500]),
        ],
        object_url=_safe_reverse("sigma_converter" if conversion.mode == SigmaConversion.MODE_SIGMA_TO_TARGET else "sigma_epl_to_sigma"),
        object_label="Abrir Sigma",
    )
