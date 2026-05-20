from datetime import date

from django.conf import settings
from django.db import OperationalError, ProgrammingError
from django.template.loader import render_to_string

from .models import DashboardReportSettings

DEFAULT_REPORT_TITLE = "Reporte ejecutivo SOC"
DEFAULT_REPORT_SUBTITLE = "Cobertura ATT&CK y D3FEND sobre casos de uso en producción"
DEFAULT_REPORT_FOOTER = "SOC Use Cases Manager"


def get_active_dashboard_report_settings():
    try:
        return DashboardReportSettings.objects.filter(is_active=True).order_by("-updated_at").first()
    except (OperationalError, ProgrammingError):
        return None


def _d3fend_executive_rows(coverage_rows, limit):
    rows = []
    ordered_rows = sorted(coverage_rows, key=lambda item: item[0], reverse=True)
    for coverage_ratio, d3fend in ordered_rows[:limit]:
        if coverage_ratio >= 1:
            continue
        rows.append(
            {
                "code": str(getattr(d3fend, "code", "-")),
                "name": str(getattr(d3fend, "name", "") or "-"),
                "category": str(getattr(d3fend, "category", "") or "-"),
                "coverage_percent": round(coverage_ratio * 100, 1),
            }
        )
    return rows


def _metric_rows(metrics):
    return [
        {
            "title": m["title"],
            "percent": m["percent_label"],
            "covered": m["covered"],
            "total": m["total"],
        }
        for m in metrics
    ]


def build_dashboard_pdf(context, report_settings, generated_by):
    try:
        from weasyprint import HTML
    except Exception as exc:
        raise RuntimeError("WeasyPrint no está disponible") from exc

    title = report_settings.report_title if report_settings else DEFAULT_REPORT_TITLE
    subtitle = report_settings.report_subtitle if report_settings else DEFAULT_REPORT_SUBTITLE
    footer = report_settings.footer_text if report_settings else DEFAULT_REPORT_FOOTER

    template_context = {
        "report_title": title,
        "report_subtitle": subtitle,
        "report_footer": footer,
        "generated_on": f"{date.today():%d/%m/%Y}",
        "generated_by": getattr(generated_by, "username", "-"),
        "selected_device": context.get("selected_device", ""),
        "selected_severity": context.get("selected_severity", ""),
        "selected_enabled": context.get("selected_enabled", ""),
        "kpis": {
            "total_cases": context["total_cases"],
            "attack_techniques": f'{context["covered_attack_techniques"]} / {context["all_attack_techniques"]}',
            "attack_tactics": f'{context["covered_tactics"]} / {context["total_tactics"]}',
            "d3fend_inferred": f'{context["covered_d3fend_techniques"]} / {context["all_d3fend_techniques"]}',
            "d3fend_full_partial": f'{context["fully_covered_d3fend_techniques"]} / {context["partially_covered_d3fend_techniques"]}',
        },
        "attack_metrics": _metric_rows(context["attack_radials"]),
        "d3fend_metrics": _metric_rows(context["d3fend_radials"]),
        "executive_global": context.get("global_d3fend_coverage_percent", 0),
        "executive_full": context.get("fully_covered_d3fend_techniques", 0),
        "executive_total": context.get("all_d3fend_techniques", 0),
        "executive_rows": _d3fend_executive_rows(context.get("d3fend_coverage_rows", []), limit=getattr(settings, "D3FEND_EXECUTIVE_REPORT_LIMIT", 50)),
    }

    html = render_to_string("reports/dashboard_pdf.html", template_context)
    return HTML(string=html).write_pdf()
