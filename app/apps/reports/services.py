from collections import Counter
from datetime import date
from io import BytesIO
from xml.sax.saxutils import escape

from django.db import models

from apps.controls.models import Control
from apps.dashboard.dashboard import build_dashboard_context, build_executive_dashboard_context
from apps.dashboard.reports import build_dashboard_pdf
from apps.lifecycle.lifecycle import lifecycle_state
from apps.lifecycle.models import LifecycleReview
from apps.sources.models import EventSource
from apps.usecases.models import UseCase

from .models import ReportDownload, ReportTemplateConfig


REPORT_DEFINITIONS = {
    ReportDownload.TYPE_EXECUTIVE: {
        "title": "Reporte ejecutivo",
        "subtitle": "Resumen general de inventario, fuentes, controles y puntos de atencion.",
        "filename_prefix": "reporte-ejecutivo",
        "accent": "#22c55e",
        "code": "PR",
    },
    ReportDownload.TYPE_MITRE: {
        "title": "Reporte MITRE / D3FEND",
        "subtitle": "Cobertura ATT&CK y D3FEND sobre casos de uso en producción.",
        "filename_prefix": "reporte-mitre-d3fend",
        "accent": "#2d7aff",
        "code": "MT",
    },
    ReportDownload.TYPE_INVENTORY: {
        "title": "Reporte de inventario",
        "subtitle": "Detalle compacto de casos de uso, fuentes, estado, severidad y cobertura asociada.",
        "filename_prefix": "reporte-inventario",
        "accent": "#00e5a0",
        "code": "CU",
    },
    ReportDownload.TYPE_LIFECYCLE: {
        "title": "Reporte de ciclo de vida",
        "subtitle": "Estado de revisiones cuatrimestrales y últimos controles realizados.",
        "filename_prefix": "reporte-ciclo-vida",
        "accent": "#f5a623",
        "code": "CV",
    },
    ReportDownload.TYPE_CONTROLS: {
        "title": "Reporte de controles",
        "subtitle": "Inventario de controles, fuentes asociadas, estado y casos relacionados.",
        "filename_prefix": "reporte-controles",
        "accent": "#a78bfa",
        "code": "CT",
    },
}

REPORT_SECTION_CHOICES = {
    ReportDownload.TYPE_EXECUTIVE: [
        ("indicators", "Indicadores principales", "Casos, fuentes, controles y puntos de atencion."),
        ("severity", "Distribucion por severidad", "Resumen por criticidad."),
        ("status", "Distribucion por estado", "Resumen por estado del inventario."),
        ("sources", "Fuentes principales", "Fuentes mas utilizadas."),
    ],
    ReportDownload.TYPE_MITRE: [
        ("mitre_dashboard", "Dashboard MITRE / D3FEND", "Cobertura ATT&CK y D3FEND completa."),
    ],
    ReportDownload.TYPE_INVENTORY: [
        ("status_summary", "Resumen por estado", "Totales agrupados por estado."),
        ("usecases", "Casos de uso", "Inventario compacto de casos."),
    ],
    ReportDownload.TYPE_LIFECYCLE: [
        ("annual_state", "Estado anual", "Períodos, avance y pendientes."),
        ("reviews", "Últimas revisiones", "Controles lifecycle registrados."),
    ],
    ReportDownload.TYPE_CONTROLS: [
        ("status_summary", "Resumen por estado", "Totales agrupados por estado."),
        ("controls", "Inventario de controles", "Controles y fuentes asociadas."),
    ],
}


def default_sections(report_type):
    return [key for key, *_ in REPORT_SECTION_CHOICES.get(report_type, [])]


def report_template_config(report_type):
    definition = REPORT_DEFINITIONS[report_type]
    config, _ = ReportTemplateConfig.objects.get_or_create(
        report_type=report_type,
        defaults={
            "report_title": definition["title"],
            "sections": default_sections(report_type),
        },
    )
    if not config.sections:
        config.sections = default_sections(report_type)
    return config


def report_filename(report_type):
    definition = REPORT_DEFINITIONS[report_type]
    return f"{definition['filename_prefix']}-{date.today():%Y%m%d}.pdf"


def _shared_logo_path(template_config):
    shared = ReportTemplateConfig.objects.filter(
        report_type=ReportDownload.TYPE_EXECUTIVE,
    ).exclude(logo="").first()
    if shared and shared.logo:
        try:
            return shared.logo.path
        except Exception:
            return ""
    if template_config and template_config.logo:
        try:
            return template_config.logo.path
        except Exception:
            return ""
    return ""


def report_index_context():
    counts = Counter(ReportDownload.objects.values_list("report_type", flat=True))
    cards = []
    for report_type, definition in REPORT_DEFINITIONS.items():
        cards.append({
            "type": report_type,
            "title": definition["title"],
            "subtitle": definition["subtitle"],
            "accent": definition.get("accent", "#2d7aff"),
            "code": definition.get("code", report_type[:2].upper()),
            "count": counts.get(report_type, 0),
        })
    return {
        "cards": cards,
        "total_downloads": sum(counts.values()),
        "report_types": len(REPORT_DEFINITIONS),
    }


def build_report_pdf(report_type, request):
    template_config = report_template_config(report_type)
    if report_type == ReportDownload.TYPE_MITRE:
        buffer = BytesIO()
        build_dashboard_pdf(
            buffer,
            build_dashboard_context(request),
            template_config,
            request.user,
        )
        return buffer.getvalue()

    definition = REPORT_DEFINITIONS[report_type]
    buffer = BytesIO()
    sections = {
        ReportDownload.TYPE_EXECUTIVE: _executive_sections,
        ReportDownload.TYPE_INVENTORY: _inventory_sections,
        ReportDownload.TYPE_LIFECYCLE: _lifecycle_sections,
        ReportDownload.TYPE_CONTROLS: _controls_sections,
    }[report_type](request)
    enabled_sections = set(template_config.sections or default_sections(report_type))
    sections = [section for section in sections if section.get("key") in enabled_sections]
    _render_pdf(buffer, definition["title"], definition["subtitle"], sections, request.user, template_config)
    return buffer.getvalue()


def _as_text(value, default="-"):
    text = str(value if value not in (None, "") else default).replace("\r", " ").replace("\n", " ").strip()
    replacements = {
        "\u00e1": "a", "\u00e9": "e", "\u00ed": "i", "\u00f3": "o", "\u00fa": "u", "\u00f1": "n",
        "\u00c1": "A", "\u00c9": "E", "\u00cd": "I", "\u00d3": "O", "\u00da": "U", "\u00d1": "N",
        "\u00c3\u00a1": "a", "\u00c3\u00a9": "e", "\u00c3\u00ad": "i", "\u00c3\u00b3": "o", "\u00c3\u00ba": "u", "\u00c3\u00b1": "n",
        "\u00c3\u0161": "U", "\u00c3\u0192\u00c2\u0161": "U", "\u00c2\u00b7": "-", "\u00c3\u201a\u00c2\u00b7": "-",
        "\u2014": "-", "\u2013": "-",
    }
    for broken, replacement in replacements.items():
        text = text.replace(broken, replacement)
    return text or default


def _clip(value, max_chars=100):
    text = _as_text(value)
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 3]}..."


def _rows_from_metric_rows(rows, label="Dimension"):
    output = [[label, "Cantidad", "%"]]
    for row in rows[:8]:
        output.append([row["name"], row["value"], f'{row["percent"]}%'])
    return output if len(output) > 1 else [[label, "Cantidad", "%"], ["Sin datos", 0, "0%"]]


def _executive_sections(request):
    ctx = build_executive_dashboard_context(request)
    return [
        {
            "key": "indicators",
            "title": "Indicadores principales",
            "table": [
                ["Indicador", "Valor"],
                ["Casos operativos", ctx["total_cases"]],
                ["Casos en inventario total", ctx["total_inventory_cases"]],
                ["Casos en baja", ctx["retired_cases"]],
                ["Casos en produccion habilitados", ctx["production_cases"]],
                ["Casos en produccion total", ctx["production_total_cases"]],
                ["Productivos deshabilitados", ctx["production_disabled_cases"]],
                ["Casos habilitados", ctx["enabled_cases"]],
                ["Fuentes activas", f'{ctx["active_sources"]} / {ctx["total_sources"]}'],
                ["Controles en producción", f'{ctx["production_controls"]} / {ctx["total_controls"]}'],
                ["Puntos de atencion", ctx["attention_total"]],
            ],
            "widths": [260, 120],
        },
        {"key": "severity", "title": "Distribucion por severidad", "table": _rows_from_metric_rows(ctx["severity_rows"], "Severidad")},
        {"key": "status", "title": "Distribucion por estado", "table": _rows_from_metric_rows(ctx["status_rows"], "Estado")},
        {"key": "sources", "title": "Fuentes principales", "table": _rows_from_metric_rows(ctx["source_rows"], "Fuente")},
    ]


def _inventory_sections(request):
    cases = (
        UseCase.objects
        .select_related("lifecycle_control_owner")
        .prefetch_related("mitre_attacks", "d3fends", "source_links__source")
        .order_by("name")[:60]
    )
    summary = UseCase.objects.values("status").annotate(value=models.Count("id")).order_by("-value", "status")
    rows = [["ID", "Caso de uso", "Estado", "Sev.", "Fuentes", "ATT&CK", "D3FEND"]]
    for usecase in cases:
        sources = ", ".join(link.source.display_name for link in usecase.source_links.all()) or "-"
        rows.append([
            f"#{usecase.pk}",
            usecase.name,
            usecase.status or "-",
            usecase.severity or "-",
            sources,
            usecase.mitre_attacks.count(),
            usecase.d3fends.count(),
        ])
    return [
        {
            "key": "status_summary",
            "title": "Resumen por estado",
            "table": [["Estado", "Cantidad"]] + [[item["status"] or "Sin estado", item["value"]] for item in summary],
            "widths": [240, 120],
        },
        {"key": "usecases", "title": "Casos de uso", "table": rows, "widths": [34, 170, 62, 38, 122, 42, 42]},
    ]


def _lifecycle_sections(request):
    state = lifecycle_state(date.today().year)
    period_rows = [["Período", "Estado", "Casos", "Revisados", "Pendientes", "Avance"]]
    for period in state["periods"]:
        period_rows.append([
            period["label"],
            period["state"],
            period["total_use_cases"],
            period["reviewed_use_cases"],
            period["pending_use_cases"],
            f'{period["progress"]}%',
        ])

    reviews = (
        LifecycleReview.objects
        .select_related("use_case", "control_owner", "completed_by")
        .order_by("-checked_at", "-created_at")[:40]
    )
    review_rows = [["Fecha", "Caso", "Período", "Resultado", "Responsable"]]
    for review in reviews:
        owner = review.control_owner.get_username() if review.control_owner else "-"
        review_rows.append([review.checked_at, review.use_case.name, review.review_type, review.result or review.status, owner])
    return [
        {"key": "annual_state", "title": "Estado anual", "table": period_rows},
        {"key": "reviews", "title": "Últimas revisiones", "table": review_rows, "widths": [58, 205, 80, 95, 80]},
    ]


def _controls_sections(request):
    controls = Control.objects.select_related("source").prefetch_related("use_cases").order_by("code", "name")[:60]
    status = Control.objects.values("status").annotate(value=models.Count("id")).order_by("-value", "status")
    rows = [["Código", "Control", "Fuente", "Estado", "Casos", "Próxima revisión"]]
    for control in controls:
        rows.append([
            control.code,
            control.name,
            control.source.display_name,
            control.status,
            control.use_cases.count(),
            control.next_review_at or "-",
        ])
    return [
        {
            "key": "status_summary",
            "title": "Resumen por estado",
            "table": [["Estado", "Cantidad"]] + [[item["status"] or "Sin estado", item["value"]] for item in status],
            "widths": [240, 120],
        },
        {"key": "controls", "title": "Inventario de controles", "table": rows, "widths": [58, 165, 130, 70, 42, 70]},
    ]


def _render_pdf(buffer, title, subtitle, sections, generated_by, template_config):
    from pathlib import Path
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_RIGHT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Image, LongTable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    page_size = landscape(A4)
    doc = SimpleDocTemplate(
        buffer,
        pagesize=page_size,
        rightMargin=1.25 * cm,
        leftMargin=1.25 * cm,
        topMargin=1.1 * cm,
        bottomMargin=1.35 * cm,
        title=template_config.report_title or title,
    )
    styles = getSampleStyleSheet()
    primary_color = colors.HexColor(template_config.primary_color or "#1d4ed8")
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=primary_color)
    subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=9, leading=12, textColor=colors.HexColor("#4b5563"))
    meta_style = ParagraphStyle("Meta", parent=subtitle_style, alignment=TA_RIGHT)
    section_style = ParagraphStyle("Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=colors.HexColor("#1f2937"), spaceBefore=12, spaceAfter=6)
    cell_style = ParagraphStyle("Cell", parent=styles["Normal"], fontName="Helvetica", fontSize=7.2, leading=9, textColor=colors.HexColor("#111827"), wordWrap="CJK", splitLongWords=1)
    head_style = ParagraphStyle("HeadCell", parent=cell_style, fontName="Helvetica-Bold", textColor=colors.white)

    def p(value, style=cell_style, max_chars=120):
        return Paragraph(escape(_clip(value, max_chars)), style)

    story = []
    logo_path = _shared_logo_path(template_config)
    if logo_path and Path(logo_path).exists():
        story.extend([Image(logo_path, width=90, height=36, kind="proportional"), Spacer(1, 6)])
    story.extend([
        Table(
            [[p(template_config.report_title or title, title_style, 140), p(f"Generado por: {generated_by}<br/>Fecha: {date.today():%d/%m/%Y}", meta_style, 120)]],
            colWidths=[doc.width * 0.66, doc.width * 0.34],
        ),
        Paragraph(escape(template_config.introduction_text or subtitle), subtitle_style),
        Spacer(1, 10),
    ])

    table_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), primary_color),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ])

    for section in sections:
        rows = section["table"] or [["Sin datos"]]
        converted = []
        for row_index, row in enumerate(rows):
            style = head_style if row_index == 0 else cell_style
            converted.append([p(value, style, 95) for value in row])
        story.append(Paragraph(escape(section["title"]), section_style))
        table_cls = LongTable if len(converted) > 16 else Table
        story.append(table_cls(converted, colWidths=section.get("widths"), repeatRows=1, style=table_style))
        story.append(Spacer(1, 8))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFillColorRGB(0.43, 0.47, 0.55)
        canvas.setFont("Helvetica", 8)
        if template_config.show_footer:
            canvas.drawString(document.leftMargin, 22, template_config.footer_text or "SOC Control Manager - Reportes")
            canvas.drawCentredString(document.pagesize[0] / 2, 22, template_config.confidentiality_label or "")
        if template_config.show_page_numbers:
            canvas.drawRightString(document.pagesize[0] - document.rightMargin, 22, f"Pagina {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
