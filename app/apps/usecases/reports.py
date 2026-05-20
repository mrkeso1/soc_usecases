"""Report builders for use-case dashboard exports.

Views should decide HTTP concerns only. This module owns ReportLab layout,
branding settings, and PDF table formatting.
"""

from datetime import date
from xml.sax.saxutils import escape

from django.db import OperationalError, ProgrammingError

from .models import DashboardReportSettings

DEFAULT_REPORT_TITLE = "Reporte ejecutivo SOC"
DEFAULT_REPORT_SUBTITLE = "Cobertura ATT&CK y D3FEND sobre casos de uso en producción"
DEFAULT_REPORT_FOOTER = "SOC Use Cases Manager"


def get_active_dashboard_report_settings():
    """Return active report settings, tolerating deployments before migration."""
    try:
        return DashboardReportSettings.objects.filter(is_active=True).order_by("-updated_at").first()
    except (OperationalError, ProgrammingError):
        return None


def _as_text(value, default="-"):
    text = str(value if value is not None else default).replace("\r", " ").replace("\n", " ").strip()
    return text or default


def _clip(value, max_chars=140):
    text = _as_text(value)
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 3]}..."


def _pdf_metric_table(metrics):
    # Defensive filter: old contexts may still include the removed manual D3FEND metric.
    clean_metrics = [
        metric for metric in metrics
        if "manual" not in _as_text(metric.get("title", "")).lower()
    ]
    return [
        [m["title"], f'{m["percent_label"]}%', f'{m["covered"]} / {m["total"]}']
        for m in clean_metrics
    ]


def _draw_pdf_footer(canvas, doc, footer_text):
    canvas.saveState()
    canvas.setFillColorRGB(0.45, 0.49, 0.56)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(doc.leftMargin, 24, footer_text or DEFAULT_REPORT_FOOTER)
    canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 24, f"Página {doc.page}")
    canvas.restoreState()


def _safe_table_rows(items, code_attr, subtitle_attr=None, limit=12):
    rows = []
    for item in list(items)[:limit]:
        code = getattr(item, code_attr, "")
        name = getattr(item, "name", "")
        subtitle = getattr(item, subtitle_attr, "") if subtitle_attr else ""
        rows.append([_as_text(code), _as_text(name), _as_text(subtitle)])
    return rows or [["-", "Sin pendientes", "-"]]


def _d3fend_executive_rows(coverage_rows, limit=35):
    rows = []
    ordered_rows = sorted(coverage_rows, key=lambda item: item[0], reverse=True)
    for coverage_ratio, d3fend in ordered_rows[:limit]:
        if coverage_ratio >= 1:
            continue
        rows.append([
            _as_text(getattr(d3fend, "code", "-")),
            _as_text(getattr(d3fend, "name", "") or "-"),
            _as_text(getattr(d3fend, "category", "") or "-"),
            f"{round(coverage_ratio * 100, 1)}%",
        ])
    return rows or [["-", "Sin pendientes", "-", "-"]]


def build_dashboard_pdf(buffer, context, report_settings, generated_by):
    """Render the dashboard context into a PDF written to ``buffer``."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Image, LongTable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    page_width, _ = A4
    left_margin = 1.35 * cm
    right_margin = 1.35 * cm
    content_width = page_width - left_margin - right_margin

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=right_margin,
        leftMargin=left_margin,
        topMargin=1.2 * cm,
        bottomMargin=1.45 * cm,
        title="Dashboard SOC",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#111827"),
        spaceAfter=6,
    )
    brand_style = ParagraphStyle(
        "BrandTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=22,
        textColor=colors.HexColor("#111827"),
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#4b5563"),
    )
    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11.5,
        leading=14,
        textColor=colors.HexColor("#1f2937"),
        spaceBefore=13,
        spaceAfter=7,
    )
    right_style = ParagraphStyle(
        "RightMeta",
        parent=styles["Normal"],
        alignment=TA_RIGHT,
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#6b7280"),
    )
    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.3,
        leading=9,
        textColor=colors.HexColor("#111827"),
        wordWrap="CJK",
        splitLongWords=1,
    )
    header_cell_style = ParagraphStyle(
        "TableHeaderCell",
        parent=cell_style,
        fontName="Helvetica-Bold",
        fontSize=7.4,
        leading=9,
        textColor=colors.HexColor("#111827"),
    )
    kpi_label_style = ParagraphStyle(
        "KpiLabel",
        parent=cell_style,
        fontName="Helvetica-Bold",
        fontSize=7.5,
        textColor=colors.HexColor("#4b5563"),
    )
    kpi_value_style = ParagraphStyle(
        "KpiValue",
        parent=cell_style,
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=13,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#111827"),
    )

    def p(value, style=None, max_chars=140):
        return Paragraph(escape(_clip(value, max_chars)), style or cell_style)

    def paragraph_rows(rows, max_by_col=None):
        max_by_col = max_by_col or {}
        converted = []
        for row_number, row in enumerate(rows):
            style = header_cell_style if row_number == 0 else cell_style
            converted.append([
                p(value, style, max_by_col.get(col_number, 140))
                for col_number, value in enumerate(row)
            ])
        return converted

    def base_table_style(header_bg, grid_color, header_fg=None):
        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), header_bg),
            ("TEXTCOLOR", (0, 0), (-1, 0), header_fg or colors.HexColor("#111827")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.35, grid_color),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fbfdff")]),
        ])

    story = []
    title = report_settings.report_title if report_settings else DEFAULT_REPORT_TITLE
    subtitle = report_settings.report_subtitle if report_settings else DEFAULT_REPORT_SUBTITLE
    footer = report_settings.footer_text if report_settings else DEFAULT_REPORT_FOOTER

    if report_settings and report_settings.logo:
        try:
            header_left = Image(report_settings.logo.path)
            header_left._restrictSize(4.0 * cm, 1.6 * cm)
        except Exception:
            header_left = Paragraph("SOC", brand_style)
    else:
        header_left = Paragraph("SOC", brand_style)

    filters = []
    if context.get("selected_device"):
        filters.append(f'Dispositivo: {context["selected_device"]}')
    if context.get("selected_severity"):
        filters.append(f'Severidad: {context["selected_severity"]}')
    if context.get("selected_enabled"):
        filters.append(f'Habilitado: {"Sí" if context["selected_enabled"] == "yes" else "No"}')
    filter_text = " - ".join(filters) if filters else "Sin filtros adicionales"

    meta = Paragraph(
        escape(f"Generado: {date.today():%d/%m/%Y}")
        + "<br/>"
        + escape(f"Usuario: {getattr(generated_by, 'username', '-')}")
        + "<br/>"
        + escape(filter_text),
        right_style,
    )
    header = Table([[header_left, meta]], colWidths=[content_width * 0.58, content_width * 0.42])
    header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.6, colors.HexColor("#d1d5db")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(header)
    story.append(Spacer(1, 10))
    story.append(Paragraph(escape(_as_text(title)), title_style))
    story.append(Paragraph(escape(_as_text(subtitle)), subtitle_style))
    story.append(Spacer(1, 10))

    kpi_items = [
        ("Casos productivos", context.get("total_cases", 0)),
        ("ATT&CK técnicas", f'{context.get("covered_attack_techniques", 0)} / {context.get("all_attack_techniques", 0)}'),
        ("ATT&CK tácticas", f'{context.get("covered_tactics", 0)} / {context.get("total_tactics", 0)}'),
        ("D3FEND inferido", f'{context.get("covered_d3fend_techniques", 0)} / {context.get("all_d3fend_techniques", 0)}'),
        ("D3FEND 100% cubiertos", f'{context.get("fully_covered_d3fend_techniques", 0)} / {context.get("all_d3fend_techniques", 0)}'),
        ("D3FEND parciales", f'{context.get("partially_covered_d3fend_techniques", 0)} / {context.get("all_d3fend_techniques", 0)}'),
    ]
    kpi_rows = []
    for idx in range(0, len(kpi_items), 3):
        kpi_rows.append([
            [p(label, kpi_label_style, 42), p(value, kpi_value_style, 24)]
            for label, value in kpi_items[idx:idx + 3]
        ])
    kpi_table = Table(kpi_rows, colWidths=[content_width / 3] * 3, hAlign="LEFT")
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.45, colors.HexColor("#dbe3ef")),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#e5e7eb")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(kpi_table)

    metric_widths = [content_width * 0.58, content_width * 0.15, content_width * 0.27]
    for title_text, metrics in (
        ("Cobertura ATT&CK", context.get("attack_radials", [])),
        ("Cobertura D3FEND inferida", context.get("d3fend_radials", [])),
    ):
        story.append(Paragraph(escape(title_text), section_style))
        rows = [["Métrica", "%", "Cubierto / Total"]] + _pdf_metric_table(metrics)
        table = LongTable(paragraph_rows(rows, {0: 90, 1: 12, 2: 24}), colWidths=metric_widths, repeatRows=1)
        table.setStyle(base_table_style(colors.HexColor("#eaf2ff"), colors.HexColor("#dbe3ef"), colors.HexColor("#1d4ed8")))
        story.append(table)

    story.append(Paragraph(escape("Pendientes ATT&CK"), section_style))
    attack_rows = [["ID", "Técnica", "Táctica"]] + _safe_table_rows(
        context.get("uncovered_attacks", []),
        "external_id",
        "tactic",
        limit=12,
    )
    table = LongTable(
        paragraph_rows(attack_rows, {0: 18, 1: 115, 2: 70}),
        colWidths=[content_width * 0.15, content_width * 0.62, content_width * 0.23],
        repeatRows=1,
    )
    table.setStyle(base_table_style(colors.HexColor("#fff7ed"), colors.HexColor("#fed7aa"), colors.HexColor("#9a3412")))
    story.append(table)

    story.append(Paragraph(escape("Pendientes D3FEND por cobertura ATT&CK inferida"), section_style))
    d3_rows = [["Código", "Control", "Categoría"]] + _safe_table_rows(
        context.get("uncovered_d3fends", []),
        "code",
        "category",
        limit=12,
    )
    table = LongTable(
        paragraph_rows(d3_rows, {0: 20, 1: 115, 2: 70}),
        colWidths=[content_width * 0.15, content_width * 0.62, content_width * 0.23],
        repeatRows=1,
    )
    table.setStyle(base_table_style(colors.HexColor("#ecfdf5"), colors.HexColor("#bbf7d0"), colors.HexColor("#047857")))
    story.append(table)

    story.append(Paragraph("Detalle ejecutivo D3FEND", section_style))
    executive_rows = [["Código", "Nombre", "Categoría", "% actual"]] + _d3fend_executive_rows(
        context.get("d3fend_coverage_rows", []),
        limit=35,
    )
    executive_table = LongTable(
        paragraph_rows(executive_rows, {0: 18, 1: 105, 2: 65, 3: 14}),
        colWidths=[content_width * 0.14, content_width * 0.50, content_width * 0.24, content_width * 0.12],
        repeatRows=1,
    )
    executive_table.setStyle(base_table_style(colors.HexColor("#dcfce7"), colors.HexColor("#bbf7d0"), colors.HexColor("#166534")))
    story.append(executive_table)

    doc.build(
        story,
        onFirstPage=lambda c, d: _draw_pdf_footer(c, d, footer),
        onLaterPages=lambda c, d: _draw_pdf_footer(c, d, footer),
    )
