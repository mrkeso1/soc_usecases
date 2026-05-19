"""Report builders for use-case dashboard exports.

Views should decide HTTP concerns only. This module owns ReportLab layout,
branding settings, and PDF table formatting.
"""

from datetime import date

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


def _pdf_metric_table(metrics):
    return [[m["title"], f'{m["percent_label"]}%', f'{m["covered"]} / {m["total"]}'] for m in metrics]


def _draw_pdf_footer(canvas, doc, footer_text):
    canvas.saveState()
    canvas.setFillColorRGB(0.45, 0.49, 0.56)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(doc.leftMargin, 24, footer_text or DEFAULT_REPORT_FOOTER)
    canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 24, f"Página {doc.page}")
    canvas.restoreState()


def _safe_table_rows(items, code_attr, subtitle_attr=None, limit=10):
    rows = []
    for item in list(items)[:limit]:
        code = getattr(item, code_attr, "")
        name = getattr(item, "name", "")
        subtitle = getattr(item, subtitle_attr, "") if subtitle_attr else ""
        rows.append([str(code), str(name or "-"), str(subtitle or "-")])
    return rows or [["-", "Sin pendientes", "-"]]



def _d3fend_executive_rows(coverage_rows, limit=50):
    rows = []
    ordered_rows = sorted(coverage_rows, key=lambda item: item[0], reverse=True)
    for coverage_ratio, d3fend in ordered_rows[:limit]:
        if coverage_ratio >= 1:
            continue
        rows.append([
            str(getattr(d3fend, "code", "-")),
            str(getattr(d3fend, "name", "") or "-"),
            str(getattr(d3fend, "category", "") or "-"),
            f'{round(coverage_ratio * 100, 1)}%',
        ])
    return rows or [["-", "Sin pendientes", "-", "-"]]

def build_dashboard_pdf(buffer, context, report_settings, generated_by):
    """Render the dashboard context into a PDF written to ``buffer``."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=1.4 * cm,
        leftMargin=1.4 * cm,
        topMargin=1.2 * cm,
        bottomMargin=1.2 * cm,
        title="Dashboard SOC",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=18, textColor=colors.HexColor("#111827"), spaceAfter=6)
    subtitle_style = ParagraphStyle("ReportSubtitle", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#4b5563"), leading=12)
    section_style = ParagraphStyle("Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, textColor=colors.HexColor("#1f2937"), spaceBefore=14, spaceAfter=7)
    right_style = ParagraphStyle("RightMeta", parent=styles["Normal"], alignment=TA_RIGHT, fontSize=8, textColor=colors.HexColor("#6b7280"), leading=11)

    story = []
    title = report_settings.report_title if report_settings else DEFAULT_REPORT_TITLE
    subtitle = report_settings.report_subtitle if report_settings else DEFAULT_REPORT_SUBTITLE
    footer = report_settings.footer_text if report_settings else DEFAULT_REPORT_FOOTER

    header_left = []
    if report_settings and report_settings.logo:
        try:
            logo = Image(report_settings.logo.path)
            logo._restrictSize(4.2 * cm, 1.8 * cm)
            header_left.append(logo)
        except Exception:
            header_left.append(Paragraph("SOC", title_style))
    else:
        header_left.append(Paragraph("SOC", title_style))

    filters = []
    if context.get("selected_device"):
        filters.append(f'Dispositivo: {context["selected_device"]}')
    if context.get("selected_severity"):
        filters.append(f'Severidad: {context["selected_severity"]}')
    if context.get("selected_enabled"):
        filters.append(f'Habilitado: {"Sí" if context["selected_enabled"] == "yes" else "No"}')
    filter_text = " · ".join(filters) if filters else "Sin filtros adicionales"
    meta = Paragraph(
        f"Generado: {date.today():%d/%m/%Y}<br/>Usuario: {getattr(generated_by, 'username', '-')}<br/>{filter_text}",
        right_style,
    )
    header = Table([[header_left, meta]], colWidths=[10.2 * cm, 7.0 * cm])
    header.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.6, colors.HexColor("#d1d5db")), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    story.append(header)
    story.append(Spacer(1, 10))
    story.append(Paragraph(title, title_style))
    story.append(Paragraph(subtitle, subtitle_style))
    story.append(Spacer(1, 10))

    kpis = [
        ["Casos productivos", context["total_cases"]],
        ["ATT&CK técnicas", f'{context["covered_attack_techniques"]} / {context["all_attack_techniques"]}'],
        ["ATT&CK tácticas", f'{context["covered_tactics"]} / {context["total_tactics"]}'],
        ["D3FEND inferido", f'{context["covered_d3fend_techniques"]} / {context["all_d3fend_techniques"]}'],
        ["D3FEND 100% / parcial", f'{context["fully_covered_d3fend_techniques"]} / {context["partially_covered_d3fend_techniques"]}'],
        ["Casos con D3FEND manual", f'{context["productive_with_d3fend"]} / {context["total_cases"]}'],
    ]
    kpi_table = Table(kpis, colWidths=[6.5 * cm, 3.0 * cm])
    kpi_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")), ("PADDING", (0, 0), (-1, -1), 7)]))
    story.append(kpi_table)

    for title_text, metrics in (("Cobertura ATT&CK", context["attack_radials"]), ("Cobertura D3FEND", context["d3fend_radials"])):
        story.append(Paragraph(title_text, section_style))
        rows = [["Métrica", "%", "Cubierto / Total"]] + _pdf_metric_table(metrics)
        table = Table(rows, colWidths=[9.5 * cm, 2.5 * cm, 4.5 * cm], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf2ff")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1d4ed8")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dbe3ef")), ("PADDING", (0, 0), (-1, -1), 6)]))
        story.append(table)

    story.append(Paragraph("Pendientes y principales técnicas", section_style))
    attack_rows = [["ID", "Técnica", "Táctica"]] + _safe_table_rows(context["uncovered_attacks"], "external_id", "tactic")
    table = Table(attack_rows, colWidths=[2.4 * cm, 10.2 * cm, 4.0 * cm], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fff7ed")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#9a3412")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#fed7aa")), ("PADDING", (0, 0), (-1, -1), 5)]))
    story.append(table)

    story.append(Spacer(1, 8))
    d3_rows = [["Código", "Control", "Categoría"]] + _safe_table_rows(context["uncovered_d3fends"], "code", "category")
    table = Table(d3_rows, colWidths=[2.4 * cm, 10.2 * cm, 4.0 * cm], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ecfdf5")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#047857")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#bbf7d0")), ("PADDING", (0, 0), (-1, -1), 5)]))
    story.append(table)

    story.append(Paragraph("Informe ejecutivo D3FEND", section_style))
    executive_kpis = [
        ["Cobertura global D3FEND", f'{context.get("global_d3fend_coverage_percent", 0)}%'],
        ["Técnicas 100% cubiertas", f'{context.get("fully_covered_d3fend_techniques", 0)} / {context.get("all_d3fend_techniques", 0)}'],
    ]
    executive_kpi_table = Table(executive_kpis, colWidths=[7.5 * cm, 4.0 * cm])
    executive_kpi_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")), ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#86efac")), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("PADDING", (0, 0), (-1, -1), 6)]))
    story.append(executive_kpi_table)

    story.append(Spacer(1, 8))
    executive_rows = [["Código", "Nombre", "Categoría", "% actual"]] + _d3fend_executive_rows(context.get("d3fend_coverage_rows", []), limit=50)
    executive_table = Table(executive_rows, colWidths=[2.2 * cm, 8.3 * cm, 4.0 * cm, 2.1 * cm], repeatRows=1)
    executive_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dcfce7")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#166534")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#bbf7d0")), ("PADDING", (0, 0), (-1, -1), 5)]))
    story.append(executive_table)

    doc.build(story, onFirstPage=lambda c, d: _draw_pdf_footer(c, d, footer), onLaterPages=lambda c, d: _draw_pdf_footer(c, d, footer))
