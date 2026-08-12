import re

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from .models import ReportDownload, ReportTemplateConfig


class ReportViewsTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst_group = Group.objects.create(name="Analyst")
        self.readonly_group = Group.objects.create(name="ReadOnly")
        self.analyst = User.objects.create_user("analyst", password="pass")
        self.analyst.groups.add(self.analyst_group)
        self.admin_group = Group.objects.create(name="Admin")
        self.admin = User.objects.create_user("admin", password="pass")
        self.admin.groups.add(self.admin_group)
        self.readonly = User.objects.create_user("readonly", password="pass")
        self.readonly.groups.add(self.readonly_group)

    def test_analyst_can_open_report_center(self):
        self.client.login(username="analyst", password="pass")

        response = self.client.get(reverse("report_index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Centro de reportes")
        self.assertContains(
            response,
            reverse("report_preview", args=[ReportDownload.TYPE_EXECUTIVE]),
        )
        self.assertContains(response, 'class="report-card-link"')
        self.assertNotContains(response, ">Vista previa</a>")

    def test_analyst_can_download_executive_pdf(self):
        self.client.login(username="analyst", password="pass")

        response = self.client.get(reverse("report_download", args=[ReportDownload.TYPE_EXECUTIVE]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertTrue(response.content.startswith(b"%PDF"))
        self.assertEqual(ReportDownload.objects.filter(report_type=ReportDownload.TYPE_EXECUTIVE).count(), 1)

    def test_analyst_can_preview_report_before_download(self):
        self.client.login(username="analyst", password="pass")

        response = self.client.get(reverse("report_preview", args=[ReportDownload.TYPE_EXECUTIVE]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Vista previa real")
        self.assertContains(response, reverse("report_preview_pdf", args=[ReportDownload.TYPE_EXECUTIVE]))
        self.assertContains(response, "Descargar PDF")

    def test_preview_pdf_renders_real_pdf_inline_without_recording_download(self):
        self.client.login(username="analyst", password="pass")

        response = self.client.get(reverse("report_preview_pdf", args=[ReportDownload.TYPE_EXECUTIVE]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertIn("inline", response["Content-Disposition"])
        self.assertEqual(response["X-Frame-Options"], "SAMEORIGIN")
        self.assertTrue(response.content.startswith(b"%PDF"))
        self.assertEqual(ReportDownload.objects.count(), 0)

    def test_all_preview_pdfs_use_same_landscape_page_size(self):
        self.client.login(username="analyst", password="pass")
        expected = (b"841.8898", b"595.2756")

        for report_type, _ in ReportDownload.TYPE_CHOICES:
            with self.subTest(report_type=report_type):
                response = self.client.get(reverse("report_preview_pdf", args=[report_type]))
                media_box = re.search(rb"/MediaBox\s*\[\s*0\s+0\s+([0-9.]+)\s+([0-9.]+)", response.content)

                self.assertIsNotNone(media_box)
                self.assertEqual(media_box.groups(), expected)

    def test_admin_can_update_report_template(self):
        self.client.login(username="admin", password="pass")

        response = self.client.post(reverse("report_template_settings"), {
            "report_type": ReportDownload.TYPE_EXECUTIVE,
            "organization_name": "SOC Demo",
            "document_label": "Gobierno SOC",
            "report_title": "Executive Pack",
            "introduction_text": "Resumen operativo",
            "primary_color": "#0f766e",
            "accent_color": "#f59e0b",
            "footer_text": "Uso interno SOC",
            "confidentiality_label": "Confidencial",
            "sections": ["indicators", "severity"],
            "show_header": "on",
            "show_footer": "on",
            "show_generation_date": "on",
            "show_page_numbers": "on",
        })

        self.assertRedirects(response, reverse("report_preview", args=[ReportDownload.TYPE_EXECUTIVE]))
        config = ReportTemplateConfig.objects.get(report_type=ReportDownload.TYPE_EXECUTIVE)
        self.assertEqual(config.organization_name, "SOC Demo")
        self.assertEqual(config.sections, ["indicators", "severity"])

    def test_readonly_cannot_open_report_center(self):
        self.client.login(username="readonly", password="pass")

        response = self.client.get(reverse("report_index"))

        self.assertEqual(response.status_code, 403)
