from datetime import date
from io import BytesIO
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.test import RequestFactory
from django.urls import reverse

from apps.dashboard.dashboard import (
    build_dashboard_context,
    build_executive_dashboard_context,
    build_mitre_coverage_timeline,
    save_mitre_coverage_snapshot,
)
from apps.dashboard.reports import build_dashboard_pdf
from apps.dashboard.models import MitreCoverageSnapshot
from apps.mitre.models import D3Fend, MitreAttack
from apps.usecases.models import UseCase


class DashboardPdfReportTests(TestCase):
    def test_dashboard_pdf_renders_with_charts(self):
        buffer = BytesIO()
        context = {
            "total_cases": 5,
            "covered_attack_techniques": 3,
            "all_attack_techniques": 10,
            "covered_tactics": 2,
            "total_tactics": 4,
            "covered_d3fend_techniques": 2.5,
            "all_d3fend_techniques": 8,
            "fully_covered_d3fend_techniques": 2,
            "partially_covered_d3fend_techniques": 3,
            "attack_radials": [
                {"title": "Cobertura Técnicas ATT&CK", "percent": 30, "percent_label": "30", "covered": 3, "total": 10},
                {"title": "Tácticas ATT&CK al 100%", "percent": 50, "percent_label": "50", "covered": 2, "total": 4},
            ],
            "d3fend_radials": [
                {"title": "Cobertura D3FEND inferida por ATT&CK", "percent": 31.3, "percent_label": "31,3", "covered": 2.5, "total": 8},
                {"title": "D3FEND Detect al 100%", "percent": 25, "percent_label": "25", "covered": 2, "total": 8},
            ],
            "uncovered_attacks": [],
            "uncovered_d3fends": [],
            "d3fend_coverage_rows": [],
        }

        build_dashboard_pdf(buffer, context, None, SimpleNamespace(username="tester"))

        self.assertTrue(buffer.getvalue().startswith(b"%PDF"))


class DashboardInventoryScopeTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("dashboard-user", password="pass")
        self.factory = RequestFactory()

    def _request(self, path):
        request = self.factory.get(path)
        request.user = self.user
        return request

    def test_executive_dashboard_counts_enabled_production_separately(self):
        UseCase.objects.create(name="Enabled prod", status=UseCase.STATUS_PRODUCTION, is_enabled=True)
        UseCase.objects.create(
            name="Disabled prod",
            status=UseCase.STATUS_PRODUCTION,
            is_enabled=False,
            disabled_reason="Baja operativa",
        )
        UseCase.objects.create(name="Retired", status=UseCase.STATUS_RETIRED, is_enabled=True)

        context = build_executive_dashboard_context(self._request("/dashboard/"))

        self.assertEqual(context["production_cases"], 1)
        self.assertEqual(context["production_total_cases"], 2)
        self.assertEqual(context["production_disabled_cases"], 1)
        self.assertEqual(context["retired_cases"], 1)

    def test_mitre_dashboard_defaults_to_enabled_production(self):
        UseCase.objects.create(name="Enabled prod", status=UseCase.STATUS_PRODUCTION, is_enabled=True)
        UseCase.objects.create(
            name="Disabled prod",
            status=UseCase.STATUS_PRODUCTION,
            is_enabled=False,
            disabled_reason="Baja operativa",
        )

        default_context = build_dashboard_context(self._request("/dashboard/mitre/"))
        all_context = build_dashboard_context(self._request("/dashboard/mitre/?enabled=all"))

        self.assertEqual(default_context["total_cases"], 1)
        self.assertEqual(default_context["production_total_cases"], 2)
        self.assertEqual(default_context["production_disabled_cases"], 1)
        self.assertEqual(all_context["total_cases"], 2)

    def test_mitre_dashboard_builds_d3fend_detect_coverage_rows(self):
        attack = MitreAttack.objects.create(external_id="T1001", name="Data Obfuscation", tactic="Defense Evasion")
        d3fend = D3Fend.objects.create(code="D3-DAO", name="Decoy Object", category="Detect")
        d3fend.related_attacks.add(attack)
        usecase = UseCase.objects.create(name="Enabled prod", status=UseCase.STATUS_PRODUCTION, is_enabled=True)
        usecase.mitre_attacks.add(attack)
        usecase.d3fends.add(d3fend)

        context = build_dashboard_context(self._request("/dashboard/mitre/"))
        rows = context["d3fend_detect_coverage_rows"]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["code"], "D3-DAO")
        self.assertEqual(rows[0]["name"], "Decoy Object")
        self.assertEqual(rows[0]["covered"], "1")
        self.assertEqual(rows[0]["total"], "1")
        self.assertEqual(rows[0]["production_cases"], 1)

    def test_mitre_dashboard_respects_usecase_d3fend_exclusions(self):
        attack = MitreAttack.objects.create(external_id="T1110", name="Brute Force", tactic="Credential Access")
        d3fend = D3Fend.objects.create(code="D3-ANAA", name="Account Authentication Analysis", category="Detect")
        d3fend.related_attacks.add(attack)
        usecase = UseCase.objects.create(name="VPN brute force", status=UseCase.STATUS_PRODUCTION, is_enabled=True)
        usecase.mitre_attacks.add(attack)
        usecase.sync_d3fends_from_attacks()
        usecase.d3fend_exclusions.add(d3fend)
        usecase.sync_d3fends_from_attacks()

        context = build_dashboard_context(self._request("/dashboard/mitre/"))

        self.assertEqual(context["attack_radials"][0]["percent"], 100)
        self.assertEqual(context["d3fend_radials"][0]["percent"], 0)
        self.assertEqual(context["covered_d3fend_techniques"], 0)

    def test_mitre_dashboard_counts_only_fully_covered_tactics(self):
        covered_attack = MitreAttack.objects.create(external_id="T1001", name="Covered", tactic="Execution")
        MitreAttack.objects.create(external_id="T1002", name="Uncovered", tactic="Execution")
        usecase = UseCase.objects.create(name="Enabled prod", status=UseCase.STATUS_PRODUCTION, is_enabled=True)
        usecase.mitre_attacks.add(covered_attack)

        context = build_dashboard_context(self._request("/dashboard/mitre/"))

        self.assertEqual(context["covered_tactics"], 0)
        self.assertEqual(context["total_tactics"], 1)

    def test_mitre_coverage_snapshot_feeds_timeline(self):
        attack = MitreAttack.objects.create(external_id="T1001", name="Covered", tactic="Execution")
        d3fend = D3Fend.objects.create(code="D3-DAO", name="Decoy Object", category="Detect")
        d3fend.related_attacks.add(attack)
        usecase = UseCase.objects.create(name="Enabled prod", status=UseCase.STATUS_PRODUCTION, is_enabled=True)
        usecase.mitre_attacks.add(attack)
        usecase.d3fends.add(d3fend)

        context = build_dashboard_context(self._request("/dashboard/mitre/"))
        snapshot = save_mitre_coverage_snapshot(context, snapshot_date=date(2026, 6, 26))
        timeline = build_mitre_coverage_timeline(days=365)

        self.assertEqual(snapshot.coverage_score, 100)
        self.assertEqual(timeline["count"], 1)
        self.assertEqual(timeline["latest"]["score"], 100)

    def test_mitre_dashboard_view_captures_today_snapshot(self):
        attack = MitreAttack.objects.create(external_id="T1001", name="Covered", tactic="Execution")
        d3fend = D3Fend.objects.create(code="D3-DAO", name="Decoy Object", category="Detect")
        d3fend.related_attacks.add(attack)
        usecase = UseCase.objects.create(name="Enabled prod", status=UseCase.STATUS_PRODUCTION, is_enabled=True)
        usecase.mitre_attacks.add(attack)
        usecase.d3fends.add(d3fend)
        self.client.login(username="dashboard-user", password="pass")

        response = self.client.get(reverse("dashboard_mitre"))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(MitreCoverageSnapshot.objects.filter(snapshot_date=date.today()).exists())
        self.assertGreaterEqual(response.context["mitre_risk_overview"]["count"], 1)
