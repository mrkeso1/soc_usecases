from datetime import date, timedelta
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.test import RequestFactory
from django.urls import reverse

from apps.dashboard.dashboard import (
    build_dashboard_context,
    build_d3fend_daily_chart,
    build_executive_dashboard_context,
    build_mitre_coverage_timeline,
    save_mitre_coverage_snapshot,
)
from apps.dashboard.reports import build_dashboard_pdf
from apps.dashboard.models import MitreCoverageSnapshot
from apps.mitre.models import D3Fend, MitreAttack
from apps.usecases.models import UseCase
from apps.server_heatmap.models import ServerAsset, ServerCategory


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
        UseCase.objects.create(name="Enabled prod", status=UseCase.STATUS_PRODUCTION, is_enabled=True, objective="Documentado")
        UseCase.objects.create(
            name="Disabled prod",
            status=UseCase.STATUS_PRODUCTION,
            is_enabled=False,
            disabled_reason="Baja operativa",
        )
        UseCase.objects.create(name="Retired", status=UseCase.STATUS_RETIRED, is_enabled=True)
        UseCase.objects.create(name="Test documented", status=UseCase.STATUS_TEST, is_enabled=True, objective="No debe sumar")

        context = build_executive_dashboard_context(self._request("/dashboard/"))

        self.assertEqual(context["production_cases"], 1)
        self.assertEqual(context["production_total_cases"], 2)
        self.assertEqual(context["production_disabled_cases"], 1)
        self.assertEqual(context["retired_cases"], 1)
        self.assertEqual(context["test_cases"], 1)
        self.assertEqual(context["total_inventory_cases"], 4)
        self.assertEqual(context["documented_cases"], 1)
        self.assertEqual(context["documentation_percentage"], 100.0)

    def test_executive_dashboard_status_rows_include_zero_statuses(self):
        for index in range(3):
            UseCase.objects.create(name=f"Production {index}", status=UseCase.STATUS_PRODUCTION)
        UseCase.objects.create(name="Test case", status=UseCase.STATUS_TEST)

        context = build_executive_dashboard_context(self._request("/dashboard/"))
        rows = {item["name"]: item for item in context["status_rows"]}

        self.assertEqual(rows[UseCase.STATUS_PRODUCTION]["value"], 3)
        self.assertEqual(rows[UseCase.STATUS_PRODUCTION]["percent"], 75)
        self.assertEqual(rows[UseCase.STATUS_TEST]["value"], 1)
        self.assertEqual(rows[UseCase.STATUS_TEST]["percent"], 25)
        self.assertEqual(rows[UseCase.STATUS_DEVELOPMENT]["value"], 0)
        self.assertEqual(rows[UseCase.STATUS_DEVELOPMENT]["percent"], 0)
        self.assertEqual(rows[UseCase.STATUS_RETIRED]["value"], 0)
        self.assertEqual(rows[UseCase.STATUS_RETIRED]["percent"], 0)

    def test_executive_heatmap_contains_only_windows_and_linux_unix(self):
        ServerAsset.objects.create(
            hostname="win-covered",
            environment="PROD",
            os_family=ServerAsset.OS_WINDOWS,
            in_active_directory=True,
            in_siem=True,
        )
        ServerAsset.objects.create(
            hostname="linux-pending",
            environment="PROD",
            os_family=ServerAsset.OS_LINUX,
            in_active_directory=True,
            in_siem=False,
        )
        ServerAsset.objects.create(
            hostname="aix-covered",
            environment="PROD",
            os_family=ServerAsset.OS_UNIX,
            in_active_directory=True,
            in_siem=True,
        )
        ServerAsset.objects.create(
            hostname="other-ignored",
            environment="PROD",
            os_family=ServerAsset.OS_OTHER,
            in_active_directory=True,
            in_siem=True,
        )

        context = build_executive_dashboard_context(self._request("/dashboard/?tab=mapa-calor"))

        self.assertEqual([item["name"] for item in context["server_heatmap_rows"]], [
            "Windows",
            "Linux / Unix / AIX",
        ])
        self.assertEqual(
            [item["key"] for item in context["server_heatmap_matrix_rows"]],
            [ServerAsset.OS_WINDOWS, ServerAsset.OS_LINUX],
        )
        self.assertEqual(context["server_heatmap_total"], 3)
        self.assertEqual(context["server_heatmap_covered"], 2)
        self.assertEqual(context["server_heatmap_pending"], 1)
        self.assertEqual(context["server_heatmap_percent"], 66.7)
        self.assertEqual(context["server_heatmap_rows"][1]["total"], 2)
        self.assertEqual(context["server_heatmap_rows"][1]["covered"], 1)
        self.assertTrue(all(
            item["color"] == "#00e5a0"
            and "#00e5a0" in item["gradient"]
            and "#ff4757" in item["gradient"]
            for item in context["server_heatmap_rows"]
        ))

    def test_executive_heatmap_defaults_to_prod_and_all_includes_every_environment(self):
        category = ServerCategory.objects.get(code="application")
        ServerAsset.objects.create(
            hostname="prod-win",
            environment="prod",
            category=category,
            os_family=ServerAsset.OS_WINDOWS,
            in_active_directory=True,
            in_siem=True,
        )
        ServerAsset.objects.create(
            hostname="desa-win",
            environment="DESA",
            category=category,
            os_family=ServerAsset.OS_WINDOWS,
            in_active_directory=True,
            in_siem=False,
        )

        default_context = build_executive_dashboard_context(
            self._request("/dashboard/?tab=mapa-calor")
        )
        all_context = build_executive_dashboard_context(
            self._request("/dashboard/?tab=mapa-calor&environment=all")
        )

        self.assertEqual(default_context["selected_server_environment"], "PROD")
        self.assertEqual(default_context["server_heatmap_total"], 1)
        self.assertEqual(all_context["server_heatmap_total"], 2)
        self.assertEqual(all_context["server_heatmap_pending"], 1)
        self.assertEqual(all_context["server_environment_choices"], ["DESA", "PROD"])
        default_windows = next(
            row for row in default_context["server_heatmap_matrix_rows"]
            if row["key"] == ServerAsset.OS_WINDOWS
        )
        all_windows = next(
            row for row in all_context["server_heatmap_matrix_rows"]
            if row["key"] == ServerAsset.OS_WINDOWS
        )
        default_cell = next(
            cell for cell in default_windows["cells"]
            if cell["category"].id == category.id
        )
        all_cell = next(
            cell for cell in all_windows["cells"]
            if cell["category"].id == category.id
        )
        self.assertEqual(default_cell["ad_count"], 1)
        self.assertEqual(default_cell["percent"], 100.0)
        self.assertEqual(all_cell["ad_count"], 2)
        self.assertEqual(all_cell["pending"], 1)

    def test_executive_heatmap_critical_wheel_ignores_os_and_section(self):
        ServerAsset.objects.create(
            hostname="critical-other-covered",
            environment="PROD",
            os_family=ServerAsset.OS_OTHER,
            is_critical=True,
            in_active_directory=True,
            in_siem=True,
        )
        ServerAsset.objects.create(
            hostname="critical-windows-pending",
            environment="PROD",
            os_family=ServerAsset.OS_WINDOWS,
            is_critical=True,
            in_active_directory=True,
            in_siem=False,
        )
        ServerAsset.objects.create(
            hostname="standard-covered",
            environment="PROD",
            is_critical=False,
            in_active_directory=True,
            in_siem=True,
        )
        ServerAsset.objects.create(
            hostname="critical-disabled",
            environment="PROD",
            is_critical=True,
            is_enabled=False,
            in_active_directory=True,
            in_siem=False,
        )

        context = build_executive_dashboard_context(
            self._request("/dashboard/?tab=mapa-calor")
        )

        critical = context["server_critical_coverage"]
        self.assertEqual(critical["total"], 2)
        self.assertEqual(critical["covered"], 1)
        self.assertEqual(critical["pending"], 1)
        self.assertEqual(critical["percent"], 50.0)
        self.assertEqual(critical["color"], "#00e5a0")
        self.assertIn("#ff4757", critical["gradient"])

    def test_executive_heatmap_renders_thermometer_and_three_rings_in_order(self):
        self.client.force_login(self.user)

        response = self.client.get(
            reverse("dashboard"),
            {"tab": "mapa-calor", "environment": "all"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'class="heat-summary-card"', count=1)
        self.assertContains(response, 'class="heat-os-card"', count=3)
        content = response.content.decode()
        self.assertLess(content.index("Cobertura general"), content.index("Windows"))
        self.assertLess(content.index("Windows"), content.index("Linux / Unix / AIX"))
        self.assertLess(content.index("Linux / Unix / AIX"), content.index("Servidores críticos"))

    def test_executive_distribution_bars_use_total_cases_as_one_hundred_percent(self):
        UseCase.objects.create(name="ICBC 1", status=UseCase.STATUS_PRODUCTION, owner_name="ICBC")
        UseCase.objects.create(name="ICBC 2", status=UseCase.STATUS_PRODUCTION, owner_name="ICBC")
        UseCase.objects.create(name="Other", status=UseCase.STATUS_PRODUCTION, owner_name="Otro")

        context = build_executive_dashboard_context(self._request("/dashboard/"))
        owners = {item["name"]: item for item in context["owner_rows"]}

        self.assertEqual(owners["ICBC"]["value"], 2)
        self.assertEqual(owners["ICBC"]["percent"], 67)
        self.assertEqual(owners["ICBC"]["bar_percent"], 67)

    def test_inventory_quality_uses_all_production_cases_regardless_of_enabled_state(self):
        UseCase.objects.create(
            name="Production with rule",
            status=UseCase.STATUS_PRODUCTION,
            is_enabled=True,
            full_rule_text="regla",
        )
        UseCase.objects.create(name="Production without rule", status=UseCase.STATUS_PRODUCTION, is_enabled=True)
        UseCase.objects.create(
            name="Disabled production with rule",
            status=UseCase.STATUS_PRODUCTION,
            is_enabled=False,
            disabled_reason="Deshabilitado para prueba",
            full_rule_text="también debe sumar",
        )
        UseCase.objects.create(
            name="Test with rule",
            status=UseCase.STATUS_TEST,
            is_enabled=True,
            full_rule_text="no debe sumar",
        )

        context = build_executive_dashboard_context(self._request("/dashboard/"))
        quality = {item["name"]: item for item in context["inventory_quality_rows"]}

        self.assertEqual(quality["Regla / logica"]["value"], 2)
        self.assertEqual(quality["Regla / logica"]["total"], 3)
        self.assertEqual(quality["Regla / logica"]["percent"], 66.7)

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

    def test_d3fend_daily_chart_uses_each_snapshot_in_selected_period(self):
        today = date.today()
        MitreCoverageSnapshot.objects.create(
            snapshot_date=today - timedelta(days=2),
            d3fend_detect_percent=10,
        )
        MitreCoverageSnapshot.objects.create(
            snapshot_date=today - timedelta(days=1),
            d3fend_detect_percent=25,
        )
        MitreCoverageSnapshot.objects.create(
            snapshot_date=today,
            d3fend_detect_percent=40,
        )

        chart = build_d3fend_daily_chart(days=30)

        self.assertEqual(chart["day_count"], 30)
        self.assertEqual(len(chart["rows"]), 3)
        self.assertEqual(chart["rows"][-2]["value"], 25)
        self.assertEqual(chart["rows"][-1]["value"], 40)

    def test_mitre_dashboard_view_does_not_overwrite_daily_snapshot(self):
        attack = MitreAttack.objects.create(external_id="T1001", name="Covered", tactic="Execution")
        d3fend = D3Fend.objects.create(code="D3-DAO", name="Decoy Object", category="Detect")
        d3fend.related_attacks.add(attack)
        usecase = UseCase.objects.create(name="Enabled prod", status=UseCase.STATUS_PRODUCTION, is_enabled=True)
        usecase.mitre_attacks.add(attack)
        usecase.d3fends.add(d3fend)
        self.client.login(username="dashboard-user", password="pass")

        response = self.client.get(reverse("dashboard_mitre"))

        self.assertEqual(response.status_code, 200)
        self.assertFalse(MitreCoverageSnapshot.objects.filter(snapshot_date=date.today()).exists())
        self.assertTrue(response.context["d3fend_daily_chart"]["has_data"])
        self.assertIsNotNone(response.context["d3fend_daily_chart"]["latest"])

    @patch("apps.dashboard.views.build_dashboard_context")
    def test_mitre_detail_endpoint_paginates_and_sorts_without_full_page(self, build_context):
        build_context.return_value = {
            "tactic_coverage_rows": [
                {
                    "name": f"Tactica {index}",
                    "covered": index,
                    "total": 10,
                    "percent": index * 10,
                    "percent_label": str(index * 10),
                    "production_cases": 0,
                }
                for index in range(1, 8)
            ]
        }
        self.client.login(username="dashboard-user", password="pass")

        response = self.client.get(reverse("dashboard_mitre_details"), {
            "panel": "tactic_coverage",
            "page": 2,
            "sort": "asc",
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Tactica 7")
        self.assertNotContains(response, "Tactica 1")
        self.assertContains(response, "Pagina 2 de 2")
        self.assertNotContains(response, "Dashboard MITRE")
