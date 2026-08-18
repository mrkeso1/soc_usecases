from datetime import datetime, timedelta

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.dashboard.inventory_metrics import build_inventory_dashboard_context
from apps.server_heatmap.models import ServerAsset, ServerInventoryConfiguration


class InventoryDashboardMetricsTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("inventory-dashboard-user", password="pass")
        self.factory = RequestFactory()
        configuration = ServerInventoryConfiguration.load()
        configuration.dashboard_period_days = 7
        configuration.ingestion_sla_days = 3
        configuration.dashboard_default_environment = "PROD"
        configuration.dashboard_enabled_only = True
        configuration.dashboard_page_size = 10
        configuration.save()
        self.now = timezone.make_aware(datetime(2026, 8, 18, 12, 0))

        ServerAsset.objects.create(
            hostname="new-pending",
            environment="PROD",
            in_active_directory=True,
            in_siem=False,
            ad_first_seen_at=self.now - timedelta(days=2),
        )
        ServerAsset.objects.create(
            hostname="old-overdue",
            environment="PROD",
            is_critical=True,
            in_active_directory=True,
            in_siem=False,
            ad_first_seen_at=self.now - timedelta(days=5),
        )
        ServerAsset.objects.create(
            hostname="completed",
            environment="PROD",
            in_active_directory=True,
            in_siem=True,
            ad_first_seen_at=self.now - timedelta(days=4),
            siem_first_seen_at=self.now - timedelta(days=2),
        )
        ServerAsset.objects.create(
            hostname="lab-ignored",
            environment="LAB",
            in_active_directory=True,
            in_siem=False,
            ad_first_seen_at=self.now - timedelta(days=1),
        )
        ServerAsset.objects.create(
            hostname="disabled-ignored",
            environment="PROD",
            is_enabled=False,
            in_active_directory=True,
            in_siem=False,
            ad_first_seen_at=self.now - timedelta(days=1),
        )

    def _request(self, query=""):
        request = self.factory.get(f"/dashboard/?{query}")
        request.user = self.user
        return request

    def test_metrics_use_discovery_cohort_and_current_pending_backlog(self):
        context = build_inventory_dashboard_context(self._request(), now=self.now)

        self.assertEqual(context["selected_inventory_environment"], "PROD")
        self.assertEqual(context["inventory_new_count"], 3)
        self.assertEqual(context["inventory_pending_count"], 2)
        self.assertEqual(context["inventory_overdue_count"], 1)
        self.assertEqual(context["inventory_completed_count"], 1)
        self.assertEqual(context["inventory_average_ingestion"], "2 d 0 h")
        self.assertEqual([row["asset"].hostname for row in context["inventory_rows"]], [
            "old-overdue",
            "new-pending",
        ])

    def test_criticality_and_list_mode_filter_without_page_reload_contract(self):
        context = build_inventory_dashboard_context(
            self._request("inventory_criticality=critical&inventory_list=overdue"),
            now=self.now,
        )

        self.assertEqual(context["inventory_pending_count"], 1)
        self.assertEqual(context["inventory_overdue_count"], 1)
        self.assertEqual(context["inventory_list_mode"], "overdue")
        self.assertEqual(context["inventory_rows"][0]["asset"].hostname, "old-overdue")

    def test_inventory_results_endpoint_renders_partial(self):
        self.client.force_login(self.user)

        response = self.client.get(
            reverse("dashboard_inventory_results"),
            {"inventory_environment": "PROD", "inventory_list": "pending"},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Servidores con falta de ingesta")
        self.assertContains(response, "new-pending")
        self.assertNotContains(response, "lab-ignored")


class InventoryDashboardTemplateTests(TestCase):
    def test_executive_dashboard_exposes_inventory_tab(self):
        user = get_user_model().objects.create_user("inventory-tab-user", password="pass")
        self.client.force_login(user)

        response = self.client.get(reverse("dashboard"), {"tab": "inventario"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'data-tab="inventario"')
        self.assertContains(response, 'data-inventory-dashboard')
        self.assertContains(response, reverse("dashboard_inventory_results"))
