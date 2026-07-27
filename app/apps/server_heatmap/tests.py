import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.test import RequestFactory, TestCase
from django.urls import reverse

from .classification import apply_automatic_classification
from .connectors.ad import _active_computer_filter
from .connectors.base import InventoryRecord
from .models import (
    InventoryObservation,
    InventorySyncRun,
    ReconciliationIssue,
    ServerAsset,
    ServerCategory,
    ServerInventoryConfiguration,
    ServerNamingRule,
)
from .network_diagnostics import diagnose_asset, diagnose_ingestion_gaps
from .reconciliation import synchronize_inventory
from apps.accounts.models import LDAPSettings
from .management.commands.sync_server_inventory import (
    _domain_base_from_dn,
    build_ad_connector,
)
from .views import build_server_heatmap_context


class ServerHeatmapTests(TestCase):
    def test_simple_wildcard_rule_classifies_domain_controllers(self):
        ServerNamingRule.objects.create(
            name="Controladores ARPADS",
            pattern="arpads*",
            match_type=ServerNamingRule.MATCH_WILDCARD,
            server_type=ServerAsset.TYPE_AD,
            priority=1,
        )
        asset = ServerAsset.objects.create(hostname="ARPADS12")

        apply_automatic_classification(asset)

        asset.refresh_from_db()
        self.assertEqual(asset.server_type, ServerAsset.TYPE_AD)

    def test_inventory_configuration_is_singleton(self):
        configuration = ServerInventoryConfiguration.load()
        configuration.ad_active_days = 45
        configuration.save()

        self.assertEqual(ServerInventoryConfiguration.load().ad_active_days, 45)
        self.assertEqual(ServerInventoryConfiguration.objects.count(), 1)

    def test_ad_sync_removes_assets_older_than_retention_period(self):
        configuration = ServerInventoryConfiguration.load()
        configuration.retention_days = 90
        configuration.save()
        ServerAsset.objects.create(
            hostname="obsolete01",
            in_active_directory=True,
            ad_last_logon_at=datetime.now(timezone.utc) - timedelta(days=91),
        )

        class Connector:
            def collect(self):
                return [
                    InventoryRecord(
                        external_id="active01.example.local",
                        hostname="active01",
                        observed_at=datetime.now(timezone.utc),
                    ),
                ]

        run = synchronize_inventory(InventorySyncRun.SOURCE_AD, Connector())

        self.assertFalse(ServerAsset.objects.filter(hostname="obsolete01").exists())
        self.assertTrue(ServerAsset.objects.filter(hostname="active01").exists())
        self.assertEqual(run.metadata["deleted_stale_assets"], 1)

    def test_ad_sync_removes_old_asset_without_last_logon(self):
        configuration = ServerInventoryConfiguration.load()
        configuration.retention_days = 90
        configuration.save()
        zombie = ServerAsset.objects.create(
            hostname="zombie-without-logon",
            in_active_directory=True,
            ad_last_logon_at=None,
        )
        ServerAsset.objects.filter(pk=zombie.pk).update(
            created_at=datetime.now(timezone.utc) - timedelta(days=91),
        )

        class Connector:
            def collect(self):
                return []

        run = synchronize_inventory(InventorySyncRun.SOURCE_AD, Connector())

        self.assertFalse(ServerAsset.objects.filter(pk=zombie.pk).exists())
        self.assertEqual(run.metadata["deleted_stale_assets"], 1)

    def test_reprocess_button_does_not_require_new_inventory(self):
        user = get_user_model().objects.create_user("reprocess-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="reprocess-admin", password="pass")
        ServerAsset.objects.create(hostname="arpads99")
        ServerNamingRule.objects.create(
            name="DC ARPADS",
            pattern="arpads*",
            server_type=ServerAsset.TYPE_AD,
            priority=1,
        )

        response = self.client.post(reverse("server_heatmap_reprocess"))

        self.assertRedirects(response, reverse("server_heatmap"))
        self.assertEqual(
            ServerAsset.objects.get(hostname="arpads99").server_type,
            ServerAsset.TYPE_AD,
        )

    def test_ad_filter_only_includes_enabled_computers_active_in_period(self):
        search_filter = _active_computer_filter(
            60,
            now=datetime(2026, 7, 24, tzinfo=timezone.utc),
        )

        self.assertIn("(objectCategory=computer)", search_filter)
        self.assertIn("(!(userAccountControl:1.2.840.113556.1.4.803:=2))", search_filter)
        self.assertIn("(lastLogonTimestamp>=", search_filter)

    def test_domain_base_is_derived_from_existing_ldap_search_dn(self):
        self.assertEqual(
            _domain_base_from_dn("OU=Users,DC=example,DC=local"),
            "DC=example,DC=local",
        )

    @override_settings(
        SERVER_INVENTORY_AD_SERVER="",
        SERVER_INVENTORY_AD_USER="",
        SERVER_INVENTORY_AD_PASSWORD="",
        SERVER_INVENTORY_AD_BASE_DN="",
    )
    def test_ad_connector_reuses_active_admin_ldap_configuration(self):
        LDAPSettings.objects.create(
            name="LDAP inventario",
            is_enabled=True,
            server_uri="ldap://ldap.example.local:389",
            use_ssl=False,
            bind_dn="CN=soc-bind,OU=Services,DC=example,DC=local",
            bind_password="secret",
            user_search_base="OU=Users,DC=example,DC=local",
        )

        connector = build_ad_connector()

        self.assertEqual(connector.server_uri, "ldap://ldap.example.local:389")
        self.assertEqual(connector.bind_user, "CN=soc-bind,OU=Services,DC=example,DC=local")
        self.assertEqual(connector.bind_password, "secret")
        self.assertEqual(connector.search_base, "DC=example,DC=local")

    def test_generic_naming_rules_classify_os_and_server_type(self):
        asset = ServerAsset.objects.create(hostname="AR-LNX-DB01")

        apply_automatic_classification(asset)

        asset.refresh_from_db()
        self.assertEqual(asset.os_family, ServerAsset.OS_LINUX)
        self.assertEqual(asset.server_type, ServerAsset.TYPE_DATABASE)

    def test_heatmap_compares_ad_coverage_against_siem(self):
        category = ServerCategory.objects.get(code="application")
        ServerAsset.objects.create(
            hostname="AR-WIN-APP01",
            os_family=ServerAsset.OS_WINDOWS,
            server_type=ServerAsset.TYPE_APPLICATION,
            category=category,
            in_active_directory=True,
            in_siem=True,
            classification_source=ServerAsset.CLASSIFICATION_MANUAL,
        )
        ServerAsset.objects.create(
            hostname="AR-WIN-APP02",
            os_family=ServerAsset.OS_WINDOWS,
            server_type=ServerAsset.TYPE_APPLICATION,
            category=category,
            in_active_directory=True,
            in_siem=False,
            classification_source=ServerAsset.CLASSIFICATION_MANUAL,
        )
        ServerAsset.objects.create(hostname="DISABLED", in_active_directory=True, is_enabled=False)

        context = build_server_heatmap_context({})
        windows_row = next(
            row for row in context["matrix_rows"]
            if row["key"] == ServerAsset.OS_WINDOWS
        )
        cell = next(
            item for item in windows_row["cells"]
            if item["category"].id == category.id
        )

        self.assertEqual(context["total_assets"], 2)
        self.assertEqual(context["ad_only_count"], 1)
        self.assertEqual(context["siem_coverage_percent"], 50.0)
        self.assertEqual(cell["coverage_percent"], 50.0)
        self.assertEqual(cell["gap_count"], 1)

    def test_siem_only_cell_has_neutral_no_baseline_state(self):
        category = ServerCategory.objects.get(code="exchange")
        ServerAsset.objects.create(
            hostname="siem-only-mail",
            os_family=ServerAsset.OS_WINDOWS,
            category=category,
            in_active_directory=False,
            in_siem=True,
        )

        context = build_server_heatmap_context({})
        windows_row = next(
            row for row in context["matrix_rows"]
            if row["key"] == ServerAsset.OS_WINDOWS
        )
        cell = next(
            item for item in windows_row["cells"]
            if item["category"].id == category.id
        )

        self.assertIsNone(cell["coverage_percent"])
        self.assertEqual(cell["level"], "no_baseline")
        self.assertEqual(cell["siem_count"], 1)

    def test_heatmap_always_includes_all_os_and_active_categories(self):
        context = build_server_heatmap_context({})

        self.assertEqual(
            [row["key"] for row in context["matrix_rows"]],
            [key for key, _ in ServerAsset.OS_CHOICES],
        )
        self.assertEqual(
            [category.id for category in context["matrix_types"]],
            list(
                ServerCategory.objects.filter(is_active=True)
                .order_by("order", "name")
                .values_list("id", flat=True)
            ),
        )

    def test_os_coverage_uses_ad_as_denominator(self):
        for number in range(1, 101):
            ServerAsset.objects.create(
                hostname=f"win-{number:03}",
                os_family=ServerAsset.OS_WINDOWS,
                in_active_directory=True,
                in_siem=number <= 80,
            )

        windows = next(
            row for row in build_server_heatmap_context({})["os_rows"]
            if row["key"] == ServerAsset.OS_WINDOWS
        )

        self.assertEqual(windows["ad_count"], 100)
        self.assertEqual(windows["covered_count"], 80)
        self.assertEqual(windows["gap_count"], 20)
        self.assertEqual(windows["percent"], 80.0)

    def test_functional_section_coverage_uses_each_ad_section_as_100_percent(self):
        category = ServerCategory.objects.get(code="database")
        for number in range(1, 11):
            ServerAsset.objects.create(
                hostname=f"db-{number:02}",
                category=category,
                in_active_directory=True,
                in_siem=number <= 7,
            )
        ServerAsset.objects.create(
            hostname="unrelated-siem",
            in_siem=True,
            category=ServerCategory.objects.get(code="application"),
        )

        database = next(
            row for row in build_server_heatmap_context({})["type_rows"]
            if row["key"] == category.id
        )

        self.assertEqual(database["ad_count"], 10)
        self.assertEqual(database["covered_count"], 7)
        self.assertEqual(database["gap_count"], 3)
        self.assertEqual(database["percent"], 70.0)

    def test_admin_role_can_open_server_heatmap(self):
        user = get_user_model().objects.create_user("heatmap-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="heatmap-admin", password="pass")

        response = self.client.get(reverse("server_heatmap"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Mapa de calor de servidores")

    def test_admin_role_can_manage_inventory_from_front_panel(self):
        user = get_user_model().objects.create_user("front-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="front-admin", password="pass")

        response = self.client.get(reverse("server_heatmap_administration"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Panel de administración")
        self.assertContains(response, "Configuración del inventario")
        self.assertContains(response, "Administrar equipos")

    def test_front_panel_updates_configuration_and_creates_rule(self):
        user = get_user_model().objects.create_user("settings-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="settings-admin", password="pass")

        response = self.client.post(
            reverse("server_heatmap_administration"),
            {
                "action": "save_configuration",
                "ad_active_days": 45,
                "retention_days": 120,
            },
        )
        self.assertRedirects(response, reverse("server_heatmap_administration"))
        configuration = ServerInventoryConfiguration.load()
        self.assertEqual(configuration.ad_active_days, 45)
        self.assertEqual(configuration.retention_days, 120)

        response = self.client.post(
            reverse("server_heatmap_administration"),
            {
                "action": "create_rule",
                "rule-name": "Controladores front",
                "rule-pattern": "arpads*",
                "rule-match_type": ServerNamingRule.MATCH_WILDCARD,
                "rule-os_family": "",
                "rule-server_type": ServerAsset.TYPE_AD,
                "rule-priority": 5,
                "rule-is_active": "on",
                "rule-notes": "",
            },
        )
        self.assertRedirects(response, reverse("server_heatmap_administration"))
        self.assertTrue(ServerNamingRule.objects.filter(name="Controladores front").exists())

    def test_front_panel_can_create_dynamic_server_category(self):
        user = get_user_model().objects.create_user("category-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="category-admin", password="pass")

        response = self.client.post(
            reverse("server_heatmap_administration"),
            {
                "action": "create_category",
                "category-name": "SAP",
                "category-code": "sap",
                "category-order": 55,
                "category-is_active": "on",
                "category-description": "Servidores de SAP",
            },
        )

        self.assertRedirects(response, reverse("server_heatmap_administration"))
        self.assertTrue(ServerCategory.objects.filter(code="sap", name="SAP").exists())

    def test_front_panel_can_disable_selected_assets(self):
        user = get_user_model().objects.create_user("asset-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="asset-admin", password="pass")
        asset = ServerAsset.objects.create(hostname="disable-me")

        response = self.client.post(
            reverse("server_heatmap_administration"),
            {"action": "disable_assets", "asset_ids": [asset.id]},
        )

        self.assertRedirects(response, reverse("server_heatmap_administration"))
        asset.refresh_from_db()
        self.assertFalse(asset.is_enabled)

    def test_front_panel_resolves_reconciliation_issue_and_dashboard_excludes_it(self):
        user = get_user_model().objects.create_user("issue-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="issue-admin", password="pass")
        run = InventorySyncRun.objects.create(
            source=InventorySyncRun.SOURCE_SIEM,
            status=InventorySyncRun.STATUS_SUCCESS,
        )
        observation = InventoryObservation.objects.create(
            sync_run=run,
            source=InventorySyncRun.SOURCE_SIEM,
            external_id="orphan01",
            hostname="orphan01",
        )
        issue = ReconciliationIssue.objects.create(
            sync_run=run,
            observation=observation,
            issue_type=ReconciliationIssue.TYPE_NOT_IN_AD,
            identifier="orphan01",
        )

        before = build_server_heatmap_context({})
        self.assertEqual(before["unresolved_issue_counts"]["not_in_ad"], 1)

        response = self.client.post(
            reverse("server_heatmap_administration"),
            {"action": "resolve_issues", "issue_ids": [issue.id]},
        )

        self.assertRedirects(response, reverse("server_heatmap_administration"))
        issue.refresh_from_db()
        self.assertTrue(issue.is_resolved)
        after = build_server_heatmap_context({})
        self.assertEqual(after["unresolved_issue_counts"]["not_in_ad"], 0)
        self.assertEqual(after["unmatched_siem_count"], 0)

    def test_percentage_bar_uses_css_decimal_point(self):
        ServerAsset.objects.create(
            hostname="win01",
            os_family=ServerAsset.OS_WINDOWS,
            in_active_directory=True,
            in_siem=True,
        )
        ServerAsset.objects.create(
            hostname="win02",
            os_family=ServerAsset.OS_WINDOWS,
            in_active_directory=True,
            in_siem=True,
        )
        ServerAsset.objects.create(
            hostname="win03",
            os_family=ServerAsset.OS_WINDOWS,
            in_active_directory=True,
            in_siem=False,
        )
        user = get_user_model().objects.create_user("chart-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="chart-admin", password="pass")

        response = self.client.get(reverse("server_heatmap"))

        self.assertContains(response, "width:66.7%")
        self.assertNotContains(response, "width:66,7%")

    def test_legacy_hotmap_import_maps_ad_siem_and_classification(self):
        headers = (
            "ds_ip;ds_name;ds_grupo_esm;ingestado;d_source;ds_so;"
            "ds_ou;ambiente;ds_grupo_clasificacion;;\n"
        )
        rows = (
            "10.0.0.1;APP01;Applications;1;siem;Windows Server 2022;"
            "Appl > Production > Servers;PROD;SRV;;\n"
            "10.0.0.2;DC01;;0;ldap;Windows Server 2019;"
            "Domain Controllers > Production;PROD;DC;;\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            windows = Path(temp) / "servidores.csv"
            linux = Path(temp) / "linux.csv"
            windows.write_text(headers + rows, encoding="utf-8")
            linux.write_text(headers, encoding="utf-8")
            call_command("import_legacy_hotmap", windows, linux)

        app = ServerAsset.objects.get(hostname="app01")
        dc = ServerAsset.objects.get(hostname="dc01")
        self.assertTrue(app.in_active_directory)
        self.assertTrue(app.in_siem)
        self.assertEqual(app.server_type, ServerAsset.TYPE_APPLICATION)
        self.assertEqual(app.os_family, ServerAsset.OS_WINDOWS)
        self.assertFalse(dc.in_siem)
        self.assertEqual(dc.server_type, ServerAsset.TYPE_AD)

    def test_legacy_hotmap_dry_run_does_not_write(self):
        headers = (
            "ds_ip;ds_name;ds_grupo_esm;ingestado;d_source;ds_so;"
            "ds_ou;ambiente;ds_grupo_clasificacion;;\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            windows = Path(temp) / "servidores.csv"
            linux = Path(temp) / "linux.csv"
            windows.write_text(
                headers + "10.0.0.3;TEMP01;;1;siem;Windows Server 2022;Appl;PROD;SRV;;\n",
                encoding="utf-8",
            )
            linux.write_text(headers, encoding="utf-8")
            call_command("import_legacy_hotmap", windows, linux, dry_run=True)

        self.assertFalse(ServerAsset.objects.filter(hostname="temp01").exists())

    def test_siem_sync_creates_history_and_updates_coverage(self):
        ServerAsset.objects.create(hostname="app01", in_active_directory=True)

        class Connector:
            def collect(self):
                return [
                    InventoryRecord(
                        external_id="siem:app01",
                        hostname="APP01",
                        fqdn="app01.example.local",
                        ip_address="10.0.0.10",
                        os_name="Windows Server 2022",
                        groups="Applications",
                    )
                ]

        run = synchronize_inventory(InventorySyncRun.SOURCE_SIEM, Connector())

        asset = ServerAsset.objects.get(hostname="app01")
        self.assertEqual(run.status, InventorySyncRun.STATUS_SUCCESS)
        self.assertTrue(asset.in_siem)
        self.assertEqual(asset.os_family, ServerAsset.OS_WINDOWS)
        self.assertEqual(asset.domain, "example.local")
        self.assertEqual(InventoryObservation.objects.filter(sync_run=run, asset=asset).count(), 1)

    def test_ad_sync_reconciles_with_existing_siem_asset(self):
        ServerAsset.objects.create(hostname="app01", in_siem=True)

        class Connector:
            def collect(self):
                return [
                    InventoryRecord(
                        external_id="app01.example.local",
                        hostname="APP01",
                        fqdn="app01.example.local",
                        os_name="Windows Server 2022",
                        organizational_unit="Appl > PROD",
                        environment="PROD",
                    )
                ]

        synchronize_inventory(InventorySyncRun.SOURCE_AD, Connector())

        self.assertEqual(ServerAsset.objects.count(), 1)
        asset = ServerAsset.objects.get(hostname="app01")
        self.assertTrue(asset.in_active_directory)
        self.assertTrue(asset.in_siem)
        self.assertEqual(asset.organizational_unit, "Appl > PROD")

    def test_ad_sync_consolidates_duplicate_external_ids(self):
        class Connector:
            def collect(self):
                return [
                    InventoryRecord(
                        external_id="NICEAPP.ARDP.LOCAL",
                        hostname="NICEAPP",
                        fqdn="niceapp.ardp.local",
                    ),
                    InventoryRecord(
                        external_id="niceapp.ardp.local.",
                        hostname="NICEAPP",
                        fqdn="niceapp.ardp.local",
                        os_name="Windows Server 2022",
                        organizational_unit="Applications > PROD",
                    ),
                ]

        run = synchronize_inventory(InventorySyncRun.SOURCE_AD, Connector())

        self.assertEqual(run.status, InventorySyncRun.STATUS_SUCCESS)
        self.assertEqual(run.records_read, 2)
        self.assertEqual(run.metadata["unique_records"], 1)
        self.assertEqual(run.metadata["duplicate_records"], 1)
        self.assertEqual(InventoryObservation.objects.filter(sync_run=run).count(), 1)
        asset = ServerAsset.objects.get(hostname="niceapp")
        self.assertEqual(asset.os_name, "Windows Server 2022")
        self.assertEqual(asset.organizational_unit, "Applications > PROD")

    def test_upload_siem_csv_compares_against_ad_inventory(self):
        ServerAsset.objects.create(
            hostname="app01",
            in_active_directory=True,
            in_siem=False,
            classification_source=ServerAsset.CLASSIFICATION_MANUAL,
        )
        ServerAsset.objects.create(
            hostname="app02",
            in_active_directory=True,
            in_siem=True,
            classification_source=ServerAsset.CLASSIFICATION_MANUAL,
        )
        user = get_user_model().objects.create_user("inventory-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="inventory-admin", password="pass")
        upload = SimpleUploadedFile(
            "siem.csv",
            (
                "TipoDispositivo;Ip-Hostname;UltimaFechaIngesta;GruposAsociados;FechaRegistro\n"
                "winevent_nic;APP01;2026-07-24T10:00:00;['Applications'];2026-07-24\n"
            ).encode(),
            content_type="text/csv",
        )

        response = self.client.post(reverse("server_heatmap_siem_upload"), {"siem_csv": upload})

        self.assertRedirects(response, reverse("server_heatmap"))
        self.assertTrue(ServerAsset.objects.get(hostname="app01").in_siem)
        self.assertFalse(ServerAsset.objects.get(hostname="app02").in_siem)
        run = InventorySyncRun.objects.filter(source=InventorySyncRun.SOURCE_SIEM).latest("started_at")
        self.assertEqual(run.records_read, 1)
        self.assertEqual(run.issues_count, 0)

    def test_gap_export_contains_only_ad_without_siem(self):
        ServerAsset.objects.create(hostname="missing01", in_active_directory=True, in_siem=False)
        ServerAsset.objects.create(hostname="covered01", in_active_directory=True, in_siem=True)
        user = get_user_model().objects.create_user("export-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="export-admin", password="pass")

        response = self.client.get(reverse("server_heatmap_gap_export"))

        content = response.content.decode("utf-8-sig")
        self.assertEqual(response.status_code, 200)
        self.assertIn("missing01", content)
        self.assertNotIn("covered01", content)

    def test_siem_record_not_present_in_ad_is_reported_without_creating_asset(self):
        class Connector:
            def collect(self):
                return [InventoryRecord(external_id="siem:orphan", hostname="ORPHAN")]

        run = synchronize_inventory(InventorySyncRun.SOURCE_SIEM, Connector())

        self.assertFalse(ServerAsset.objects.filter(hostname="orphan").exists())
        self.assertEqual(run.issues_count, 1)
        self.assertEqual(run.issues.get().issue_type, "not_in_ad")

    @patch("apps.server_heatmap.network_diagnostics.subprocess.run")
    @patch("apps.server_heatmap.network_diagnostics.shutil.which", return_value="/usr/bin/ping")
    @patch("apps.server_heatmap.network_diagnostics.socket.getfqdn", return_value="app01.example.local")
    @patch("apps.server_heatmap.network_diagnostics.socket.getaddrinfo")
    def test_network_diagnostic_resolves_dns_and_records_ping(
        self,
        getaddrinfo,
        getfqdn,
        which,
        run,
    ):
        getaddrinfo.return_value = [(2, 1, 6, "", ("10.0.0.20", 0))]
        run.return_value.returncode = 0
        asset = ServerAsset.objects.create(
            hostname="app01",
            domain="example.local",
            in_active_directory=True,
            in_siem=False,
        )

        result = diagnose_asset(asset)

        self.assertEqual(result.dns_status, ServerAsset.DNS_RESOLVED)
        self.assertEqual(result.resolved_ip_address, "10.0.0.20")
        self.assertEqual(result.reachability_status, ServerAsset.REACHABILITY_REACHABLE)

    @patch("apps.server_heatmap.network_diagnostics.diagnose_asset")
    def test_gap_diagnostic_persists_operational_result(self, diagnose):
        from .network_diagnostics import NetworkDiagnosticResult

        asset = ServerAsset.objects.create(
            hostname="db01",
            in_active_directory=True,
            in_siem=False,
        )
        diagnose.return_value = NetworkDiagnosticResult(
            asset_id=asset.id,
            dns_status=ServerAsset.DNS_RESOLVED,
            resolved_fqdn="db01.example.local",
            resolved_ip_address="10.0.0.30",
            reachability_status=ServerAsset.REACHABILITY_UNREACHABLE,
        )

        summary = diagnose_ingestion_gaps(limit=10)

        asset.refresh_from_db()
        self.assertEqual(summary["checked"], 1)
        self.assertEqual(asset.reachability_status, ServerAsset.REACHABILITY_UNREACHABLE)
        self.assertEqual(asset.diagnostic_result, "Revisar disponibilidad")
