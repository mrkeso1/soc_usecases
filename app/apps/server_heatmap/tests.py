import tempfile
from datetime import datetime, timezone
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
    ServerAsset,
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
        ServerAsset.objects.create(
            hostname="AR-WIN-APP01",
            os_family=ServerAsset.OS_WINDOWS,
            server_type=ServerAsset.TYPE_APPLICATION,
            in_active_directory=True,
            in_siem=True,
            classification_source=ServerAsset.CLASSIFICATION_MANUAL,
        )
        ServerAsset.objects.create(
            hostname="AR-WIN-APP02",
            os_family=ServerAsset.OS_WINDOWS,
            server_type=ServerAsset.TYPE_APPLICATION,
            in_active_directory=True,
            in_siem=False,
            classification_source=ServerAsset.CLASSIFICATION_MANUAL,
        )
        ServerAsset.objects.create(hostname="DISABLED", in_active_directory=True, is_enabled=False)

        context = build_server_heatmap_context({})
        cell = context["matrix_rows"][0]["cells"][0]

        self.assertEqual(context["total_assets"], 2)
        self.assertEqual(context["ad_only_count"], 1)
        self.assertEqual(context["siem_coverage_percent"], 50.0)
        self.assertEqual(cell["coverage_percent"], 50.0)
        self.assertEqual(cell["gap_count"], 1)

    def test_admin_role_can_open_server_heatmap(self):
        user = get_user_model().objects.create_user("heatmap-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="heatmap-admin", password="pass")

        response = self.client.get(reverse("server_heatmap"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Mapa de calor de servidores")

    def test_percentage_bar_uses_css_decimal_point(self):
        ServerAsset.objects.create(hostname="win01", os_family=ServerAsset.OS_WINDOWS)
        ServerAsset.objects.create(hostname="win02", os_family=ServerAsset.OS_WINDOWS)
        ServerAsset.objects.create(hostname="lin01", os_family=ServerAsset.OS_LINUX)
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
