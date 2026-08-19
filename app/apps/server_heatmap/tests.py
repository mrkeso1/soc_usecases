import tempfile
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import resolve, reverse
from django.utils import timezone as django_timezone

from .classification import apply_automatic_classification
from .connectors.ad import (
    _PAGED_RESULTS_OID,
    _active_computer_filter,
    _environment,
    _ldap_server_address,
    _paged_entries,
)
from .connectors.base import InventoryRecord
from .connectors.siem import SiemCsvConnector
from .forms import InventoryFilterRuleForm, ServerAssetForm
from .inventory_filters import (
    apply_inventory_filters,
    evaluate_observation,
    load_compiled_filters,
    simulate_inventory_filters,
)
from .models import (
    InventoryFilterDecision,
    InventoryFilterRule,
    InventoryJob,
    InventoryObservation,
    InventoryRuleRevision,
    InventorySyncRun,
    ReconciliationIssue,
    ServerAsset,
    ServerAssetDisableEvent,
    ServerCategory,
    ServerInventoryConfiguration,
)
from .jobs import (
    claim_next_inventory_job,
    enqueue_due_inventory_sync,
    enqueue_inventory_job,
    execute_inventory_job,
    recover_zombie_jobs,
)
from .maintenance import maintain_server_inventory
from .network_diagnostics import diagnose_asset, diagnose_ingestion_gaps
from .reconciliation import (
    promote_siem_only_issue,
    reprocess_stored_inventory,
    synchronize_inventory,
)
from apps.accounts.models import LDAPSettings
from apps.auditlog.models import ActionRateLimit, AuditLog, OperationalAlert
from .management.commands.sync_server_inventory import (
    _domain_base_from_dn,
    build_ad_connector,
)
from .views import build_server_heatmap_context, build_server_inventory_results_context


class ServerHeatmapTests(TestCase):
    def test_static_route_uses_collectstatic_root_for_django_admin_assets(self):
        match = resolve("/static/admin/css/base.css")

        self.assertEqual(Path(match.kwargs["document_root"]), Path(settings.STATIC_ROOT))

    def _filter_test_observation(self, *, source="ad", hostname="ltp001", groups=""):
        run = InventorySyncRun.objects.create(
            source=source,
            status=InventorySyncRun.STATUS_SUCCESS,
        )
        return InventoryObservation.objects.create(
            sync_run=run,
            source=source,
            external_id=hostname,
            hostname=hostname,
            groups=groups,
        )

    def test_inventory_filter_excludes_hostname_by_wildcard(self):
        observation = self._filter_test_observation(hostname="LTP001")
        rule = InventoryFilterRule.objects.create(
            name="Excluir notebooks prueba",
            source=InventorySyncRun.SOURCE_AD,
            field=InventoryFilterRule.FIELD_HOSTNAME,
            operator=InventoryFilterRule.OP_WILDCARD,
            pattern="ltp*",
            action=InventoryFilterRule.ACTION_EXCLUDE,
            priority=10,
            is_active=True,
        )

        evaluation = evaluate_observation(
            observation,
            load_compiled_filters(rules=InventoryFilterRule.objects.filter(pk=rule.pk)),
        )

        self.assertTrue(evaluation["excluded"])
        self.assertEqual(evaluation["scope_decision"], rule)

    def test_inventory_filter_priority_allows_specific_include_before_exclude(self):
        observation = self._filter_test_observation(hostname="LTP-SERVER-01")
        include = InventoryFilterRule.objects.create(
            name="Permitir servidor LTP",
            source="ad",
            field="hostname",
            operator="exact",
            pattern="ltp-server-01",
            action="include",
            priority=1,
            is_active=True,
        )
        InventoryFilterRule.objects.create(
            name="Excluir resto LTP",
            source="ad",
            field="hostname",
            operator="wildcard",
            pattern="ltp*",
            action="exclude",
            priority=10,
            is_active=True,
        )

        evaluation = evaluate_observation(observation, load_compiled_filters())

        self.assertFalse(evaluation["excluded"])
        self.assertEqual(evaluation["scope_decision"], include)

    def test_word_operator_does_not_match_substring(self):
        office = self._filter_test_observation(
            source="siem",
            hostname="office-device",
            groups="Office5 platform",
        )
        firewall = InventoryObservation.objects.create(
            sync_run=office.sync_run,
            source="siem",
            external_id="firewall",
            hostname="firewall",
            groups="F5, NetScaler",
        )
        rule = InventoryFilterRule.objects.create(
            name="Seguridad F5 prueba",
            source="siem",
            field="groups",
            operator="word",
            pattern="f5",
            action="classify",
            category=ServerCategory.objects.get(code="security"),
            is_active=True,
        )
        compiled = load_compiled_filters(
            rules=InventoryFilterRule.objects.filter(pk=rule.pk),
        )

        self.assertFalse(evaluate_observation(office, compiled)["matched_rules"])
        self.assertEqual(evaluate_observation(firewall, compiled)["matched_rules"], [rule])

    def test_filter_simulation_is_read_only(self):
        self._filter_test_observation(hostname="LTP009")
        rule = InventoryFilterRule.objects.create(
            name="Simular exclusión LTP",
            source="ad",
            field="hostname",
            operator="wildcard",
            pattern="ltp*",
            action="exclude",
            is_active=False,
        )

        result = simulate_inventory_filters(
            rules=InventoryFilterRule.objects.filter(pk=rule.pk),
        )

        self.assertEqual(result["received"], 1)
        self.assertEqual(result["excluded"], 1)
        self.assertEqual(InventoryFilterDecision.objects.count(), 0)

    def test_filter_simulation_uses_legacy_as_ad_fallback(self):
        run = InventorySyncRun.objects.create(
            source=InventorySyncRun.SOURCE_LEGACY,
            status=InventorySyncRun.STATUS_SUCCESS,
        )
        InventoryObservation.objects.create(
            sync_run=run,
            source=InventorySyncRun.SOURCE_LEGACY,
            external_id="dc-legacy",
            hostname="dc-legacy",
            organizational_unit="Domain Controllers",
        )
        rule = InventoryFilterRule.objects.create(
            name="OU DC legacy",
            source="ad",
            field="organizational_unit",
            operator="contains",
            pattern="Domain Controllers",
            action="classify",
            is_active=False,
        )

        result = simulate_inventory_filters(
            rules=InventoryFilterRule.objects.filter(pk=rule.pk),
        )

        self.assertEqual(result["received"], 1)
        self.assertEqual(result["classified"], 1)
        self.assertEqual(result["run_rows"][0]["matched"], 1)

    def test_invalid_literal_star_dot_filter_is_rejected(self):
        form = InventoryFilterRuleForm(
            {
                "name": "Patrón inválido",
                "source": "ad",
                "field": "hostname",
                "operator": "wildcard",
                "pattern": "*.",
                "action": "exclude",
                "priority": 100,
            }
        )

        self.assertFalse(form.is_valid())
        self.assertIn("pattern", form.errors)

    @patch("apps.server_heatmap.connectors.siem.requests.Session")
    def test_siem_url_bypasses_environment_proxy_by_default(self, session_class):
        session = session_class.return_value.__enter__.return_value
        response = session.get.return_value
        response.content = (
            "TipoDispositivo,Ip-Hostname,UltimaFechaIngesta,GruposAsociados,FechaRegistro\n"
            "winevent_nic,host01.example.local,2026-07-27 07:25:13,[],2026-07-27\n"
        ).encode()

        records = SiemCsvConnector(url="http://siem.local/inventory.csv").collect()

        self.assertFalse(session.trust_env)
        session.get.assert_called_once_with(
            "http://siem.local/inventory.csv",
            timeout=30,
        )
        response.raise_for_status.assert_called_once()
        self.assertEqual(len(records), 1)

    @patch(
        "apps.server_heatmap.connectors.siem.resolve_hostname_from_ip",
        return_value="pv1plnxapp0085.ardp.local",
    )
    def test_siem_resolves_linux_ip_before_reconciliation(self, resolver):
        connector = SiemCsvConnector(
            text=(
                "TipoDispositivo,Ip-Hostname,UltimaFechaIngesta,GruposAsociados\n"
                "rhlinux,123.176.49.190,2026-07-27 07:25:13,['Unknown']\n"
            ),
        )

        records = connector.collect()

        resolver.assert_called_once_with("123.176.49.190", timeout=3)
        self.assertEqual(records[0].hostname, "pv1plnxapp0085")
        self.assertEqual(records[0].fqdn, "pv1plnxapp0085.ardp.local")
        self.assertEqual(records[0].ip_address, "123.176.49.190")
        self.assertTrue(records[0].raw_data["dns_resolution_attempted"])

    @patch("apps.server_heatmap.connectors.siem.resolve_hostname_from_ip")
    def test_siem_does_not_resolve_windows_hostname(self, resolver):
        connector = SiemCsvConnector(
            text=(
                "TipoDispositivo,Ip-Hostname,UltimaFechaIngesta,GruposAsociados\n"
                "winevent_nic,SERVER01.ARDP.LOCAL,2026-07-27 07:25:13,[]\n"
            ),
        )

        records = connector.collect()

        resolver.assert_not_called()
        self.assertEqual(records[0].hostname, "server01")

    def test_simple_wildcard_rule_classifies_domain_controllers(self):
        InventoryFilterRule.objects.create(
            name="Controladores ARPADS",
            source=InventoryFilterRule.SOURCE_BOTH,
            field=InventoryFilterRule.FIELD_HOSTNAME,
            operator=InventoryFilterRule.OP_WILDCARD,
            pattern="arpads*",
            action=InventoryFilterRule.ACTION_CLASSIFY,
            server_type_value=ServerAsset.TYPE_AD,
            priority=1,
            is_active=True,
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

    def test_due_inventory_schedule_enqueues_full_sync_once_for_configured_period(self):
        configuration = ServerInventoryConfiguration.load()
        configuration.siem_sync_enabled = True
        configuration.siem_sync_interval_days = 1
        configuration.siem_sync_time = datetime(2026, 8, 11, 9, 0).time()
        configuration.save()
        now = django_timezone.make_aware(datetime(2026, 8, 11, 10, 0))

        job, created = enqueue_due_inventory_sync(now=now)
        duplicate, duplicate_created = enqueue_due_inventory_sync(
            now=now + timedelta(hours=1),
        )

        self.assertTrue(created)
        self.assertEqual(job.job_type, InventoryJob.TYPE_FULL_SYNC)
        self.assertTrue(job.payload["scheduled"])
        self.assertIsNone(duplicate)
        self.assertFalse(duplicate_created)

    def test_inventory_schedule_waits_until_configured_time(self):
        configuration = ServerInventoryConfiguration.load()
        configuration.siem_sync_enabled = True
        configuration.siem_sync_interval_days = 1
        configuration.siem_sync_time = datetime(2026, 8, 11, 18, 0).time()
        configuration.save()
        now = django_timezone.make_aware(datetime(2026, 8, 11, 10, 0))

        job, created = enqueue_due_inventory_sync(now=now)

        self.assertIsNone(job)
        self.assertFalse(created)

    def test_inventory_maintenance_is_dry_run_by_default_and_preserves_latest(self):
        now = django_timezone.now()
        old_run = InventorySyncRun.objects.create(
            source=InventorySyncRun.SOURCE_AD,
            status=InventorySyncRun.STATUS_SUCCESS,
        )
        InventorySyncRun.objects.filter(pk=old_run.pk).update(
            started_at=now - timedelta(days=200),
        )
        InventoryObservation.objects.create(
            sync_run=old_run,
            source=InventorySyncRun.SOURCE_AD,
            external_id="old-maintenance",
            hostname="old-maintenance",
        )
        latest_run = InventorySyncRun.objects.create(
            source=InventorySyncRun.SOURCE_AD,
            status=InventorySyncRun.STATUS_SUCCESS,
        )
        InventorySyncRun.objects.filter(pk=latest_run.pk).update(
            started_at=now - timedelta(days=190),
        )
        old_job = InventoryJob.objects.create(
            job_type=InventoryJob.TYPE_APPLY_FILTERS,
            idempotency_key="maintenance-old-job",
            status=InventoryJob.STATUS_COMPLETED,
            finished_at=now - timedelta(days=100),
        )
        active_job = InventoryJob.objects.create(
            job_type=InventoryJob.TYPE_FULL_SYNC,
            idempotency_key="maintenance-active-job",
            status=InventoryJob.STATUS_PENDING,
        )
        alert = OperationalAlert.objects.create(
            code="maintenance",
            fingerprint="maintenance-resolved",
            status=OperationalAlert.STATUS_RESOLVED,
            title="Resuelta",
            message="Histórica",
            resolved_at=now - timedelta(days=200),
        )
        user = get_user_model().objects.create_user("maintenance-user")
        rate_limit = ActionRateLimit.objects.create(
            user=user,
            scope="maintenance",
            window_started_at=now - timedelta(days=10),
            last_request_at=now - timedelta(days=10),
        )

        preview = maintain_server_inventory(
            dry_run=True,
            now=now,
            inventory_days=180,
            job_days=90,
            resolved_alert_days=180,
            rate_limit_days=7,
        )

        self.assertEqual(preview["inventory_runs"], 1)
        self.assertEqual(preview["inventory_observations"], 1)
        self.assertEqual(preview["inventory_jobs"], 1)
        self.assertEqual(preview["resolved_alerts"], 1)
        self.assertEqual(preview["rate_limit_rows"], 1)
        self.assertTrue(InventorySyncRun.objects.filter(pk=old_run.pk).exists())

        maintain_server_inventory(
            dry_run=False,
            now=now,
            inventory_days=180,
            job_days=90,
            resolved_alert_days=180,
            rate_limit_days=7,
        )

        self.assertFalse(InventorySyncRun.objects.filter(pk=old_run.pk).exists())
        self.assertTrue(InventorySyncRun.objects.filter(pk=latest_run.pk).exists())
        self.assertFalse(InventoryJob.objects.filter(pk=old_job.pk).exists())
        self.assertTrue(InventoryJob.objects.filter(pk=active_job.pk).exists())
        self.assertFalse(OperationalAlert.objects.filter(pk=alert.pk).exists())
        self.assertFalse(ActionRateLimit.objects.filter(pk=rate_limit.pk).exists())

    def test_benchmark_rolls_back_synthetic_data(self):
        before_assets = ServerAsset.objects.count()
        output = StringIO()

        call_command(
            "benchmark_server_inventory",
            records=10,
            coverage_percent=80,
            lookup_sample=5,
            confirm=True,
            stdout=output,
        )

        self.assertEqual(ServerAsset.objects.count(), before_assets)
        self.assertIn('"persisted": false', output.getvalue())
        self.assertIn("no quedaron datos sintéticos", output.getvalue())

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

    def test_ad_sync_preserves_present_asset_with_old_last_logon(self):
        configuration = ServerInventoryConfiguration.load()
        configuration.retention_days = 90
        configuration.save()
        asset = ServerAsset.objects.create(
            hostname="buapaix01",
            in_active_directory=True,
            ad_last_logon_at=datetime.now(timezone.utc) - timedelta(days=365),
        )

        class Connector:
            def collect(self):
                return [
                    InventoryRecord(
                        external_id="buapaix01",
                        hostname="buapaix01",
                        observed_at=datetime.now(timezone.utc) - timedelta(days=365),
                    ),
                ]

        run = synchronize_inventory(InventorySyncRun.SOURCE_AD, Connector())

        asset.refresh_from_db()
        self.assertTrue(asset.in_active_directory)
        self.assertEqual(run.metadata["deleted_stale_assets"], 0)

    def test_inventory_sync_does_not_reenable_manually_disabled_asset(self):
        asset = ServerAsset.objects.create(hostname="disabled01", is_enabled=False)
        ServerAssetDisableEvent.objects.create(
            asset=asset,
            hostname=asset.hostname,
            justification="Baja manual aprobada",
            previous_enabled=True,
            new_enabled=False,
        )

        class Connector:
            def collect(self):
                return [
                    InventoryRecord(
                        external_id="disabled01.example.local",
                        hostname="disabled01",
                        observed_at=datetime.now(timezone.utc),
                    ),
                ]

        synchronize_inventory(InventorySyncRun.SOURCE_AD, Connector())

        asset.refresh_from_db()
        self.assertFalse(asset.is_enabled)
        self.assertTrue(asset.in_active_directory)

    def test_inventory_sync_reenables_legacy_disabled_asset_seen_in_ad(self):
        asset = ServerAsset.objects.create(hostname="legacy-disabled", is_enabled=False)

        class Connector:
            def collect(self):
                return [
                    InventoryRecord(
                        external_id="legacy-disabled.example.local",
                        hostname="legacy-disabled",
                        organizational_unit="Servidores > Desarrollo",
                        environment="LAB",
                        observed_at=datetime.now(timezone.utc),
                    ),
                ]

        synchronize_inventory(InventorySyncRun.SOURCE_AD, Connector())

        asset.refresh_from_db()
        self.assertTrue(asset.is_enabled)
        self.assertTrue(asset.in_active_directory)
        self.assertEqual(asset.environment, "LAB")

    def test_inventory_sync_failure_creates_operational_alert(self):
        class FailingConnector:
            def collect(self):
                raise OSError("LDAP no disponible")

        with self.assertRaises(OSError):
            synchronize_inventory(InventorySyncRun.SOURCE_AD, FailingConnector())

        alert = OperationalAlert.objects.get(
            fingerprint="inventory_sync_failed:ad",
        )
        self.assertEqual(alert.severity, OperationalAlert.SEVERITY_ERROR)
        self.assertIn("LDAP no disponible", alert.message)

    def test_active_filter_is_applied_to_coverage(self):
        asset = ServerAsset.objects.create(hostname="workstation01")
        run = InventorySyncRun.objects.create(
            source=InventorySyncRun.SOURCE_AD,
            status=InventorySyncRun.STATUS_SUCCESS,
        )
        InventoryObservation.objects.create(
            sync_run=run,
            asset=asset,
            source=InventorySyncRun.SOURCE_AD,
            external_id="workstation01",
            hostname="workstation01",
        )
        InventoryFilterRule.objects.create(
            name="Excluir estaciones",
            source=InventorySyncRun.SOURCE_AD,
            field=InventoryFilterRule.FIELD_HOSTNAME,
            operator=InventoryFilterRule.OP_WILDCARD,
            pattern="workstation*",
            action=InventoryFilterRule.ACTION_EXCLUDE,
            is_active=True,
        )

        result = apply_inventory_filters()

        asset.refresh_from_db()
        self.assertFalse(asset.in_active_directory)
        self.assertTrue(asset.is_enabled)
        self.assertTrue(asset.is_excluded_by_rule)
        self.assertFalse(asset.is_effectively_enabled)
        self.assertEqual(result["excluded"], 1)
        self.assertEqual(result["excluded_assets"], 1)
        self.assertEqual(InventoryFilterDecision.objects.count(), 1)

    def test_disabling_exclusion_rule_restores_automatic_scope_only(self):
        asset = ServerAsset.objects.create(
            hostname="ltp-restored",
            is_enabled=True,
        )
        run = InventorySyncRun.objects.create(
            source=InventorySyncRun.SOURCE_AD,
            status=InventorySyncRun.STATUS_SUCCESS,
        )
        InventoryObservation.objects.create(
            sync_run=run,
            asset=asset,
            source=InventorySyncRun.SOURCE_AD,
            external_id=asset.hostname,
            hostname=asset.hostname,
        )
        rule = InventoryFilterRule.objects.create(
            name="Excluir LTP restaurable",
            source=InventorySyncRun.SOURCE_AD,
            field=InventoryFilterRule.FIELD_HOSTNAME,
            operator=InventoryFilterRule.OP_WILDCARD,
            pattern="ltp*",
            action=InventoryFilterRule.ACTION_EXCLUDE,
            is_active=True,
        )

        apply_inventory_filters()
        asset.refresh_from_db()
        self.assertTrue(asset.is_excluded_by_rule)

        rule.is_active = False
        rule.save(update_fields=["is_active"])
        apply_inventory_filters()

        asset.refresh_from_db()
        self.assertFalse(asset.is_excluded_by_rule)
        self.assertTrue(asset.is_enabled)
        self.assertTrue(asset.is_effectively_enabled)

    def test_reprocess_button_enqueues_background_job(self):
        user = get_user_model().objects.create_user("reprocess-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="reprocess-admin", password="pass")
        ServerAsset.objects.create(hostname="arpads99")
        InventoryFilterRule.objects.create(
            name="DC ARPADS",
            source=InventoryFilterRule.SOURCE_BOTH,
            field=InventoryFilterRule.FIELD_HOSTNAME,
            operator=InventoryFilterRule.OP_WILDCARD,
            pattern="arpads*",
            action=InventoryFilterRule.ACTION_CLASSIFY,
            server_type_value=ServerAsset.TYPE_AD,
            priority=1,
            is_active=True,
        )

        response = self.client.post(reverse("server_heatmap_reprocess"))

        self.assertRedirects(response, reverse("server_heatmap_administration"))
        job = InventoryJob.objects.get(job_type=InventoryJob.TYPE_REPROCESS)
        self.assertEqual(job.status, InventoryJob.STATUS_PENDING)
        self.assertEqual(job.requested_by, user)

    def test_diagnose_button_enqueues_complete_background_job(self):
        user = get_user_model().objects.create_user("diagnose-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="diagnose-admin", password="pass")

        response = self.client.post(reverse("server_heatmap_gap_diagnose"))

        self.assertRedirects(response, reverse("server_heatmap_administration"))
        job = InventoryJob.objects.get(job_type=InventoryJob.TYPE_NETWORK_DIAGNOSTIC)
        self.assertEqual(job.status, InventoryJob.STATUS_PENDING)
        self.assertEqual(job.requested_by, user)

    @patch(
        "apps.server_heatmap.jobs.run_network_diagnostics",
        return_value={"checked": 1200, "disabled": 25},
    )
    def test_worker_executes_complete_network_diagnostic(self, diagnostic):
        job, _ = enqueue_inventory_job(InventoryJob.TYPE_NETWORK_DIAGNOSTIC)
        claimed = claim_next_inventory_job("worker-test")

        completed = execute_inventory_job(claimed, "worker-test")

        diagnostic.assert_called_once()
        self.assertEqual(completed.status, InventoryJob.STATUS_COMPLETED)
        self.assertEqual(completed.result["checked"], 1200)
        self.assertEqual(completed.result["disabled"], 25)

    @override_settings(
        ADMIN_ACTION_RATE_LIMIT_SYNC=2,
        ADMIN_ACTION_RATE_LIMIT_WINDOW_SECONDS=60,
    )
    def test_sync_actions_are_rate_limited_per_user(self):
        user = get_user_model().objects.create_user("sync-rate-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="sync-rate-admin", password="pass")

        first = self.client.post(reverse("server_heatmap_sync"))
        second = self.client.post(reverse("server_heatmap_sync"))
        blocked = self.client.post(reverse("server_heatmap_sync"))

        self.assertEqual(first.status_code, 302)
        self.assertEqual(second.status_code, 302)
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked["Retry-After"], "60")
        self.assertEqual(
            InventoryJob.objects.filter(job_type=InventoryJob.TYPE_FULL_SYNC).count(),
            1,
        )

    def test_sync_endpoint_rejects_post_without_csrf_token(self):
        user = get_user_model().objects.create_user("csrf-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(user)

        response = csrf_client.post(reverse("server_heatmap_sync"))

        self.assertEqual(response.status_code, 403)
        self.assertFalse(
            InventoryJob.objects.filter(job_type=InventoryJob.TYPE_FULL_SYNC).exists(),
        )

    def test_inventory_job_enqueue_deduplicates_active_type(self):
        first, created = enqueue_inventory_job(
            InventoryJob.TYPE_FULL_SYNC,
            idempotency_key="request-1",
        )
        second, second_created = enqueue_inventory_job(
            InventoryJob.TYPE_FULL_SYNC,
            idempotency_key="request-2",
        )

        self.assertTrue(created)
        self.assertFalse(second_created)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(InventoryJob.objects.count(), 1)

    def test_unified_rule_revisions_capture_create_update_and_delete(self):
        rule = InventoryFilterRule.objects.create(
            name="Regla versionada",
            source=InventoryFilterRule.SOURCE_BOTH,
            field=InventoryFilterRule.FIELD_HOSTNAME,
            operator=InventoryFilterRule.OP_WILDCARD,
            pattern="srv*",
            action=InventoryFilterRule.ACTION_CLASSIFY,
            server_type_value=ServerAsset.TYPE_APPLICATION,
            priority=10,
        )
        created = InventoryRuleRevision.objects.get(
            rule_type=InventoryRuleRevision.TYPE_FILTER,
            rule_object_id=rule.pk,
            version=1,
        )
        self.assertEqual(created.action, InventoryRuleRevision.ACTION_CREATED)
        self.assertEqual(created.after_snapshot["pattern"], "srv*")

        rule.pattern = "app*"
        rule.priority = 20
        rule.save()
        updated = InventoryRuleRevision.objects.get(
            rule_type=InventoryRuleRevision.TYPE_FILTER,
            rule_object_id=rule.pk,
            version=2,
        )
        self.assertEqual(updated.action, InventoryRuleRevision.ACTION_UPDATED)
        self.assertEqual(updated.before_snapshot["pattern"], "srv*")
        self.assertEqual(updated.after_snapshot["pattern"], "app*")
        self.assertIn("pattern", updated.changed_fields)
        self.assertIn("priority", updated.changed_fields)

        rule.save()
        self.assertEqual(
            InventoryRuleRevision.objects.filter(
                rule_type=InventoryRuleRevision.TYPE_FILTER,
                rule_object_id=rule.pk,
            ).count(),
            2,
        )

        rule_id = rule.pk
        rule.delete()
        deleted = InventoryRuleRevision.objects.get(
            rule_type=InventoryRuleRevision.TYPE_FILTER,
            rule_object_id=rule_id,
            version=3,
        )
        self.assertEqual(deleted.action, InventoryRuleRevision.ACTION_DELETED)
        self.assertEqual(deleted.before_snapshot["name"], "Regla versionada")
        self.assertEqual(deleted.after_snapshot, {})

    def test_filter_rule_revisions_capture_functional_changes(self):
        rule = InventoryFilterRule.objects.create(
            name="Filtro versionado",
            source=InventoryFilterRule.SOURCE_BOTH,
            field=InventoryFilterRule.FIELD_HOSTNAME,
            operator=InventoryFilterRule.OP_WILDCARD,
            pattern="old*",
            action=InventoryFilterRule.ACTION_EXCLUDE,
        )
        rule.pattern = "new*"
        rule.reason = "Ajuste de alcance"
        rule.save()

        revision = InventoryRuleRevision.objects.get(
            rule_type=InventoryRuleRevision.TYPE_FILTER,
            rule_object_id=rule.pk,
            version=2,
        )
        self.assertEqual(revision.before_snapshot["pattern"], "old*")
        self.assertEqual(revision.after_snapshot["pattern"], "new*")
        self.assertEqual(revision.after_snapshot["reason"], "Ajuste de alcance")

    def test_django_admin_rule_change_records_authenticated_actor(self):
        admin_user = get_user_model().objects.create_superuser(
            "django-rule-admin",
            "rule-admin@example.local",
            "pass",
        )
        rule = InventoryFilterRule.objects.create(
            name="Regla desde Django Admin",
            source=InventoryFilterRule.SOURCE_BOTH,
            field=InventoryFilterRule.FIELD_HOSTNAME,
            operator=InventoryFilterRule.OP_WILDCARD,
            pattern="before*",
            action=InventoryFilterRule.ACTION_CLASSIFY,
            server_type_value=ServerAsset.TYPE_APPLICATION,
            priority=10,
        )
        self.client.force_login(admin_user)

        response = self.client.post(
            reverse("admin:server_heatmap_inventoryfilterrule_change", args=[rule.pk]),
            {
                "name": rule.name,
                "source": InventoryFilterRule.SOURCE_BOTH,
                "field": InventoryFilterRule.FIELD_HOSTNAME,
                "operator": InventoryFilterRule.OP_WILDCARD,
                "pattern": "after*",
                "action": InventoryFilterRule.ACTION_CLASSIFY,
                "os_family": "",
                "server_type_value": ServerAsset.TYPE_APPLICATION,
                "category": "",
                "environment_value": "",
                "priority": 10,
                "is_active": "on",
                "reason": "",
                "_save": "Guardar",
            },
        )

        self.assertEqual(response.status_code, 302)
        revision = InventoryRuleRevision.objects.get(
            rule_type=InventoryRuleRevision.TYPE_FILTER,
            rule_object_id=rule.pk,
            version=2,
        )
        self.assertEqual(revision.changed_by, admin_user)
        self.assertEqual(revision.after_snapshot["pattern"], "after*")

    def test_inventory_job_duplicate_running_requests_rerun(self):
        job, _ = enqueue_inventory_job(InventoryJob.TYPE_APPLY_FILTERS)
        job.status = InventoryJob.STATUS_RUNNING
        job.worker_id = "worker-1"
        job.lease_expires_at = django_timezone.now() + timedelta(minutes=5)
        job.save()

        duplicate, created = enqueue_inventory_job(InventoryJob.TYPE_APPLY_FILTERS)

        self.assertFalse(created)
        self.assertEqual(duplicate.pk, job.pk)
        duplicate.refresh_from_db()
        self.assertTrue(duplicate.rerun_requested)

    def test_worker_claims_job_with_lease(self):
        job, _ = enqueue_inventory_job(InventoryJob.TYPE_APPLY_FILTERS)

        claimed = claim_next_inventory_job("worker-test")

        self.assertEqual(claimed.pk, job.pk)
        self.assertEqual(claimed.status, InventoryJob.STATUS_RUNNING)
        self.assertEqual(claimed.attempts, 1)
        self.assertEqual(claimed.worker_id, "worker-test")
        self.assertIsNotNone(claimed.lease_expires_at)

    @patch("apps.server_heatmap.jobs._execute", return_value={"processed": 10})
    def test_worker_completes_job(self, execute):
        job, _ = enqueue_inventory_job(InventoryJob.TYPE_APPLY_FILTERS)
        claimed = claim_next_inventory_job("worker-test")

        completed = execute_inventory_job(claimed, "worker-test")

        execute.assert_called_once()
        self.assertEqual(completed.status, InventoryJob.STATUS_COMPLETED)
        self.assertEqual(completed.result, {"processed": 10})
        self.assertIsNotNone(completed.finished_at)

    @patch(
        "apps.server_heatmap.jobs.run_full_inventory_sync",
        return_value={"ad": {"received": 3000}, "siem": {"received": 1200}},
    )
    def test_worker_executes_scheduled_full_inventory_sync(self, full_sync):
        job, _ = enqueue_inventory_job(
            InventoryJob.TYPE_FULL_SYNC,
            payload={"scheduled": True},
        )
        claimed = claim_next_inventory_job("worker-test")

        completed = execute_inventory_job(claimed, "worker-test")

        full_sync.assert_called_once()
        self.assertEqual(completed.status, InventoryJob.STATUS_COMPLETED)
        self.assertEqual(completed.result["ad"]["received"], 3000)

    @patch("apps.server_heatmap.jobs._execute", side_effect=OSError("SIEM no disponible"))
    def test_worker_retries_failed_job_without_losing_it(self, execute):
        job, _ = enqueue_inventory_job(
            InventoryJob.TYPE_FULL_SYNC,
            max_attempts=3,
        )
        claimed = claim_next_inventory_job("worker-test")

        retried = execute_inventory_job(claimed, "worker-test")

        execute.assert_called_once()
        self.assertEqual(retried.status, InventoryJob.STATUS_RETRYING)
        self.assertEqual(retried.attempts, 1)
        self.assertEqual(retried.last_error, "SIEM no disponible")
        self.assertGreater(retried.available_at, django_timezone.now())
        self.assertIsNone(retried.finished_at)

    @patch("apps.server_heatmap.jobs._execute", return_value={"processed": 10})
    def test_worker_schedules_rerun_requested_during_execution(self, execute):
        job, _ = enqueue_inventory_job(InventoryJob.TYPE_APPLY_FILTERS)
        claimed = claim_next_inventory_job("worker-test")
        InventoryJob.objects.filter(pk=job.pk).update(rerun_requested=True)

        completed = execute_inventory_job(claimed, "worker-test")

        self.assertEqual(completed.status, InventoryJob.STATUS_COMPLETED)
        queued = InventoryJob.objects.exclude(pk=job.pk).get()
        self.assertEqual(queued.job_type, InventoryJob.TYPE_APPLY_FILTERS)
        self.assertEqual(queued.status, InventoryJob.STATUS_PENDING)

    def test_expired_job_is_recovered(self):
        job, _ = enqueue_inventory_job(InventoryJob.TYPE_FULL_SYNC)
        InventoryJob.objects.filter(pk=job.pk).update(
            status=InventoryJob.STATUS_RUNNING,
            attempts=1,
            worker_id="dead-worker",
            heartbeat_at=django_timezone.now() - timedelta(minutes=10),
            lease_expires_at=django_timezone.now() - timedelta(minutes=5),
        )

        result = recover_zombie_jobs()

        job.refresh_from_db()
        self.assertEqual(result["recovered"], 1)
        self.assertEqual(job.status, InventoryJob.STATUS_RETRYING)
        self.assertEqual(job.worker_id, "")

    def test_expired_job_exhausting_attempts_is_failed(self):
        job, _ = enqueue_inventory_job(
            InventoryJob.TYPE_FULL_SYNC,
            max_attempts=1,
        )
        InventoryJob.objects.filter(pk=job.pk).update(
            status=InventoryJob.STATUS_RUNNING,
            attempts=1,
            worker_id="dead-worker",
            heartbeat_at=django_timezone.now() - timedelta(minutes=10),
            lease_expires_at=django_timezone.now() - timedelta(minutes=5),
        )

        result = recover_zombie_jobs()

        job.refresh_from_db()
        self.assertEqual(result["failed"], 1)
        self.assertEqual(job.status, InventoryJob.STATUS_FAILED)
        self.assertIsNotNone(job.finished_at)

    def test_ad_filter_only_includes_enabled_computers_active_in_period(self):
        search_filter = _active_computer_filter(
            60,
            now=datetime(2026, 7, 24, tzinfo=timezone.utc),
        )

        self.assertIn("(objectCategory=computer)", search_filter)
        self.assertIn("(!(userAccountControl:1.2.840.113556.1.4.803:=2))", search_filter)
        self.assertIn("(lastLogonTimestamp>=", search_filter)

    def test_ad_filter_with_zero_matches_original_full_computer_scope(self):
        self.assertEqual(
            _active_computer_filter(0),
            "(objectCategory=computer)",
        )

    def test_ad_search_reads_every_ldap_page(self):
        class PagedConnection:
            def __init__(self):
                self.entries = []
                self.result = {}
                self.calls = []

            def search(self, **kwargs):
                self.calls.append(kwargs)
                if len(self.calls) == 1:
                    self.entries = ["page-1-entry"]
                    cookie = b"next-page"
                else:
                    self.entries = ["page-2-entry"]
                    cookie = b""
                self.result = {
                    "controls": {
                        _PAGED_RESULTS_OID: {
                            "value": {"cookie": cookie},
                        },
                    },
                }
                return True

        connection = PagedConnection()
        entries = list(
            _paged_entries(
                connection,
                search_base="DC=ardp,DC=local",
                search_filter="(objectCategory=computer)",
                attributes=["cn"],
                page_size=500,
            )
        )

        self.assertEqual(entries, ["page-1-entry", "page-2-entry"])
        self.assertEqual(len(connection.calls), 2)
        self.assertIsNone(connection.calls[0]["paged_cookie"])
        self.assertEqual(connection.calls[1]["paged_cookie"], b"next-page")
        self.assertEqual(connection.calls[0]["paged_size"], 500)

    def test_ad_environment_matches_original_prod_or_lab_model(self):
        self.assertEqual(_environment("Servers > Production"), "PROD")
        self.assertEqual(_environment("Servidores > Producción"), "PROD")
        self.assertEqual(_environment("Domain Controllers"), "PROD")
        self.assertEqual(_environment("Servers > Desarrollo"), "LAB")
        self.assertEqual(_environment("Servers > DEV"), "LAB")
        self.assertEqual(_environment("Servers > QA"), "LAB")
        self.assertEqual(_environment("Servers > Testing"), "LAB")
        self.assertEqual(_environment("Servers > UAT"), "LAB")
        self.assertEqual(_environment("Servers > Laboratorio"), "LAB")
        self.assertEqual(_environment("Servers > Otro"), "LAB")

    def test_ldap_uri_is_split_into_host_port_and_ssl(self):
        self.assertEqual(
            _ldap_server_address("ldap://ARPADS014.ardp.local:389", True),
            ("arpads014.ardp.local", 389, False),
        )
        self.assertEqual(
            _ldap_server_address("ldaps://ldap.example.local:636", False),
            ("ldap.example.local", 636, True),
        )

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

    def test_editing_category_marks_asset_classification_as_manual(self):
        original = ServerCategory.objects.get(code="application")
        selected = ServerCategory.objects.get(code="database")
        asset = ServerAsset.objects.create(
            hostname="manual-category",
            category=original,
            environment="PROD",
            classification_source=ServerAsset.CLASSIFICATION_AUTO,
        )
        form = ServerAssetForm(
            {
                "display_name": "",
                "ip_address": "",
                "os_family": ServerAsset.OS_UNKNOWN,
                "category": selected.id,
                "application_name": "",
                "environment": "PROD",
                "classification_source": ServerAsset.CLASSIFICATION_AUTO,
                "is_enabled": "on",
                "notes": "",
            },
            instance=asset,
        )

        self.assertTrue(form.is_valid(), form.errors)
        form.save()

        asset.refresh_from_db()
        self.assertEqual(asset.category, selected)
        self.assertEqual(
            asset.classification_source,
            ServerAsset.CLASSIFICATION_MANUAL,
        )

    def test_reprocess_preserves_manual_category(self):
        manual_category = ServerCategory.objects.get(code="application")
        automatic_category = ServerCategory.objects.get(code="database")
        InventoryFilterRule.objects.create(
            name="Clasificar categoría automática de prueba",
            source=InventorySyncRun.SOURCE_AD,
            field=InventoryFilterRule.FIELD_HOSTNAME,
            operator=InventoryFilterRule.OP_WILDCARD,
            pattern="protected-*",
            action=InventoryFilterRule.ACTION_CLASSIFY,
            category=automatic_category,
            priority=1,
            is_active=True,
        )
        asset = ServerAsset.objects.create(
            hostname="protected-server",
            category=manual_category,
            classification_source=ServerAsset.CLASSIFICATION_MANUAL,
        )

        reprocess_stored_inventory()

        asset.refresh_from_db()
        self.assertEqual(asset.category, manual_category)
        self.assertEqual(
            asset.classification_source,
            ServerAsset.CLASSIFICATION_MANUAL,
        )

    def test_full_ad_sync_and_rules_preserve_manual_category(self):
        manual_category = ServerCategory.objects.get(code="application")
        automatic_category = ServerCategory.objects.get(code="database")
        InventoryFilterRule.objects.create(
            name="Regla automática que no debe pisar manual",
            source=InventorySyncRun.SOURCE_AD,
            field=InventoryFilterRule.FIELD_HOSTNAME,
            operator=InventoryFilterRule.OP_WILDCARD,
            pattern="manual-priority-*",
            action=InventoryFilterRule.ACTION_CLASSIFY,
            category=automatic_category,
            priority=1,
            is_active=True,
        )
        asset = ServerAsset.objects.create(
            hostname="manual-priority-01",
            category=manual_category,
            environment="AMBIENTE-MANUAL",
            classification_source=ServerAsset.CLASSIFICATION_MANUAL,
        )

        class Connector:
            def collect(self):
                return [
                    InventoryRecord(
                        external_id="manual-priority-01.ardp.local",
                        hostname="manual-priority-01",
                        fqdn="manual-priority-01.ardp.local",
                        os_name="AIX 7.3",
                        organizational_unit="Servers > Production",
                        environment="PROD",
                    ),
                ]

        synchronize_inventory(InventorySyncRun.SOURCE_AD, Connector())

        asset.refresh_from_db()
        self.assertEqual(asset.category, manual_category)
        self.assertEqual(asset.environment, "AMBIENTE-MANUAL")
        self.assertEqual(
            asset.classification_source,
            ServerAsset.CLASSIFICATION_MANUAL,
        )

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

        context = build_server_heatmap_context({"environment": "all"})
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

    def test_heatmap_environment_defaults_to_prod_and_supports_all(self):
        ServerAsset.objects.create(
            hostname="prod-server",
            environment="prod",
            in_active_directory=True,
            in_siem=True,
        )
        ServerAsset.objects.create(
            hostname="desa-server",
            environment="DESA",
            in_active_directory=True,
            in_siem=False,
        )

        default_context = build_server_heatmap_context({})
        desa_context = build_server_heatmap_context({"environment": "desa"})
        all_context = build_server_heatmap_context({"environment": "all"})

        self.assertEqual(default_context["selected_environment"], "PROD")
        self.assertEqual(default_context["total_assets"], 1)
        self.assertEqual(desa_context["total_assets"], 1)
        self.assertEqual(desa_context["ad_only_count"], 1)
        self.assertEqual(all_context["total_assets"], 2)
        self.assertEqual(all_context["environment_choices"], ["DESA", "PROD"])

    def test_critical_server_coverage_is_independent_from_functional_section(self):
        category = ServerCategory.objects.get(code="database")
        ServerAsset.objects.create(
            hostname="critical-covered-with-section",
            environment="PROD",
            category=category,
            is_critical=True,
            in_active_directory=True,
            in_siem=True,
        )
        pending = ServerAsset.objects.create(
            hostname="critical-pending-without-section",
            environment="PROD",
            is_critical=True,
            in_active_directory=True,
            in_siem=False,
        )
        ServerAsset.objects.create(
            hostname="standard-pending",
            environment="PROD",
            is_critical=False,
            in_active_directory=True,
            in_siem=False,
        )

        context = build_server_heatmap_context({"environment": "PROD"})
        filtered = build_server_inventory_results_context({
            "environment": "PROD",
            "criticality": "critical",
            "inventory_status": "pending",
        })

        self.assertEqual(context["critical_summary"]["total"], 2)
        self.assertEqual(context["critical_summary"]["ingested"], 1)
        self.assertEqual(context["critical_summary"]["pending"], 1)
        self.assertEqual(context["critical_summary"]["coverage_percent"], 50.0)
        self.assertEqual(
            list(filtered["inventory_page"].object_list.values_list("id", flat=True)),
            [pending.id],
        )

    def test_new_servers_card_and_inventory_filter_use_last_seven_days(self):
        recent = ServerAsset.objects.create(
            hostname="recent-server",
            environment="PROD",
            in_active_directory=True,
            ad_first_seen_at=django_timezone.now(),
        )
        old = ServerAsset.objects.create(
            hostname="old-server",
            environment="PROD",
            in_active_directory=True,
            ad_first_seen_at=django_timezone.now() - timedelta(days=8),
        )

        context = build_server_heatmap_context({"environment": "PROD"})
        filtered = build_server_inventory_results_context({
            "environment": "PROD",
            "inventory_status": "new",
        })

        self.assertEqual(context["new_server_count"], 1)
        self.assertEqual(
            list(filtered["inventory_page"].object_list.values_list("id", flat=True)),
            [recent.id],
        )

    def test_inventory_filters_ingested_pending_and_searches_in_real_time_context(self):
        ServerAsset.objects.create(
            hostname="prod-ingested",
            environment="PROD",
            ip_address="10.10.10.1",
            in_active_directory=True,
            in_siem=True,
        )
        ServerAsset.objects.create(
            hostname="prod-pending",
            environment="PROD",
            application_name="Payments",
            in_active_directory=True,
            in_siem=False,
        )
        ServerAsset.objects.create(
            hostname="lab-pending",
            environment="LAB",
            in_active_directory=True,
            in_siem=False,
        )
        ServerAsset.objects.create(
            hostname="siem-only",
            environment="PROD",
            in_active_directory=False,
            in_siem=True,
        )

        all_assets = build_server_heatmap_context({})
        ingested = build_server_heatmap_context({"inventory_status": "ingested"})
        pending = build_server_heatmap_context({"inventory_status": "pending"})
        searched = build_server_heatmap_context({
            "inventory_status": "all",
            "inventory_q": "payments",
        })

        self.assertEqual(
            [asset.hostname for asset in all_assets["inventory_page"]],
            ["prod-ingested", "prod-pending"],
        )
        self.assertEqual(
            [asset.hostname for asset in ingested["inventory_page"]],
            ["prod-ingested"],
        )
        self.assertEqual(
            [asset.hostname for asset in pending["inventory_page"]],
            ["prod-pending"],
        )
        self.assertEqual(
            [asset.hostname for asset in searched["inventory_page"]],
            ["prod-pending"],
        )
        self.assertEqual(ingested["total_assets"], 1)
        self.assertEqual(pending["total_assets"], 1)
        self.assertEqual(searched["total_assets"], 1)

    def test_grouped_os_filter_includes_linux_and_unix(self):
        ServerAsset.objects.create(
            hostname="linux-server",
            environment="PROD",
            os_family=ServerAsset.OS_LINUX,
            in_active_directory=True,
        )
        ServerAsset.objects.create(
            hostname="aix-server",
            environment="PROD",
            os_family=ServerAsset.OS_UNIX,
            in_active_directory=True,
        )
        ServerAsset.objects.create(
            hostname="windows-server",
            environment="PROD",
            os_family=ServerAsset.OS_WINDOWS,
            in_active_directory=True,
        )

        context = build_server_heatmap_context({"os": "linux_group"})

        self.assertEqual(context["total_assets"], 2)
        self.assertEqual(
            list(context["inventory_page"].object_list.values_list("hostname", flat=True)),
            ["aix-server", "linux-server"],
        )

    def test_siem_only_cell_has_neutral_no_baseline_state(self):
        category = ServerCategory.objects.get(code="exchange")
        ServerAsset.objects.create(
            hostname="siem-only-mail",
            os_family=ServerAsset.OS_WINDOWS,
            category=category,
            in_active_directory=False,
            in_siem=True,
        )

        context = build_server_heatmap_context({"environment": "all"})
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

    def test_heatmap_groups_os_into_windows_and_linux(self):
        context = build_server_heatmap_context({"environment": "all"})

        self.assertEqual(
            [row["key"] for row in context["matrix_rows"]],
            [
                ServerAsset.OS_WINDOWS,
                ServerAsset.OS_LINUX,
            ],
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
            row for row in build_server_heatmap_context({"environment": "all"})["os_rows"]
            if row["key"] == ServerAsset.OS_WINDOWS
        )

        self.assertEqual(windows["ad_count"], 100)
        self.assertEqual(windows["covered_count"], 80)
        self.assertEqual(windows["gap_count"], 20)
        self.assertEqual(windows["percent"], 80.0)
        windows_matrix = next(
            row for row in build_server_heatmap_context({"environment": "all"})["matrix_rows"]
            if row["key"] == ServerAsset.OS_WINDOWS
        )
        self.assertEqual(windows_matrix["total"], windows["ad_count"])

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
            row for row in build_server_heatmap_context({"environment": "all"})["type_rows"]
            if row["key"] == category.id
        )

        self.assertEqual(database["ad_count"], 10)
        self.assertEqual(database["covered_count"], 7)
        self.assertEqual(database["gap_count"], 3)
        self.assertEqual(database["percent"], 70.0)

    def test_os_coverage_merges_unix_into_linux_and_shows_only_two_rows(self):
        ServerAsset.objects.create(
            hostname="linux-covered",
            os_family=ServerAsset.OS_LINUX,
            in_active_directory=True,
            in_siem=True,
        )
        ServerAsset.objects.create(
            hostname="aix-pending",
            os_family=ServerAsset.OS_UNIX,
            in_active_directory=True,
            in_siem=False,
        )
        ServerAsset.objects.create(
            hostname="other-device",
            os_family=ServerAsset.OS_OTHER,
            in_active_directory=True,
            in_siem=True,
        )

        rows = build_server_heatmap_context({"environment": "all"})["os_rows"]

        self.assertEqual([row["key"] for row in rows], ["windows", "linux"])
        linux = rows[1]
        self.assertEqual(linux["ad_count"], 2)
        self.assertEqual(linux["covered_count"], 1)
        self.assertEqual(linux["gap_count"], 1)
        self.assertEqual(linux["percent"], 50.0)

    def test_inventory_and_administration_issues_paginate_independently(self):
        ServerAsset.objects.bulk_create(
            [
                ServerAsset(
                    hostname=f"gap-{number:03}",
                    environment="PROD",
                    in_active_directory=True,
                    in_siem=False,
                )
                for number in range(55)
            ]
        )
        run = InventorySyncRun.objects.create(
            source=InventorySyncRun.SOURCE_SIEM,
            status=InventorySyncRun.STATUS_SUCCESS,
        )
        observations = InventoryObservation.objects.bulk_create(
            [
                InventoryObservation(
                    sync_run=run,
                    source=InventorySyncRun.SOURCE_SIEM,
                    external_id=f"siem-{number:03}",
                    hostname=f"orphan-{number:03}",
                )
                for number in range(55)
            ]
        )
        ReconciliationIssue.objects.bulk_create(
            [
                ReconciliationIssue(
                    sync_run=run,
                    observation=observation,
                    issue_type=ReconciliationIssue.TYPE_NOT_IN_AD,
                    identifier=observation.external_id,
                )
                for observation in observations
            ]
        )
        user = get_user_model().objects.create_user("pagination-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="pagination-admin", password="pass")

        inventory_response = self.client.get(
            reverse("server_heatmap"),
            {"inventory_page": 2},
        )
        issues_response = self.client.get(
            reverse("server_heatmap_administration_list_results"),
            {"list": "issues", "page": 2},
        )

        self.assertEqual(inventory_response.status_code, 200)
        self.assertEqual(inventory_response.context["inventory_page"].number, 2)
        self.assertEqual(inventory_response.context["inventory_page"].paginator.num_pages, 2)
        self.assertEqual(len(inventory_response.context["inventory_page"]), 5)
        self.assertContains(inventory_response, 'aria-label="Paginación del inventario"')
        self.assertContains(inventory_response, "Página 2")
        self.assertEqual(issues_response.status_code, 200)
        self.assertEqual(issues_response.context["issues_page"].number, 2)
        self.assertEqual(len(issues_response.context["issues_page"]), 15)
        self.assertContains(issues_response, "Página 2 de 4")

    def test_admin_role_can_open_server_heatmap(self):
        category = ServerCategory.objects.get(code="application")
        ServerAsset.objects.create(
            hostname="pending-application",
            environment="PROD",
            os_family=ServerAsset.OS_WINDOWS,
            category=category,
            in_active_directory=True,
            in_siem=False,
        )
        user = get_user_model().objects.create_user("heatmap-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="heatmap-admin", password="pass")

        response = self.client.get(reverse("server_heatmap"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Mapa de calor de servidores")
        self.assertContains(response, "Cobertura SIEM")
        self.assertContains(response, "Cubiertos")
        self.assertContains(response, "Pendientes")
        self.assertContains(response, "Total en AD")
        self.assertNotContains(response, "AD cubiertos")
        self.assertNotContains(response, "brechas ·")
        self.assertContains(response, 'class="os-coverage-card', count=2)
        self.assertContains(response, "Total AD = 100%")
        self.assertContains(response, 'class="inventory-strip row g-3 my-1"', count=1)
        self.assertContains(response, 'class="server-kpi server-card card h-100"', count=4)
        self.assertContains(response, 'data-live-search="off"', count=1)
        self.assertNotContains(response, "Aplicar filtros")
        self.assertContains(response, "Limpiar filtros")
        self.assertContains(response, 'data-heatmap-filter')
        self.assertContains(response, 'aria-pressed="false"', count=1)
        self.assertContains(response, 'name="type" type="hidden"', count=1)
        self.assertNotContains(response, 'class="heat-pending-link"')
        self.assertNotContains(response, "Equipos visibles")
        self.assertNotContains(response, "<span>En SIEM</span>", html=True)

    def test_admin_role_can_manage_inventory_from_front_panel(self):
        user = get_user_model().objects.create_user("front-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="front-admin", password="pass")

        response = self.client.get(reverse("server_heatmap_administration"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Panel de administración")
        self.assertContains(response, "Configuración del inventario")
        self.assertContains(response, reverse("server_heatmap_inventory_configuration"))
        self.assertContains(response, "Administrar equipos")

    def test_admin_role_can_open_and_simulate_filter_panel(self):
        user = get_user_model().objects.create_user("filter-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="filter-admin", password="pass")
        self._filter_test_observation(hostname="LTP-PREVIEW")
        InventoryFilterRule.objects.create(
            name="Filtro activo de interfaz",
            source="ad",
            field="hostname",
            operator="wildcard",
            pattern="ltp*",
            action="exclude",
            is_active=True,
        )

        response = self.client.get(
            reverse("server_heatmap_filter_list"),
            {"simulate": "1"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Reglas de inventario")
        self.assertContains(response, "Resultado de la simulación")
        self.assertContains(response, "LTP-PREVIEW")

    def test_front_panel_updates_configuration_and_links_unified_rules(self):
        user = get_user_model().objects.create_user("settings-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="settings-admin", password="pass")

        response = self.client.post(
            reverse("server_heatmap_inventory_configuration"),
            {
                "siem_sync_interval_days": 1,
                "siem_sync_time": "02:00",
                "ad_active_days": 45,
                "retention_days": 120,
                "inventory_history_days": 180,
                "job_history_days": 90,
                "dashboard_period_days": 7,
                "ingestion_sla_days": 3,
                "dashboard_default_environment": "PROD",
                "dashboard_enabled_only": "on",
                "dashboard_page_size": 25,
            },
        )
        self.assertRedirects(response, reverse("server_heatmap_inventory_configuration"))
        configuration = ServerInventoryConfiguration.load()
        self.assertEqual(configuration.ad_active_days, 45)
        self.assertEqual(configuration.retention_days, 120)
        response = self.client.get(reverse("server_heatmap_administration"))
        self.assertContains(response, "Reglas de inventario")
        self.assertContains(response, reverse("server_heatmap_filter_list"))
        self.assertNotContains(response, "Reglas de nomenclatura")

    def test_global_notification_is_rendered_once_and_does_not_accumulate(self):
        user = get_user_model().objects.create_user("notification-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="notification-admin", password="pass")

        response = self.client.post(
            reverse("server_heatmap_inventory_configuration"),
            {
                "siem_sync_interval_days": 1,
                "siem_sync_time": "02:00",
                "ad_active_days": 45,
                "retention_days": 120,
                "inventory_history_days": 180,
                "job_history_days": 90,
                "dashboard_period_days": 7,
                "ingestion_sla_days": 3,
                "dashboard_default_environment": "PROD",
                "dashboard_enabled_only": "on",
                "dashboard_page_size": 25,
            },
            follow=True,
        )

        self.assertContains(response, "Configuración del inventario actualizada.")
        self.assertContains(response, "data-server-message", count=1)

        next_page = self.client.get(reverse("source_list"))
        self.assertNotContains(next_page, "Configuración del inventario actualizada.")
        self.assertNotContains(next_page, "data-server-message")

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
            {
                "action": "disable_assets",
                "asset_ids": [asset.id],
                "disable_justification": "Servidor retirado del inventario operativo.",
            },
        )

        self.assertRedirects(response, reverse("server_heatmap_administration"))
        asset.refresh_from_db()
        self.assertFalse(asset.is_enabled)
        event = ServerAssetDisableEvent.objects.get(asset=asset)
        self.assertEqual(event.actor.username, "asset-admin")
        self.assertEqual(
            event.justification,
            "Servidor retirado del inventario operativo.",
        )
        self.assertTrue(event.previous_enabled)
        self.assertFalse(event.new_enabled)

    def test_front_panel_rejects_disable_without_justification(self):
        user = get_user_model().objects.create_user("asset-admin-no-reason", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="asset-admin-no-reason", password="pass")
        asset = ServerAsset.objects.create(hostname="keep-enabled")

        response = self.client.post(
            reverse("server_heatmap_administration"),
            {"action": "disable_assets", "asset_ids": [asset.id]},
        )

        self.assertRedirects(response, reverse("server_heatmap_administration"))
        asset.refresh_from_db()
        self.assertTrue(asset.is_enabled)
        self.assertFalse(ServerAssetDisableEvent.objects.filter(asset=asset).exists())

    def test_front_panel_can_mark_and_clear_selected_assets_as_critical(self):
        user = get_user_model().objects.create_user("critical-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="critical-admin", password="pass")
        selected = ServerAsset.objects.create(hostname="critical-selected")
        untouched = ServerAsset.objects.create(hostname="critical-untouched")

        response = self.client.post(
            reverse("server_heatmap_administration"),
            {"action": "mark_critical_assets", "asset_ids": [selected.id]},
        )

        self.assertEqual(response.status_code, 302)
        selected.refresh_from_db()
        untouched.refresh_from_db()
        self.assertTrue(selected.is_critical)
        self.assertFalse(untouched.is_critical)
        event = AuditLog.objects.get(action="server_assets_criticality_changed")
        self.assertEqual(event.actor, user)
        self.assertTrue(event.details["is_critical"])
        self.assertEqual(event.details["hostnames"], [selected.hostname])

        self.client.post(
            reverse("server_heatmap_administration"),
            {"action": "clear_critical_assets", "asset_ids": [selected.id]},
        )
        selected.refresh_from_db()
        self.assertFalse(selected.is_critical)

    def test_asset_results_filter_without_rendering_full_panel(self):
        user = get_user_model().objects.create_user("live-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="live-admin", password="pass")
        ServerAsset.objects.create(hostname="srv-search-target")
        ServerAsset.objects.create(hostname="srv-unrelated")

        response = self.client.get(
            reverse("server_heatmap_asset_results"),
            {"q": "search-target"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "srv-search-target")
        self.assertNotContains(response, "srv-unrelated")
        self.assertNotContains(response, "Panel de administración")

    def test_asset_results_filter_by_ping_status(self):
        user = get_user_model().objects.create_user("ping-filter-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="ping-filter-admin", password="pass")
        checked_at = django_timezone.now()
        ServerAsset.objects.bulk_create([
            ServerAsset(
                hostname=f"ping-down-{index:02d}",
                reachability_status=ServerAsset.REACHABILITY_UNREACHABLE,
                network_checked_at=checked_at,
            )
            for index in range(21)
        ])
        ServerAsset.objects.create(
            hostname="ping-up",
            reachability_status=ServerAsset.REACHABILITY_REACHABLE,
            network_checked_at=checked_at,
        )

        response = self.client.get(
            reverse("server_heatmap_asset_results"),
            {"ping": ServerAsset.REACHABILITY_UNREACHABLE},
        )
        full_response = self.client.get(
            reverse("server_heatmap_administration"),
            {"ping": ServerAsset.REACHABILITY_UNREACHABLE},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Ping")
        self.assertContains(response, "No responde")
        self.assertContains(response, "ping-down-00")
        self.assertNotContains(response, "ping-up")
        self.assertContains(response, "ping=unreachable")
        self.assertEqual(response.context["selected_ping"], "unreachable")
        self.assertEqual(full_response.context["selected_ping"], "unreachable")
        self.assertContains(full_response, 'value="unreachable" selected')

    def test_asset_administration_displays_and_filters_environment(self):
        user = get_user_model().objects.create_user("environment-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="environment-admin", password="pass")
        ServerAsset.objects.create(hostname="prod-admin", environment="PROD")
        ServerAsset.objects.create(hostname="lab-admin", environment="LAB")

        response = self.client.get(
            reverse("server_heatmap_asset_results"),
            {"asset_environment": "LAB"},
        )
        full_response = self.client.get(reverse("server_heatmap_administration"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Ambiente")
        self.assertContains(response, "lab-admin")
        self.assertNotContains(response, "prod-admin")
        self.assertContains(full_response, 'name="asset_environment"')
        self.assertContains(full_response, '>LAB</option>')

    def test_asset_results_treat_rule_exclusion_as_disabled(self):
        user = get_user_model().objects.create_user(
            "rule-exclusion-admin",
            password="pass",
        )
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="rule-exclusion-admin", password="pass")
        ServerAsset.objects.create(
            hostname="ltp-rule-disabled",
            is_enabled=True,
            is_excluded_by_rule=True,
        )

        enabled_response = self.client.get(
            reverse("server_heatmap_asset_results"),
            {"q": "ltp-rule-disabled", "enabled": "yes"},
        )
        disabled_response = self.client.get(
            reverse("server_heatmap_asset_results"),
            {"q": "ltp-rule-disabled", "enabled": "no"},
        )

        self.assertNotContains(
            enabled_response,
            "<strong>ltp-rule-disabled</strong>",
            html=True,
        )
        self.assertContains(
            disabled_response,
            "<strong>ltp-rule-disabled</strong>",
            html=True,
        )
        self.assertContains(disabled_response, "Deshabilitado")

    def test_asset_ajax_combines_state_section_ping_environment_and_criticality(self):
        user = get_user_model().objects.create_user("combined-filter-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="combined-filter-admin", password="pass")
        category = ServerCategory.objects.get(code="database")
        target = ServerAsset.objects.create(
            hostname="combined-filter-target",
            category=category,
            environment="LAB",
            is_enabled=False,
            reachability_status=ServerAsset.REACHABILITY_UNREACHABLE,
            is_critical=True,
        )
        ServerAsset.objects.create(
            hostname="wrong-state",
            category=category,
            environment="LAB",
            is_enabled=True,
            reachability_status=ServerAsset.REACHABILITY_UNREACHABLE,
            is_critical=True,
        )
        ServerAsset.objects.create(
            hostname="wrong-criticality",
            category=category,
            environment="LAB",
            is_enabled=False,
            reachability_status=ServerAsset.REACHABILITY_UNREACHABLE,
            is_critical=False,
        )

        params = {
            "enabled": "no",
            "type": category.id,
            "ping": ServerAsset.REACHABILITY_UNREACHABLE,
            "asset_environment": "LAB",
            "criticality": "critical",
        }
        response = self.client.get(reverse("server_heatmap_asset_results"), params)
        full_response = self.client.get(reverse("server_heatmap_administration"), params)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["asset_page"].object_list), [target])
        self.assertEqual(list(full_response.context["asset_page"].object_list), [target])
        self.assertContains(response, "combined-filter-target")
        self.assertNotContains(response, "wrong-state")
        self.assertNotContains(response, "wrong-criticality")

    def test_criticality_survives_ad_inventory_refresh(self):
        asset = ServerAsset.objects.create(
            hostname="critical-persistent",
            is_critical=True,
            in_active_directory=True,
        )

        class Connector:
            def collect(self):
                return [
                    InventoryRecord(
                        external_id="critical-persistent",
                        hostname="critical-persistent",
                        os_name="Windows Server 2022",
                    ),
                ]

        synchronize_inventory(InventorySyncRun.SOURCE_AD, Connector())

        asset.refresh_from_db()
        self.assertTrue(asset.is_critical)

    def test_new_inventory_filter_is_active_by_default(self):
        user = get_user_model().objects.create_user(
            "new-filter-admin",
            password="pass",
        )
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="new-filter-admin", password="pass")

        response = self.client.get(reverse("server_heatmap_filter_create"))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["form"]["is_active"].value())

    def test_sections_page_and_legacy_rule_route_use_unified_rules(self):
        user = get_user_model().objects.create_user("catalog-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="catalog-admin", password="pass")

        sections = self.client.get(reverse("server_heatmap_sections"))
        rules = self.client.get(reverse("server_heatmap_naming_rules"))

        self.assertEqual(sections.status_code, 200)
        self.assertContains(sections, "Secciones funcionales")
        self.assertRedirects(rules, reverse("server_heatmap_filter_list"))

    def test_used_section_can_be_deleted_and_relations_are_detached(self):
        user = get_user_model().objects.create_user("delete-section-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="delete-section-admin", password="pass")
        category = ServerCategory.objects.create(name="Temporal", code="temporal")
        asset = ServerAsset.objects.create(hostname="srv-temporal", category=category)
        rule = InventoryFilterRule.objects.create(
            name="Regla temporal",
            source=InventoryFilterRule.SOURCE_BOTH,
            field=InventoryFilterRule.FIELD_HOSTNAME,
            operator=InventoryFilterRule.OP_WILDCARD,
            pattern="tmp*",
            action=InventoryFilterRule.ACTION_CLASSIFY,
            category=category,
        )

        response = self.client.post(
            reverse("server_heatmap_category_delete", args=[category.id]),
        )

        self.assertRedirects(response, reverse("server_heatmap_sections"))
        self.assertFalse(ServerCategory.objects.filter(pk=category.id).exists())
        asset.refresh_from_db()
        rule.refresh_from_db()
        self.assertIsNone(asset.category_id)
        self.assertIsNone(rule.category_id)
        category_revision = InventoryRuleRevision.objects.get(
            rule_type=InventoryRuleRevision.TYPE_FILTER,
            rule_object_id=rule.pk,
            version=2,
        )
        self.assertIn("category", category_revision.changed_fields)
        self.assertIsNone(category_revision.after_snapshot["category_id"])

    def test_rule_history_page_lists_versions_and_requires_management_permission(self):
        admin_user = get_user_model().objects.create_user("history-admin", password="pass")
        admin_group, _ = Group.objects.get_or_create(name="Admin")
        admin_user.groups.add(admin_group)
        readonly_user = get_user_model().objects.create_user("history-readonly", password="pass")
        readonly_group, _ = Group.objects.get_or_create(name="ReadOnly")
        readonly_user.groups.add(readonly_group)
        rule = InventoryFilterRule.objects.create(
            name="Regla visible en historial",
            source=InventoryFilterRule.SOURCE_BOTH,
            field=InventoryFilterRule.FIELD_HOSTNAME,
            operator=InventoryFilterRule.OP_WILDCARD,
            pattern="history*",
            action=InventoryFilterRule.ACTION_CLASSIFY,
            server_type_value=ServerAsset.TYPE_APPLICATION,
        )

        self.client.login(username="history-admin", password="pass")
        response = self.client.get(
            reverse("server_heatmap_rule_history"),
            {"type": "filter", "id": rule.pk},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Regla visible en historial")
        self.assertContains(response, "v1")

        self.client.logout()
        self.client.login(username="history-readonly", password="pass")
        forbidden = self.client.get(reverse("server_heatmap_rule_history"))
        self.assertEqual(forbidden.status_code, 403)

    @patch(
        "apps.server_heatmap.network_diagnostics.socket.gethostbyaddr",
        return_value=("srv-dns.ardp.local", [], ["10.20.30.40"]),
    )
    def test_conflict_can_resolve_name_by_reverse_dns(self, _gethostbyaddr):
        user = get_user_model().objects.create_user("dns-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="dns-admin", password="pass")
        asset = ServerAsset.objects.create(
            hostname="srv-dns",
            in_active_directory=True,
        )
        run = InventorySyncRun.objects.create(
            source=InventorySyncRun.SOURCE_SIEM,
            status=InventorySyncRun.STATUS_SUCCESS,
        )
        observation = InventoryObservation.objects.create(
            sync_run=run,
            source=InventorySyncRun.SOURCE_SIEM,
            external_id="rhlinux:10.20.30.40",
            ip_address="10.20.30.40",
        )
        issue = ReconciliationIssue.objects.create(
            sync_run=run,
            observation=observation,
            issue_type=ReconciliationIssue.TYPE_NOT_IN_AD,
            identifier="10.20.30.40",
        )

        response = self.client.post(
            reverse("server_heatmap_administration"),
            {"action": "resolve_issue_names", "issue_ids": [issue.id]},
        )

        self.assertRedirects(response, reverse("server_heatmap_administration"))
        issue.refresh_from_db()
        observation.refresh_from_db()
        asset.refresh_from_db()
        self.assertTrue(issue.is_resolved)
        self.assertEqual(observation.asset_id, asset.id)
        self.assertEqual(observation.hostname, "srv-dns")
        self.assertTrue(asset.in_siem)

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
            environment="PROD",
            os_family=ServerAsset.OS_WINDOWS,
            in_active_directory=True,
            in_siem=True,
        )
        ServerAsset.objects.create(
            hostname="win02",
            environment="PROD",
            os_family=ServerAsset.OS_WINDOWS,
            in_active_directory=True,
            in_siem=True,
        )
        ServerAsset.objects.create(
            hostname="win03",
            environment="PROD",
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

    def test_inventory_export_uses_the_same_filters_as_the_list(self):
        ServerAsset.objects.create(
            hostname="missing01", environment="PROD",
            in_active_directory=True, in_siem=False,
        )
        ServerAsset.objects.create(
            hostname="covered01", environment="PROD",
            in_active_directory=True, in_siem=True,
        )
        user = get_user_model().objects.create_user("export-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="export-admin", password="pass")

        response = self.client.get(
            reverse("server_heatmap_gap_export"),
            {"environment": "PROD", "enabled": "yes", "inventory_status": "pending"},
        )

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

    @patch(
        "apps.server_heatmap.network_diagnostics.socket.getaddrinfo",
        side_effect=OSError("Name or service not known"),
    )
    def test_network_diagnostic_without_resolved_ip_is_error_not_unchecked(self, _getaddrinfo):
        asset = ServerAsset.objects.create(
            hostname="buapaix-unresolved",
            in_active_directory=True,
            in_siem=False,
        )

        result = diagnose_asset(asset)

        self.assertEqual(result.dns_status, ServerAsset.DNS_FAILED)
        self.assertEqual(result.reachability_status, ServerAsset.REACHABILITY_ERROR)
        self.assertIn("no se obtuvo una dirección IP", result.error)

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

    @patch("apps.server_heatmap.network_diagnostics.diagnose_asset")
    def test_pending_and_disabled_diagnostic_auto_disables_network_failures(self, diagnose):
        from .network_diagnostics import NetworkDiagnosticResult

        pending = ServerAsset.objects.create(
            hostname="pending-unreachable",
            in_active_directory=True,
            in_siem=False,
        )
        disabled = ServerAsset.objects.create(
            hostname="disabled-reachable",
            in_active_directory=True,
            is_enabled=False,
            network_checked_at=django_timezone.now() - timedelta(days=1),
        )
        checked_at = django_timezone.now()
        checked = ServerAsset.objects.create(
            hostname="checked-enabled",
            in_active_directory=True,
            reachability_status=ServerAsset.REACHABILITY_REACHABLE,
            network_checked_at=checked_at,
        )
        errored = ServerAsset.objects.create(
            hostname="errored-enabled",
            in_active_directory=True,
            reachability_status=ServerAsset.REACHABILITY_ERROR,
            network_checked_at=checked_at,
        )

        def result_for(asset, *, timeout):
            status = (
                ServerAsset.REACHABILITY_UNREACHABLE
                if asset.id == pending.id
                else (
                    ServerAsset.REACHABILITY_ERROR
                    if asset.id == errored.id
                    else ServerAsset.REACHABILITY_REACHABLE
                )
            )
            return NetworkDiagnosticResult(
                asset_id=asset.id,
                dns_status=ServerAsset.DNS_RESOLVED,
                resolved_ip_address="10.0.0.30",
                reachability_status=status,
            )

        diagnose.side_effect = result_for
        summary = diagnose_ingestion_gaps(
            limit=10,
            only_unchecked=True,
            include_disabled=True,
            include_covered=True,
            auto_disable_failures=True,
        )

        pending.refresh_from_db()
        disabled.refresh_from_db()
        checked.refresh_from_db()
        errored.refresh_from_db()
        self.assertEqual(summary["checked"], 3)
        self.assertEqual(summary["disabled"], 1)
        self.assertEqual(summary["errors"], 1)
        self.assertFalse(pending.is_enabled)
        self.assertFalse(disabled.is_enabled)
        self.assertTrue(errored.is_enabled)
        self.assertEqual(checked.network_checked_at, checked_at)
        event = ServerAssetDisableEvent.objects.get(asset=pending)
        self.assertIsNone(event.actor)
        self.assertIn("no respondió al ping", event.justification)

    @patch("apps.server_heatmap.network_diagnostics.diagnose_asset")
    def test_network_failure_disables_only_ad_asset_without_siem(self, diagnose):
        from .network_diagnostics import NetworkDiagnosticResult

        missing = ServerAsset.objects.create(
            hostname="buapaix-missing",
            in_active_directory=True,
            in_siem=False,
        )
        covered = ServerAsset.objects.create(
            hostname="buapaix-covered",
            in_active_directory=True,
            in_siem=True,
        )

        def unresolved(asset, *, timeout):
            return NetworkDiagnosticResult(
                asset_id=asset.id,
                dns_status=ServerAsset.DNS_FAILED,
                reachability_status=ServerAsset.REACHABILITY_ERROR,
                error="DNS directo: no resuelto",
            )

        diagnose.side_effect = unresolved
        summary = diagnose_ingestion_gaps(
            limit=None,
            include_covered=True,
            auto_disable_failures=True,
        )

        missing.refresh_from_db()
        covered.refresh_from_db()
        self.assertEqual(summary["disabled"], 1)
        self.assertFalse(missing.is_enabled)
        self.assertTrue(covered.is_enabled)
        event = ServerAssetDisableEvent.objects.get(asset=missing)
        self.assertIn("no resolvió DNS", event.justification)

    def _siem_only_issue(self, hostname="aix-siem-only", ip_address="10.20.30.40"):
        run = InventorySyncRun.objects.create(
            source=InventorySyncRun.SOURCE_SIEM,
            status=InventorySyncRun.STATUS_SUCCESS,
        )
        observation = InventoryObservation.objects.create(
            sync_run=run,
            source=InventorySyncRun.SOURCE_SIEM,
            external_id=hostname,
            hostname=hostname,
            ip_address=ip_address,
            os_name="IBM AIX 7.3",
            groups="aix-production",
        )
        issue = ReconciliationIssue.objects.create(
            sync_run=run,
            observation=observation,
            issue_type=ReconciliationIssue.TYPE_NOT_IN_AD,
            identifier=hostname,
        )
        return issue

    def test_promote_siem_only_issue_creates_audited_manual_asset(self):
        user = get_user_model().objects.create_user("siem-approver")
        issue = self._siem_only_issue()

        asset = promote_siem_only_issue(
            issue,
            {
                "hostname": "AIX-SIEM-ONLY",
                "display_name": "AIX exclusivo",
                "ip_address": "10.20.30.40",
                "os_family": ServerAsset.OS_UNIX,
                "category": None,
                "application_name": "Core AIX",
                "environment": "PROD",
                "is_critical": True,
                "is_enabled": False,
                "notes": "Validado por infraestructura.",
                "approval_reason": "Equipo AIX fuera del dominio por diseño.",
            },
            approved_by=user,
        )

        issue.refresh_from_db()
        issue.observation.refresh_from_db()
        self.assertEqual(asset.hostname, "aix-siem-only")
        self.assertFalse(asset.in_active_directory)
        self.assertTrue(asset.in_siem)
        self.assertTrue(asset.is_siem_only_approved)
        self.assertFalse(asset.is_enabled)
        self.assertEqual(asset.os_family, ServerAsset.OS_UNIX)
        self.assertEqual(asset.classification_source, ServerAsset.CLASSIFICATION_MANUAL)
        self.assertEqual(asset.siem_exception_approved_by, user)
        self.assertEqual(issue.observation.asset, asset)
        self.assertTrue(issue.is_resolved)

    def test_approved_siem_only_asset_survives_ad_retention_cleanup(self):
        configuration = ServerInventoryConfiguration.load()
        configuration.retention_days = 1
        configuration.save(update_fields=["retention_days"])
        asset = ServerAsset.objects.create(
            hostname="aix-retained",
            in_active_directory=False,
            in_siem=True,
            is_siem_only_approved=True,
        )
        ServerAsset.objects.filter(pk=asset.pk).update(
            created_at=django_timezone.now() - timedelta(days=30),
        )

        class EmptyConnector:
            def collect(self):
                return []

        synchronize_inventory(InventorySyncRun.SOURCE_AD, EmptyConnector())

        self.assertTrue(ServerAsset.objects.filter(pk=asset.pk).exists())

    def test_approved_siem_only_asset_returns_to_normal_flow_when_ad_finds_it(self):
        user = get_user_model().objects.create_user("siem-to-ad-approver")
        issue = self._siem_only_issue(hostname="aix-later-in-ad")
        asset = promote_siem_only_issue(
            issue,
            {
                "hostname": "aix-later-in-ad",
                "display_name": "",
                "ip_address": "10.20.30.40",
                "os_family": ServerAsset.OS_UNIX,
                "category": None,
                "application_name": "",
                "environment": "LAB",
                "is_critical": False,
                "is_enabled": True,
                "notes": "",
                "approval_reason": "Excepción temporal.",
            },
            approved_by=user,
        )

        class AdConnector:
            def collect(self):
                return [InventoryRecord(external_id=asset.hostname, hostname=asset.hostname)]

        synchronize_inventory(InventorySyncRun.SOURCE_AD, AdConnector())

        asset.refresh_from_db()
        self.assertTrue(asset.in_active_directory)
        self.assertFalse(asset.is_siem_only_approved)
        self.assertEqual(asset.siem_exception_approved_by, user)

    def test_future_siem_sync_reuses_approved_asset_without_new_conflict(self):
        user = get_user_model().objects.create_user("siem-refresh-approver")
        issue = self._siem_only_issue(hostname="aix-siem-refresh")
        asset = promote_siem_only_issue(
            issue,
            {
                "hostname": "aix-siem-refresh",
                "display_name": "AIX SIEM",
                "ip_address": "10.20.30.40",
                "os_family": ServerAsset.OS_UNIX,
                "category": None,
                "application_name": "Core",
                "environment": "PROD",
                "is_critical": False,
                "is_enabled": True,
                "notes": "",
                "approval_reason": "Fuera de AD por diseño.",
            },
            approved_by=user,
        )

        class SiemConnector:
            def collect(self):
                return [
                    InventoryRecord(
                        external_id="aix-siem-refresh",
                        hostname="aix-siem-refresh",
                        ip_address="10.20.30.40",
                        os_name="IBM AIX 7.3",
                    )
                ]

        run = synchronize_inventory(InventorySyncRun.SOURCE_SIEM, SiemConnector())

        asset.refresh_from_db()
        self.assertTrue(asset.is_siem_only_approved)
        self.assertTrue(asset.in_siem)
        self.assertEqual(run.issues_count, 0)
        self.assertEqual(run.observations.get().asset, asset)

    def test_admin_can_promote_and_filter_siem_only_assets(self):
        user = get_user_model().objects.create_user("siem-ui-admin", password="pass")
        group, _ = Group.objects.get_or_create(name="Admin")
        user.groups.add(group)
        self.client.login(username="siem-ui-admin", password="pass")
        issue = self._siem_only_issue(hostname="aix-ui-only")

        response = self.client.post(
            reverse("server_heatmap_siem_only_promote", args=[issue.id]),
            {
                "action": "promote",
                "hostname": "aix-ui-only",
                "display_name": "AIX UI",
                "ip_address": "10.20.30.40",
                "os_family": ServerAsset.OS_UNIX,
                "application_name": "Pagos",
                "environment": "PROD",
                "approval_reason": "Servidor no integrado al dominio.",
                "is_enabled": "on",
            },
        )

        asset = ServerAsset.objects.get(hostname="aix-ui-only")
        self.assertRedirects(response, reverse("server_heatmap_asset_edit", args=[asset.id]))
        filtered = self.client.get(
            reverse("server_heatmap_asset_results"),
            {"origin": "siem_only"},
        )
        self.assertContains(filtered, "aix-ui-only")
        self.assertContains(filtered, "Solo SIEM aprobado")
        self.assertTrue(
            AuditLog.objects.filter(action="server_siem_only_asset_approved").exists()
        )

    @patch("apps.server_heatmap.network_diagnostics.diagnose_asset")
    def test_selected_network_diagnostic_includes_siem_only_asset(self, diagnose):
        from .network_diagnostics import NetworkDiagnosticResult

        asset = ServerAsset.objects.create(
            hostname="aix-manual-ping",
            in_active_directory=False,
            in_siem=True,
            is_siem_only_approved=True,
            is_enabled=False,
        )
        diagnose.return_value = NetworkDiagnosticResult(
            asset_id=asset.id,
            dns_status=ServerAsset.DNS_RESOLVED,
            resolved_ip_address="10.20.30.50",
            reachability_status=ServerAsset.REACHABILITY_REACHABLE,
        )

        summary = diagnose_ingestion_gaps(asset_ids=[asset.id], limit=None)

        asset.refresh_from_db()
        self.assertEqual(summary["checked"], 1)
        self.assertEqual(asset.reachability_status, ServerAsset.REACHABILITY_REACHABLE)
        self.assertFalse(asset.is_enabled)
