from datetime import date, timedelta
from io import BytesIO, StringIO
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .coverage_admin import build_coverage_admin_context
from .mitre_sync import MitreAttackSyncResult, load_mitre_attack_data, run_scheduled_mitre_attack_sync
from .models import CoverageOverride, D3Fend, LifecycleReview, LifecycleSettings, MitreAttack, MitreAttackSyncSettings, UseCase
from .reports import build_dashboard_pdf


class UseCaseBusinessRuleTests(TestCase):
    def test_production_usecase_requires_mitre_mapping(self):
        usecase = UseCase(
            name="Suspicious process execution",
            status=UseCase.STATUS_PRODUCTION,
            production_date=date(2026, 1, 1),
        )
        usecase._clean_mitre_attack_ids = set()

        with self.assertRaises(ValidationError) as ctx:
            usecase.clean()

        self.assertIn("mitre_attacks", ctx.exception.message_dict)

    def test_sync_d3fends_from_attacks_sets_inferred_cache(self):
        attack = MitreAttack.objects.create(external_id="T1059", name="Command and Scripting Interpreter")
        d3fend = D3Fend.objects.create(code="D3-PSEP", name="Process Spawn Analysis")
        d3fend.related_attacks.add(attack)
        usecase = UseCase.objects.create(name="Command shell alert")
        usecase.mitre_attacks.add(attack)

        changed = usecase.sync_d3fends_from_attacks()

        self.assertTrue(changed)
        self.assertEqual(list(usecase.d3fends.order_by("id")), [d3fend])


class UseCaseLifecycleDateTests(TestCase):
    def test_save_does_not_recalculate_lifecycle_dates(self):
        usecase = UseCase.objects.create(
            name="Endpoint malware alert",
            last_validation_date=date(2026, 1, 1),
            next_review_date=date(2026, 3, 1),
        )

        usecase.owner_name = "SOC"
        usecase.save()
        usecase.refresh_from_db()

        self.assertEqual(usecase.next_review_date, date(2026, 3, 1))

    def test_set_lifecycle_review_dates_uses_active_interval(self):
        LifecycleSettings.objects.create(name="Monthly", review_interval_days=30)
        usecase = UseCase(name="Privileged login alert")

        usecase.set_lifecycle_review_dates(date(2026, 1, 1))

        self.assertEqual(usecase.last_review_date, date(2026, 1, 1))
        self.assertEqual(usecase.next_review_date, date(2026, 1, 31))


class MitreAttackSyncTests(TestCase):
    def test_load_mitre_attack_data_creates_and_updates_catalog(self):
        MitreAttack.objects.create(external_id="T1059", name="Old name", tactic="Execution")
        data = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Command and Scripting Interpreter",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                },
                {
                    "type": "attack-pattern",
                    "name": "Valid Accounts",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1078"}],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}],
                },
                {"type": "attack-pattern", "name": "No external id", "external_references": []},
            ]
        }

        result = load_mitre_attack_data(data)

        self.assertEqual(result.created, 1)
        self.assertEqual(result.updated, 1)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(MitreAttack.objects.get(external_id="T1059").name, "Command and Scripting Interpreter")
        self.assertEqual(MitreAttack.objects.get(external_id="T1078").tactic, "Defense Evasion")

    def test_scheduled_sync_skips_until_interval_is_due(self):
        settings = MitreAttackSyncSettings.objects.create(
            name="Hourly",
            interval_value=6,
            interval_unit=MitreAttackSyncSettings.UNIT_HOURS,
            last_success_at=timezone.now() - timedelta(hours=1),
        )

        result = run_scheduled_mitre_attack_sync(settings=settings, fetcher=lambda: self.fail("fetcher should not run"))

        self.assertFalse(result.ran)
        self.assertIn("omitida", result.message)

    def test_scheduled_sync_runs_when_due_and_updates_status(self):
        settings = MitreAttackSyncSettings.objects.create(
            name="Daily",
            interval_value=1,
            interval_unit=MitreAttackSyncSettings.UNIT_DAYS,
            last_success_at=timezone.now() - timedelta(days=2),
        )
        data = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Brute Force",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
                }
            ]
        }

        result = run_scheduled_mitre_attack_sync(settings=settings, fetcher=lambda: data)

        self.assertTrue(result.ran)
        settings.refresh_from_db()
        self.assertEqual(settings.last_status, MitreAttackSyncSettings.STATUS_SUCCESS)
        self.assertEqual(settings.last_created, 1)
        self.assertIsNotNone(settings.last_success_at)


class SeedDemoDataCommandTests(TestCase):
    def test_seed_demo_data_creates_demo_catalog_users_and_cases(self):
        call_command("seed_demo_data", verbosity=0, stdout=StringIO())

        User = get_user_model()
        self.assertTrue(User.objects.filter(username="demo_admin", is_superuser=True).exists())
        self.assertTrue(User.objects.filter(username="demo_analyst").exists())
        self.assertGreaterEqual(MitreAttack.objects.filter(external_id__in=["T1059", "T1078", "T1110"]).count(), 3)
        self.assertGreaterEqual(D3Fend.objects.filter(code__startswith="D3-").count(), 5)
        self.assertGreaterEqual(UseCase.objects.filter(name__startswith="Demo - ").count(), 8)
        self.assertTrue(LifecycleReview.objects.filter(use_case__name__startswith="Demo - ").exists())
        self.assertTrue(CoverageOverride.objects.filter(reason__icontains="[demo]").exists())

    def test_seed_demo_data_is_idempotent(self):
        call_command("seed_demo_data", verbosity=0, stdout=StringIO())
        call_command("seed_demo_data", verbosity=0, stdout=StringIO())

        self.assertEqual(get_user_model().objects.filter(username="demo_admin").count(), 1)
        self.assertEqual(MitreAttack.objects.filter(external_id="T1059").count(), 1)
        self.assertEqual(UseCase.objects.filter(name="Demo - PowerShell suspicious execution").count(), 1)
        self.assertTrue(LifecycleSettings.objects.get(name="Demo lifecycle").is_active)


class MitreAttackSyncAdminTests(TestCase):
    def test_run_now_admin_action_executes_sync(self):
        User = get_user_model()
        admin_user = User.objects.create_superuser("admin", "admin@example.test", "pass")
        settings = MitreAttackSyncSettings.objects.create(name="Admin run", interval_value=24)
        self.client.force_login(admin_user)

        with patch(
            "apps.usecases.admin.run_scheduled_mitre_attack_sync",
            return_value=MitreAttackSyncResult(created=1, updated=2, skipped=3, message="OK"),
        ) as mocked_sync:
            response = self.client.get(reverse("admin:usecases_mitreattacksyncsettings_run_now", args=[settings.pk]))

        self.assertEqual(response.status_code, 302)
        mocked_sync.assert_called_once()
        self.assertTrue(mocked_sync.call_args.kwargs["force"])
        self.assertEqual(mocked_sync.call_args.kwargs["settings"], settings)


class UseCasePermissionTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin_group = Group.objects.create(name="Admin")
        self.analyst_group = Group.objects.create(name="Analyst")
        self.readonly_group = Group.objects.create(name="ReadOnly")

        self.admin = User.objects.create_user("admin", password="pass")
        self.admin.groups.add(self.admin_group)
        self.analyst = User.objects.create_user("analyst", password="pass")
        self.analyst.groups.add(self.analyst_group)
        self.other_analyst = User.objects.create_user("other", password="pass")
        self.other_analyst.groups.add(self.analyst_group)
        self.readonly = User.objects.create_user("readonly", password="pass")
        self.readonly.groups.add(self.readonly_group)

        self.attack = MitreAttack.objects.create(external_id="T1059", name="Command and Scripting Interpreter")
        self.owned_usecase = self._create_production_usecase("Owned use case", self.analyst)
        self.other_usecase = self._create_production_usecase("Other use case", self.other_analyst)

    def _create_production_usecase(self, name, creator):
        usecase = UseCase.objects.create(
            name=name,
            owner_name=creator.username,
            created_by=creator,
            status=UseCase.STATUS_PRODUCTION,
            production_date=date(2026, 1, 1),
            severity="Low",
            is_enabled=True,
        )
        usecase.mitre_attacks.add(self.attack)
        return usecase

    def _bulk_payload(self, *usecases):
        data = {"changed_ids": ",".join(str(usecase.pk) for usecase in usecases)}
        for usecase in usecases:
            data.update({
                f"owner_name_{usecase.pk}": usecase.owner_name,
                f"severity_{usecase.pk}": "High",
                f"last_validation_date_{usecase.pk}": "",
                f"is_enabled_{usecase.pk}": "on",
                f"status_{usecase.pk}": usecase.status,
                f"validation_status_{usecase.pk}": usecase.validation_status,
                f"validation_result_{usecase.pk}": usecase.validation_result,
                f"mitre_attack_ids_{usecase.pk}": str(self.attack.pk),
            })
        return data

    def test_readonly_cannot_access_usecase_inventory(self):
        self.client.login(username="readonly", password="pass")

        response = self.client.get(reverse("usecase_list"))

        self.assertEqual(response.status_code, 403)

    def test_readonly_cannot_export_csv_or_pdf(self):
        self.client.login(username="readonly", password="pass")

        csv_response = self.client.get(reverse("export_usecases_csv"))
        pdf_response = self.client.get(reverse("dashboard_pdf_export"))

        self.assertEqual(csv_response.status_code, 403)
        self.assertEqual(pdf_response.status_code, 403)

    def test_analyst_can_export_dashboard_pdf(self):
        self.client.login(username="analyst", password="pass")

        response = self.client.get(reverse("dashboard_pdf_export"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertIn("dashboard-soc-", response["Content-Disposition"])
        self.assertTrue(response.content.startswith(b"%PDF"))

    def test_csv_export_respects_device_filter(self):
        self.owned_usecase.device = "EDR"
        self.owned_usecase.save()
        self.other_usecase.device = "SIEM"
        self.other_usecase.save()
        self.client.login(username="analyst", password="pass")

        response = self.client.get(reverse("export_usecases_csv"), {"device": "EDR"})
        content = response.content.decode("utf-8-sig")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Owned use case", content)
        self.assertNotIn("Other use case", content)

    def test_csv_export_only_includes_production_usecases(self):
        draft = UseCase.objects.create(
            name="Draft only use case",
            owner_name=self.analyst.username,
            created_by=self.analyst,
            status=UseCase.STATUS_DEVELOPMENT,
            severity="Low",
            is_enabled=True,
        )
        draft.mitre_attacks.add(self.attack)
        self.client.login(username="analyst", password="pass")

        response = self.client.get(reverse("export_usecases_csv"))
        content = response.content.decode("utf-8-sig")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Owned use case", content)
        self.assertIn("Other use case", content)
        self.assertNotIn("Draft only use case", content)

    def test_analyst_bulk_update_only_changes_owned_usecases(self):
        self.client.login(username="analyst", password="pass")

        response = self.client.post(
            reverse("usecase_bulk_update"),
            self._bulk_payload(self.owned_usecase, self.other_usecase),
        )

        self.assertEqual(response.status_code, 302)
        self.owned_usecase.refresh_from_db()
        self.other_usecase.refresh_from_db()
        self.assertEqual(self.owned_usecase.severity, "High")
        self.assertEqual(self.other_usecase.severity, "Low")

    def test_admin_bulk_update_can_change_any_usecase(self):
        self.client.login(username="admin", password="pass")

        response = self.client.post(
            reverse("usecase_bulk_update"),
            self._bulk_payload(self.other_usecase),
        )

        self.assertEqual(response.status_code, 302)
        self.other_usecase.refresh_from_db()
        self.assertEqual(self.other_usecase.severity, "High")

    def test_coverage_override_requires_reason_for_fulfilled_status(self):
        self.client.login(username="analyst", password="pass")

        response = self.client.post(reverse("coverage_override_update"), {
            "framework": CoverageOverride.FRAMEWORK_ATTACK,
            "object_type": CoverageOverride.OBJECT_TECHNIQUE,
            "object_key": self.attack.external_id,
            "object_name": self.attack.name,
            "status": CoverageOverride.STATUS_FULFILLED,
            "reason": "",
            "default_enabled": "1",
        })

        self.assertEqual(response.status_code, 302)
        self.assertFalse(CoverageOverride.objects.exists())

    def test_coverage_admin_context_searches_tactics_by_child_technique(self):
        context = build_coverage_admin_context({
            "tab": CoverageOverride.FRAMEWORK_ATTACK,
            "scope": CoverageOverride.OBJECT_TACTIC,
            "q": "T1059",
        })

        self.assertEqual(context["tab"], CoverageOverride.FRAMEWORK_ATTACK)
        self.assertEqual(context["scope"], CoverageOverride.OBJECT_TACTIC)
        self.assertEqual(len(context["rows"]), 1)

    def test_lifecycle_owner_can_mark_review_done(self):
        self.owned_usecase.lifecycle_control_owner = self.analyst
        self.owned_usecase.save()
        self.client.login(username="analyst", password="pass")

        response = self.client.post(reverse("lifecycle_mark_done", args=[self.owned_usecase.pk]))

        self.assertEqual(response.status_code, 302)
        self.owned_usecase.refresh_from_db()
        self.assertEqual(self.owned_usecase.validation_status, UseCase.VALIDATION_STATUS_FINISHED)
        self.assertEqual(LifecycleReview.objects.filter(use_case=self.owned_usecase).count(), 1)

    def test_non_owner_cannot_mark_lifecycle_review_done(self):
        self.owned_usecase.lifecycle_control_owner = self.analyst
        self.owned_usecase.save()
        self.client.login(username="other", password="pass")

        response = self.client.post(reverse("lifecycle_mark_done", args=[self.owned_usecase.pk]))

        self.assertEqual(response.status_code, 403)
        self.assertFalse(LifecycleReview.objects.filter(use_case=self.owned_usecase).exists())

    def test_admin_can_delete_usecase(self):
        self.client.login(username="admin", password="pass")

        response = self.client.post(reverse("usecase_delete", args=[self.other_usecase.pk]))

        self.assertEqual(response.status_code, 302)
        self.assertFalse(UseCase.objects.filter(pk=self.other_usecase.pk).exists())


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
                {"title": "Cobertura Tácticas ATT&CK", "percent": 50, "percent_label": "50", "covered": 2, "total": 4},
            ],
            "d3fend_radials": [
                {"title": "Cobertura D3FEND inferida por ATT&CK", "percent": 31.3, "percent_label": "31,3", "covered": 2.5, "total": 8},
                {"title": "D3FEND totalmente cubiertos", "percent": 25, "percent_label": "25", "covered": 2, "total": 8},
            ],
            "uncovered_attacks": [],
            "uncovered_d3fends": [],
            "d3fend_coverage_rows": [],
        }

        build_dashboard_pdf(buffer, context, None, SimpleNamespace(username="tester"))

        self.assertTrue(buffer.getvalue().startswith(b"%PDF"))
