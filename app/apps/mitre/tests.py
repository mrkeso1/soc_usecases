from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.mitre.framework_sync import run_scheduled_security_frameworks_sync
from apps.mitre.mitre_sync import (
    MitreAttackSyncResult,
    load_mitre_attack_data,
    run_scheduled_mitre_attack_sync,
)
from apps.mitre.models import D3Fend, MitreAttack, MitreAttackSyncSettings


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

    def test_scheduled_sync_logs_failures(self):
        settings = MitreAttackSyncSettings.objects.create(name="Failing sync", interval_value=1)

        with patch("apps.mitre.mitre_sync.logger") as mocked_logger:
            with self.assertRaises(RuntimeError):
                run_scheduled_mitre_attack_sync(
                    settings=settings,
                    fetcher=lambda: (_ for _ in ()).throw(RuntimeError("network down")),
                )

        mocked_logger.exception.assert_called_once()
        settings.refresh_from_db()
        self.assertEqual(settings.last_status, MitreAttackSyncSettings.STATUS_ERROR)

    def test_full_framework_sync_skips_when_mitre_sync_is_not_due(self):
        with patch(
            "apps.mitre.framework_sync.run_scheduled_mitre_attack_sync",
            return_value=MitreAttackSyncResult(ran=False, message="Sincronizacion MITRE omitida."),
        ) as mocked_mitre, patch(
            "apps.mitre.framework_sync.call_command"
        ) as mocked_call:
            call_command("sync_security_frameworks_scheduled", stdout=StringIO())

        mocked_mitre.assert_called_once()
        mocked_call.assert_not_called()

    def test_full_framework_sync_runs_d3fend_mapping_and_usecase_steps(self):
        with patch(
            "apps.mitre.framework_sync.run_scheduled_mitre_attack_sync",
            return_value=MitreAttackSyncResult(created=1, updated=2, skipped=3, message="OK"),
        ), patch(
            "apps.mitre.framework_sync.call_command"
        ) as mocked_call:
            call_command("sync_security_frameworks_scheduled", force=True, stdout=StringIO())

        calls = [item.args for item in mocked_call.call_args_list]
        self.assertEqual(
            calls,
            [
                ("load_d3fend", "--disable-non-detect"),
                ("normalize_d3fend_codes",),
                ("load_d3fend", "--mappings-only", "--disable-non-detect"),
                ("sync_usecase_d3fends",),
            ],
        )
        self.assertEqual(mocked_call.call_args_list[1].kwargs["sleep"], 0)

    def test_full_framework_sync_updates_settings_message(self):
        settings = MitreAttackSyncSettings.objects.create(name="Full sync", interval_value=1)
        MitreAttack.objects.create(external_id="T1000", name="Existing attack")
        D3Fend.objects.create(code="D3-TEST", name="Existing defense")

        def fake_call_command(command_name, *args, **kwargs):
            output = kwargs.get("stdout")
            if not output:
                return
            if command_name == "load_d3fend" and "--mappings-only" not in args:
                output.write("Creados: 2\nActualizados: 3\nNormalizados a código oficial: 1\n")
            elif command_name == "normalize_d3fend_codes":
                output.write("Normalizados: 4\nFusionados con registros existentes: 1\n")
            elif command_name == "load_d3fend" and "--mappings-only" in args:
                output.write("Relaciones unicas procesadas: 9\nD3FEND creados desde mappings: 1\n")
            elif command_name == "sync_usecase_d3fends":
                output.write("Casos revisados: 7\nCasos con cambios: 5\n")

        with patch(
            "apps.mitre.framework_sync.run_scheduled_mitre_attack_sync",
            return_value=MitreAttackSyncResult(created=1, updated=2, skipped=3, message="Carga ATT&CK finalizada."),
        ), patch("apps.mitre.framework_sync.call_command", side_effect=fake_call_command):
            run_scheduled_security_frameworks_sync(force=True, settings=settings)

        settings.refresh_from_db()
        self.assertIn("ATT&CK: existentes 1, creados 1, modificados 2, omitidos 3", settings.last_message)
        self.assertIn("D3FEND: existentes 1, creados 3, modificados/normalizados 8", settings.last_message)
        self.assertIn("Mappings D3FEND->ATT&CK: relaciones procesadas 9", settings.last_message)
        self.assertIn("Casos: revisados 7, matcheados/actualizados 5", settings.last_message)

    def test_full_framework_sync_uses_active_settings_for_summary_when_not_explicit(self):
        settings = MitreAttackSyncSettings.objects.create(name="Active full sync", interval_value=1)

        def fake_call_command(command_name, *args, **kwargs):
            output = kwargs.get("stdout")
            if not output:
                return
            if command_name == "load_d3fend" and "--mappings-only" not in args:
                output.write("Creados: 0\nActualizados: 0\n")
            elif command_name == "normalize_d3fend_codes":
                output.write("Normalizados: 0\nFusionados con registros existentes: 0\n")
            elif command_name == "load_d3fend" and "--mappings-only" in args:
                output.write("Relaciones unicas procesadas: 2\nD3FEND creados desde mappings: 0\n")
            elif command_name == "sync_usecase_d3fends":
                output.write("Casos revisados: 3\nCasos con cambios: 1\n")

        with patch(
            "apps.mitre.framework_sync.run_scheduled_mitre_attack_sync",
            return_value=MitreAttackSyncResult(created=0, updated=1, skipped=0, message="Carga ATT&CK finalizada."),
        ) as mocked_mitre, patch("apps.mitre.framework_sync.call_command", side_effect=fake_call_command):
            run_scheduled_security_frameworks_sync(force=True)

        settings.refresh_from_db()
        self.assertEqual(mocked_mitre.call_args.kwargs["settings"], settings)
        self.assertIn("Sincronización completa finalizada.", settings.last_message)
        self.assertIn("Mappings D3FEND->ATT&CK: relaciones procesadas 2", settings.last_message)
        self.assertIn("Casos: revisados 3, matcheados/actualizados 1", settings.last_message)


class MitreAttackSyncAdminTests(TestCase):
    def test_add_sync_settings_admin_page_renders(self):
        User = get_user_model()
        admin_user = User.objects.create_superuser("admin", "admin@example.test", "pass")
        self.client.force_login(admin_user)

        response = self.client.get(reverse("admin:mitre_mitreattacksyncsettings_add"))

        self.assertEqual(response.status_code, 200)

    def test_run_now_admin_action_executes_sync(self):
        User = get_user_model()
        admin_user = User.objects.create_superuser("admin", "admin@example.test", "pass")
        settings = MitreAttackSyncSettings.objects.create(name="Admin run", interval_value=24)
        self.client.force_login(admin_user)

        with patch(
            "apps.mitre.admin.run_scheduled_security_frameworks_sync",
            return_value=MitreAttackSyncResult(created=1, updated=2, skipped=3, message="OK"),
        ) as mocked_sync:
            response = self.client.get(reverse("admin:mitre_mitreattacksyncsettings_run_now", args=[settings.pk]))

        self.assertEqual(response.status_code, 302)
        mocked_sync.assert_called_once()
        self.assertTrue(mocked_sync.call_args.kwargs["force"])
        self.assertEqual(mocked_sync.call_args.kwargs["settings"], settings)
        messages = [str(message) for message in response.wsgi_request._messages]
        self.assertTrue(any("D3FEND" in message and "casos" in message for message in messages))

    def test_change_sync_settings_admin_page_shows_full_sync_button(self):
        User = get_user_model()
        admin_user = User.objects.create_superuser("admin", "admin@example.test", "pass")
        settings = MitreAttackSyncSettings.objects.create(name="Admin page", interval_value=24)
        self.client.force_login(admin_user)

        response = self.client.get(reverse("admin:mitre_mitreattacksyncsettings_change", args=[settings.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Ejecutar sync completo ATT&CK + D3FEND")
