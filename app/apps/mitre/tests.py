from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.mitre.framework_sync import run_scheduled_security_frameworks_sync
from apps.mitre.d3fend_matrix import build_d3fend_matrix_context
from apps.mitre.attack_ids import attack_family_query
from apps.mitre.mitre_sync import (
    MitreAttackSyncResult,
    load_mitre_attack_data,
    run_scheduled_mitre_attack_sync,
)
from apps.mitre.management.commands.load_d3fend import (
    Command as LoadD3FendCommand,
    build_d3fend_catalog_url,
)
from apps.mitre.models import (
    CoverageOverride,
    D3Fend,
    D3FendAttackRelationOverride,
    MitreAttack,
    MitreAttackSyncSettings,
    MitreAttackTactic,
)
from apps.mitre.translation_catalog import export_translation_catalog, import_translation_catalog


class MitreAttackSyncTests(TestCase):
    def test_translation_catalog_updates_only_spanish_description(self):
        attack = MitreAttack.objects.create(
            external_id="T1114.001",
            name="Local Email Collection",
            description="Official English description.",
        )
        exported = export_translation_catalog()
        translated = exported.replace(
            "Official English description.;",
            "Official English description.;Descripción oficial en castellano.",
        )
        uploaded = SimpleUploadedFile(
            "mitre_descripciones_castellano.csv",
            translated.encode("utf-8-sig"),
            content_type="text/csv",
        )

        result = import_translation_catalog(uploaded)

        attack.refresh_from_db()
        self.assertEqual(result.updated, 1)
        self.assertEqual(attack.description, "Official English description.")
        self.assertEqual(attack.name, "Local Email Collection")
        self.assertEqual(attack.translated_description, "Descripción oficial en castellano.")

    def test_translation_catalog_rejects_changed_headers(self):
        uploaded = SimpleUploadedFile("bad.csv", b"id;descripcion\nT1001;texto", content_type="text/csv")

        with self.assertRaisesMessage(ValueError, "columnas"):
            import_translation_catalog(uploaded)

    def test_attack_family_query_matches_exact_ids_only(self):
        parent = MitreAttack.objects.create(external_id="T1110", name="Brute Force")
        MitreAttack.objects.create(external_id="T1110.001", name="Password Guessing")

        matches = list(MitreAttack.objects.filter(attack_family_query(["T1110"])))

        self.assertEqual(matches, [parent])

    def test_d3fend_matrix_counts_attack_tactic_override_as_covered(self):
        attack = MitreAttack.objects.create(
            external_id="T1001",
            name="Data Obfuscation",
            tactic="Defense Evasion",
        )
        d3fend = D3Fend.objects.create(
            code="D3-TEST",
            name="Test Detection",
            category="Detect",
        )
        d3fend.related_attacks.add(attack)
        CoverageOverride.objects.create(
            framework=CoverageOverride.FRAMEWORK_ATTACK,
            object_type=CoverageOverride.OBJECT_TACTIC,
            object_key="Defense Evasion",
            object_name="Defense Evasion",
            status=CoverageOverride.STATUS_FULFILLED,
            reason="Cubierta por herramienta",
        )

        context = build_d3fend_matrix_context(RequestFactory().get("/mitre/d3fend/"))

        self.assertEqual(context["total_relations"], 1)
        self.assertEqual(context["total_covered_relations"], 1)
        self.assertEqual(context["overall_coverage_percent"], 100.0)
        self.assertEqual(context["overall_technique_coverage_percent"], 100.0)
        self.assertEqual(context["rows"][0]["covered_attacks"], 1)

    def test_d3fend_mapping_skips_non_detect_candidates_by_default(self):
        row = {
            "def_tech_label": "Network Isolation",
            "def_tech": "https://d3fend.mitre.org/dao/artifact/d3fend.owl#D3-NI",
            "def_tactic_label": "Harden",
        }

        d3fends, created_count, resolved_count, skipped_not_detect = (
            LoadD3FendCommand()._resolve_or_create_d3fends_from_mapping_row(row, {})
        )

        self.assertEqual(d3fends, [])
        self.assertEqual(created_count, 0)
        self.assertEqual(resolved_count, 0)
        self.assertGreater(skipped_not_detect, 0)
        self.assertFalse(D3Fend.objects.filter(code__iexact="D3-NI").exists())

    def test_d3fend_catalog_extracts_official_level_columns(self):
        row = {
            "ID": "D3-ANET",
            "D3FEND Tactic": "Detect",
            "D3FEND Technique": "",
            "D3FEND Technique Level 0": "Authentication Event Thresholding",
            "D3FEND Technique Level 1": "",
            "Definition": "Collecting authentication events and building a baseline.",
        }
        command = LoadD3FendCommand()

        self.assertEqual(command._extract_official_code(row), "D3-ANET")
        self.assertEqual(command._extract_name(row), "Authentication Event Thresholding")
        self.assertEqual(command._extract_category(row), "Detect")
        self.assertEqual(command._extract_description(row), "Collecting authentication events and building a baseline.")

    def test_d3fend_catalog_url_resolves_latest_version(self):
        with patch(
            "apps.mitre.management.commands.load_d3fend.resolve_latest_d3fend_version",
            return_value="1.5.0",
        ):
            url, version = build_d3fend_catalog_url(catalog_version="latest")

        self.assertEqual(version, "1.5.0")
        self.assertEqual(url, "https://d3fend.mitre.org/ontologies/d3fend/1.5.0/d3fend.csv")

    def test_d3fend_mapping_respects_relation_override_exclusion(self):
        attack = MitreAttack.objects.create(external_id="T1001", name="Data Obfuscation")
        d3fend = D3Fend.objects.create(code="D3-TEST", name="Test Detection", category="Detect")
        D3FendAttackRelationOverride.objects.create(
            d3fend=d3fend,
            attack=attack,
            reason="No aplica al modelo local",
        )

        class Response:
            text = (
                "off_tech_id,off_tech_label,def_tech_label,def_tech,def_tactic_label\n"
                "T1001,Data Obfuscation,Test Detection,D3-TEST,Detect\n"
            )

            def raise_for_status(self):
                return None

        with patch("apps.mitre.management.commands.load_d3fend.requests.get", return_value=Response()):
            LoadD3FendCommand()._load_attack_mappings()

        self.assertFalse(d3fend.related_attacks.filter(pk=attack.pk).exists())

    def test_inferred_d3fends_endpoint_uses_selected_attack_ids(self):
        User = get_user_model()
        user = User.objects.create_superuser("admin", "admin@example.test", "pass")
        parent = MitreAttack.objects.create(external_id="T1110", name="Brute Force")
        subtechnique = MitreAttack.objects.create(external_id="T1110.003", name="Password Spraying")
        d3fend = D3Fend.objects.create(code="D3-ANAA", name="Administrative Network Activity Analysis", category="Detect")
        d3fend.related_attacks.add(subtechnique)
        self.client.force_login(user)

        parent_response = self.client.get(reverse("infer_d3fends_for_attacks"), {"attack_ids": [parent.pk]})
        subtechnique_response = self.client.get(reverse("infer_d3fends_for_attacks"), {"attack_ids": [subtechnique.pk]})

        self.assertEqual(parent_response.json()["results"], [])
        self.assertEqual(subtechnique_response.json()["results"][0]["code"], "D3-ANAA")

    def test_mitre_subtechniques_endpoint_returns_children_for_parent(self):
        User = get_user_model()
        user = User.objects.create_superuser("admin", "admin@example.test", "pass")
        parent = MitreAttack.objects.create(external_id="T1110", name="Brute Force")
        MitreAttack.objects.create(external_id="T1110.001", name="Password Guessing")
        MitreAttack.objects.create(external_id="T1110.003", name="Password Spraying")
        MitreAttack.objects.create(external_id="T1111", name="Unrelated")
        self.client.force_login(user)

        response = self.client.get(reverse("mitre_attack_subtechniques"), {"attack_ids": [parent.pk]})
        labels = [item["external_id"] for item in response.json()["results"]]

        self.assertEqual(labels, ["T1110.001", "T1110.003"])

    def test_d3fend_mapping_resolves_subtechnique_to_parent_when_subtechnique_is_missing(self):
        parent = MitreAttack.objects.create(external_id="T1110", name="Brute Force")
        attack_lookup = {"T1110": parent}
        row = {"off_tech_id": "T1110.003", "off_tech_label": "Password Spraying"}

        resolved = LoadD3FendCommand()._resolve_attack_from_mapping_row(row, attack_lookup)

        self.assertEqual(resolved, parent)

    def test_load_mitre_attack_data_creates_and_updates_catalog(self):
        MitreAttack.objects.create(external_id="T1059", name="Old name", tactic="Execution")
        data = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Command and Scripting Interpreter",
                    "description": "Adversaries may abuse command interpreters.",
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
        self.assertEqual(MitreAttack.objects.get(external_id="T1059").description, "Adversaries may abuse command interpreters.")
        self.assertEqual(MitreAttack.objects.get(external_id="T1078").tactic, "Defense Evasion")

    def test_load_mitre_attack_data_stores_tactic_context(self):
        from apps.mitre.models import MitreAttackTactic

        data = {
            "objects": [
                {
                    "type": "x-mitre-tactic",
                    "name": "Execution",
                    "description": "The adversary is trying to run malicious code.",
                    "x_mitre_shortname": "execution",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
                },
                {
                    "type": "attack-pattern",
                    "name": "Command and Scripting Interpreter",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                },
            ]
        }

        load_mitre_attack_data(data)

        tactic = MitreAttackTactic.objects.get(external_id="TA0002")
        self.assertEqual(tactic.name, "Execution")
        self.assertIn("malicious code", tactic.description)

    def test_load_mitre_attack_data_disables_revoked_catalog_entries(self):
        revoked = MitreAttack.objects.create(external_id="T1562", name="Impair Defenses", is_enabled=True)
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
                    "name": "Impair Defenses",
                    "revoked": True,
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1562"}],
                },
            ]
        }

        result = load_mitre_attack_data(data)

        revoked.refresh_from_db()
        self.assertFalse(revoked.is_enabled)
        self.assertIn("revocada o deprecada", revoked.disabled_reason)
        self.assertEqual(result.skipped, 1)

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
                (
                    "load_d3fend",
                    "--all",
                    "--disable-non-detect",
                    "--base-url",
                    "https://d3fend.mitre.org/ontologies/d3fend/",
                    "--d3fend-version",
                    "latest",
                ),
                ("normalize_d3fend_codes",),
                (
                    "load_d3fend",
                    "--mappings-only",
                    "--all",
                    "--disable-non-detect",
                    "--base-url",
                    "https://d3fend.mitre.org/ontologies/d3fend/",
                    "--d3fend-version",
                    "latest",
                ),
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
