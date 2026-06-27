from datetime import date
from io import BytesIO, StringIO

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from openpyxl import Workbook, load_workbook

from apps.lifecycle.models import LifecycleReview, LifecycleSettings
from apps.mitre.coverage_admin import build_coverage_admin_context
from apps.mitre.models import CoverageOverride, D3Fend, MitreAttack
from apps.sources.models import EventSource, UseCaseSource

from .models import UseCase, UseCaseChangeLog, UseCaseRuleCondition


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

    def test_analyst_can_export_usecases_xlsx(self):
        self.client.login(username="analyst", password="pass")

        response = self.client.get(reverse("export_usecases_xlsx"))
        workbook = load_workbook(BytesIO(response.content))
        sheet = workbook.active

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.assertEqual(sheet["F1"].value, "NOMBRE NETWITNESS")
        self.assertIn("Owned use case", [cell.value for cell in sheet["F"]])

    def test_analyst_can_download_import_template(self):
        self.client.login(username="analyst", password="pass")

        response = self.client.get(reverse("download_usecase_import_template"))
        workbook = load_workbook(BytesIO(response.content))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(workbook.active["F1"].value, "NOMBRE NETWITNESS")

    def test_analyst_can_import_usecases_excel(self):
        workbook = Workbook()
        sheet = workbook.active
        sheet.append([
            "GRUPO",
            "DISPOSITIVO",
            "TIPO",
            "OBJETIVO2",
            "Tipo_bloqueo",
            "NOMBRE NETWITNESS",
            "RESPONSABLE",
            "Monitoreo",
            "status2",
            "Fecha alta/ajuste",
            "Fecha puesta en producción",
            "MITRE ATT&CK",
            "Severidad",
            "Escalamiento",
            "ENVIO.HO",
            "HO",
            "FUENTES",
            "Fecha última validación",
        ])
        sheet.append([
            "SOC",
            "SIEM",
            "Correlation",
            "Detect test import",
            "Manual",
            "Imported Excel use case",
            "analyst",
            "24x7",
            UseCase.STATUS_PRODUCTION,
            date(2026, 1, 1),
            date(2026, 1, 2),
            "T1059 - Command and Scripting Interpreter",
            "High",
            "SOC",
            "No",
            "No",
            "SRC-EDR - Endpoint EDR; CloudTrail",
            date(2026, 1, 3),
        ])
        buffer = BytesIO()
        workbook.save(buffer)
        upload = SimpleUploadedFile(
            "usecases.xlsx",
            buffer.getvalue(),
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.client.login(username="analyst", password="pass")

        response = self.client.post(reverse("import_usecases_excel"), {"excel_file": upload})

        self.assertEqual(response.status_code, 302)
        imported = UseCase.objects.get(name="Imported Excel use case")
        self.assertEqual(imported.status, UseCase.STATUS_PRODUCTION)
        self.assertEqual(imported.device, "SIEM")
        self.assertEqual(list(imported.mitre_attacks.values_list("external_id", flat=True)), ["T1059"])
        self.assertTrue(EventSource.objects.filter(code="SRC-EDR", name="Endpoint EDR").exists())
        self.assertTrue(EventSource.objects.filter(name="CloudTrail").exists())
        self.assertEqual(
            set(imported.source_links.values_list("source__name", flat=True)),
            {"Endpoint EDR", "CloudTrail"},
        )

    def test_import_without_fuentes_does_not_treat_device_as_event_source(self):
        workbook = Workbook()
        sheet = workbook.active
        sheet.append([
            "GRUPO",
            "DISPOSITIVO",
            "TIPO",
            "OBJETIVO2",
            "Tipo_bloqueo",
            "NOMBRE NETWITNESS",
            "RESPONSABLE",
            "Monitoreo",
            "status2",
            "Fecha alta/ajuste",
            "Fecha puesta en producción",
            "MITRE ATT&CK",
            "Severidad",
            "Escalamiento",
            "ENVIO.HO",
            "HO",
            "Fecha última validación",
        ])
        sheet.append([
            "SOC",
            "Legacy FW",
            "Correlation",
            "Detect test import without source",
            "Manual",
            "Imported without source",
            "analyst",
            "24x7",
            UseCase.STATUS_PRODUCTION,
            date(2026, 1, 1),
            date(2026, 1, 2),
            "T1059 - Command and Scripting Interpreter",
            "High",
            "SOC",
            "No",
            "No",
            date(2026, 1, 3),
        ])
        buffer = BytesIO()
        workbook.save(buffer)
        upload = SimpleUploadedFile(
            "usecases.xlsx",
            buffer.getvalue(),
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.client.login(username="analyst", password="pass")

        response = self.client.post(reverse("import_usecases_excel"), {"excel_file": upload})

        self.assertEqual(response.status_code, 302)
        imported = UseCase.objects.get(name="Imported without source")
        self.assertEqual(imported.device, "Legacy FW")
        self.assertFalse(imported.source_links.exists())
        self.assertFalse(EventSource.objects.filter(name="Legacy FW").exists())

    def test_import_rejects_macro_enabled_workbook_extension(self):
        upload = SimpleUploadedFile(
            "usecases.xlsm",
            b"not-a-real-workbook",
            content_type="application/vnd.ms-excel.sheet.macroEnabled.12",
        )
        self.client.login(username="analyst", password="pass")

        response = self.client.post(reverse("import_usecases_excel"), {"excel_file": upload})

        self.assertEqual(response.status_code, 302)
        self.assertFalse(UseCase.objects.filter(name="usecases.xlsm").exists())

    def test_readonly_cannot_import_or_export_xlsx(self):
        self.client.login(username="readonly", password="pass")

        xlsx_response = self.client.get(reverse("export_usecases_xlsx"))
        template_response = self.client.get(reverse("download_usecase_import_template"))
        import_response = self.client.get(reverse("import_usecases_excel"))

        self.assertEqual(xlsx_response.status_code, 403)
        self.assertEqual(template_response.status_code, 403)
        self.assertEqual(import_response.status_code, 403)

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

    def test_analyst_can_save_rule_conditions_and_full_rule(self):
        self.client.login(username="analyst", password="pass")

        response = self.client.post(reverse("usecase_edit", args=[self.owned_usecase.pk]), {
            "group_name": self.owned_usecase.group_name,
            "device": self.owned_usecase.device,
            "case_type": self.owned_usecase.case_type,
            "objective": "Detect privileged group changes.",
            "blocking_type": "",
            "name": self.owned_usecase.name,
            "owner_name": self.owned_usecase.owner_name,
            "monitoring": self.owned_usecase.monitoring,
            "status": self.owned_usecase.status,
            "created_or_adjusted_at": "",
            "production_date": "2026-01-01",
            "mitre_attacks": [str(self.attack.pk)],
            "severity": self.owned_usecase.severity,
            "escalation": "",
            "sent_to_ho": "",
            "ho_flag": "",
            "last_validation_date": "",
            "validation_status": self.owned_usecase.validation_status,
            "validation_result": self.owned_usecase.validation_result,
            "is_enabled": "on",
            "disabled_reason": "",
            "comments": "Reviewable logic.",
            "full_rule_text": "SELECT * FROM Event WHERE source = 'Active Directory';",
            "functional_description": "Controla altas de usuarios privilegiados.",
            "event_sources": [],
            "conditions-TOTAL_FORMS": "2",
            "conditions-INITIAL_FORMS": "0",
            "conditions-MIN_NUM_FORMS": "0",
            "conditions-MAX_NUM_FORMS": "1000",
            "conditions-0-position": "1",
            "conditions-0-condition_type": UseCaseRuleCondition.TYPE_INCLUDE,
            "conditions-0-field_name": "source",
            "conditions-0-operator": UseCaseRuleCondition.OP_EQUALS,
            "conditions-0-value": "Active Directory",
            "conditions-0-use_case": str(self.owned_usecase.pk),
            "conditions-1-position": "2",
            "conditions-1-condition_type": UseCaseRuleCondition.TYPE_EXCLUDE,
            "conditions-1-field_name": "environment",
            "conditions-1-operator": UseCaseRuleCondition.OP_EQUALS,
            "conditions-1-value": "laboratorio",
            "conditions-1-use_case": str(self.owned_usecase.pk),
        })

        self.assertEqual(response.status_code, 302)
        self.owned_usecase.refresh_from_db()
        self.assertEqual(self.owned_usecase.rule_conditions.count(), 2)
        self.assertEqual(self.owned_usecase.full_rule_text, "SELECT * FROM Event WHERE source = 'Active Directory';")
        self.assertTrue(
            UseCaseChangeLog.objects.filter(
                use_case=self.owned_usecase,
                field_name="rule_conditions",
                new_value__icontains="Active Directory",
            ).exists()
        )

        detail_response = self.client.get(reverse("usecase_detail", args=[self.owned_usecase.pk]))
        self.assertContains(detail_response, "Regla y condiciones")
        self.assertContains(detail_response, "Active Directory")
        self.assertContains(detail_response, "laboratorio")
        self.assertContains(detail_response, "Controla altas de usuarios privilegiados.")

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
        source = EventSource.objects.create(name="EDR", source_type=EventSource.TYPE_EDR)
        UseCaseSource.objects.create(use_case=self.owned_usecase, source=source)
        self.client.login(username="analyst", password="pass")

        response = self.client.post(reverse("lifecycle_mark_done", args=[self.owned_usecase.pk]), {
            "validation_result": LifecycleReview.RESULT_CURRENT,
            "logic_valid": "on",
            "sources_active": "on",
            "event_ids_valid": "on",
            "fields_exist": "on",
            "trigger_count": "0",
            "notes": "Control funcional verificado.",
        })

        self.assertEqual(response.status_code, 302)
        self.owned_usecase.refresh_from_db()
        self.assertEqual(self.owned_usecase.validation_status, UseCase.VALIDATION_STATUS_FINISHED)
        self.assertEqual(self.owned_usecase.validation_result, UseCase.VALIDATION_RESULT_OK)
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



