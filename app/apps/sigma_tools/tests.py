from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from apps.usecases.models import UseCase, UseCaseRuleCondition

from .models import SigmaConversion, UseCaseTechnicalBackup


class TechnicalBackupTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin_group = Group.objects.create(name="Admin")
        self.user = User.objects.create_user("admin", password="pass")
        self.user.groups.add(self.admin_group)
        self.usecase = UseCase.objects.create(name="Backup test case")

    def _post_inventory_edit(self, rule_text):
        return self.client.post(reverse("usecase_edit", args=[self.usecase.pk]), {
            "name": self.usecase.name,
            "status": UseCase.STATUS_TEST,
            "validation_status": UseCase.VALIDATION_STATUS_NOT_DONE,
            "validation_result": UseCase.VALIDATION_RESULT_NONE,
            "is_enabled": "on",
            "full_rule_text": rule_text,
            "conditions-TOTAL_FORMS": "0",
            "conditions-INITIAL_FORMS": "0",
            "conditions-MIN_NUM_FORMS": "0",
            "conditions-MAX_NUM_FORMS": "1000",
        })

    def test_backup_sets_version_checksum_and_current_flag(self):
        first = UseCaseTechnicalBackup.objects.create(
            use_case=self.usecase,
            logic_text="select * from logs",
            sigma_text="title: Test",
            created_by=self.user,
        )
        second = UseCaseTechnicalBackup.objects.create(
            use_case=self.usecase,
            logic_text="select * from logs where severity = 'high'",
            sigma_text="title: Test v2",
            created_by=self.user,
        )

        first.refresh_from_db()
        self.assertEqual(first.version, 1)
        self.assertEqual(second.version, 2)
        self.assertEqual(len(second.checksum), 64)
        self.assertFalse(first.is_current)
        self.assertTrue(second.is_current)

    def test_sigma_conversion_creates_technical_backup_when_usecase_is_selected(self):
        self.client.login(username="admin", password="pass")

        response = self.client.post(reverse("sigma_epl_to_sigma"), {
            "use_case": self.usecase.pk,
            "input_text": "alert tcp any any -> any any",
            "target": SigmaConversion.TARGET_NETWITNESS,
        })

        self.assertEqual(response.status_code, 200)
        backup = UseCaseTechnicalBackup.objects.get(use_case=self.usecase)
        self.assertIn("alert tcp", backup.logic_text)
        self.assertTrue(backup.sigma_text)

    def test_manual_backup_route_redirects_to_inventory_edit(self):
        self.usecase.full_rule_text = "SELECT * FROM Event WHERE source = 'Active Directory';"
        self.usecase.save()
        self.client.login(username="admin", password="pass")

        response = self.client.get(reverse("technical_backup_create"), {"use_case": self.usecase.pk})

        self.assertRedirects(response, reverse("usecase_edit", args=[self.usecase.pk]))

    def test_inventory_edit_creates_technical_backup_from_rule(self):
        self.client.login(username="admin", password="pass")

        response = self._post_inventory_edit("SELECT * FROM Event WHERE action = 'add';")

        self.assertRedirects(response, reverse("usecase_detail", args=[self.usecase.pk]))
        backup = UseCaseTechnicalBackup.objects.get(use_case=self.usecase)
        self.assertEqual(backup.logic_text, "SELECT * FROM Event WHERE action = 'add';")
        self.assertTrue(backup.is_current)

    def test_inventory_edit_does_not_duplicate_backup_when_rule_is_unchanged(self):
        self.usecase.full_rule_text = "SELECT * FROM Event WHERE action = 'add';"
        self.usecase.save()
        UseCaseTechnicalBackup.objects.create(
            use_case=self.usecase,
            backup_type=UseCaseTechnicalBackup.TYPE_LOGIC,
            logic_text=self.usecase.full_rule_text,
            created_by=self.user,
        )
        self.client.login(username="admin", password="pass")

        response = self._post_inventory_edit(self.usecase.full_rule_text)

        self.assertRedirects(response, reverse("usecase_detail", args=[self.usecase.pk]))
        self.assertEqual(UseCaseTechnicalBackup.objects.filter(use_case=self.usecase).count(), 1)

    def test_backup_can_be_created_directly_from_inventory_rule(self):
        self.usecase.full_rule_text = "SELECT * FROM Event WHERE action = 'add';"
        self.usecase.save()
        self.client.login(username="admin", password="pass")

        response = self.client.post(reverse("technical_backup_from_usecase_rule", args=[self.usecase.pk]))

        self.assertEqual(response.status_code, 302)
        backup = UseCaseTechnicalBackup.objects.get(use_case=self.usecase)
        self.assertEqual(backup.logic_text, "SELECT * FROM Event WHERE action = 'add';")
        self.assertEqual(backup.backup_type, UseCaseTechnicalBackup.TYPE_LOGIC)
        self.assertTrue(backup.is_current)
        self.assertEqual(len(backup.checksum), 64)

    def test_direct_backup_uses_conditions_when_full_rule_is_empty(self):
        UseCaseRuleCondition.objects.create(
            use_case=self.usecase,
            position=1,
            condition_type=UseCaseRuleCondition.TYPE_INCLUDE,
            field_name="source",
            operator=UseCaseRuleCondition.OP_EQUALS,
            value="Active Directory",
        )
        self.client.login(username="admin", password="pass")

        response = self.client.post(reverse("technical_backup_from_usecase_rule", args=[self.usecase.pk]))

        self.assertEqual(response.status_code, 302)
        backup = UseCaseTechnicalBackup.objects.get(use_case=self.usecase)
        self.assertIn("source Es igual a Active Directory", backup.logic_text)

    def test_backup_coverage_page_renders(self):
        self.client.login(username="admin", password="pass")

        response = self.client.get(reverse("technical_backup_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Backups tecnicos")
