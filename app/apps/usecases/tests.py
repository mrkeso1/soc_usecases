from datetime import date

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from .models import D3Fend, LifecycleSettings, MitreAttack, UseCase


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
