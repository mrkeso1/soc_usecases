from datetime import date

from django.core.exceptions import ValidationError
from django.test import TestCase

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
