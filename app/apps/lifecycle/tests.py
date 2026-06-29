from datetime import date
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.lifecycle.lifecycle import lifecycle_completion_errors, lifecycle_state, mark_lifecycle_review_done, period_key
from apps.lifecycle.models import (
    DetectionMetric,
    LifecycleCycle,
    LifecyclePeriod,
    LifecyclePeriodMember,
    LifecycleReview,
    LifecycleTransition,
)
from apps.usecases.models import UseCase
from apps.usecases.snapshots import snapshot_usecase


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

    def test_set_lifecycle_review_dates_uses_configured_period_deadline(self):
        cycle = LifecycleCycle.objects.create(year=2026)
        LifecyclePeriod.objects.create(
            cycle=cycle,
            period=1,
            label="Enero",
            start_date=date(2026, 1, 1),
            end_date=date(2026, 1, 31),
        )
        usecase = UseCase(name="Privileged login alert")

        usecase.set_lifecycle_review_dates(date(2026, 1, 1))

        self.assertEqual(usecase.last_review_date, date(2026, 1, 1))
        self.assertEqual(usecase.next_review_date, date(2026, 1, 31))

    def test_lifecycle_period_members_are_frozen_after_first_open(self):
        first = UseCase.objects.create(name="First production case", status=UseCase.STATUS_PRODUCTION)

        lifecycle_state(2026, today=date(2026, 1, 15))
        UseCase.objects.create(name="Late production case", status=UseCase.STATUS_PRODUCTION)
        lifecycle_state(2026, today=date(2026, 2, 15))

        members = LifecyclePeriodMember.objects.filter(year=2026, period=1)
        self.assertEqual(members.count(), 1)
        self.assertEqual(members.get().use_case, first)

    def test_lifecycle_state_sets_pending_inventory_counter_to_period_end(self):
        cycle = LifecycleCycle.objects.create(year=2026)
        LifecyclePeriod.objects.create(
            cycle=cycle,
            period=1,
            label="Control especial",
            start_date=date(2026, 1, 1),
            end_date=date(2026, 4, 4),
        )
        usecase = UseCase.objects.create(name="Production case", status=UseCase.STATUS_PRODUCTION)

        lifecycle_state(2026, today=date(2026, 2, 1))
        usecase.refresh_from_db()

        self.assertEqual(usecase.next_review_date, date(2026, 4, 4))


class LifecycleDetectionMetricTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="analyst", password="x")
        self.usecase = UseCase.objects.create(
            name="Privileged access detection",
            status=UseCase.STATUS_PRODUCTION,
            validation_status=UseCase.VALIDATION_STATUS_NOT_DONE,
            validation_result=UseCase.VALIDATION_RESULT_NONE,
        )

    def test_lifecycle_review_creates_metric_and_transition(self):
        today = date.today()
        review_type = period_key(today.year, 1)
        post_data = {
            "review_type": review_type,
            "validation_result": LifecycleReview.RESULT_CURRENT,
            "trigger_count": "4",
            "true_incidents": "3",
            "false_positives": "1",
            "logic_valid": "on",
            "sources_active": "on",
            "event_ids_valid": "on",
            "fields_exist": "on",
            "notes": "Validado con evidencia del SIEM.",
        }

        mark_lifecycle_review_done(self.usecase, self.user, post_data, snapshot_usecase)

        review = LifecycleReview.objects.get(use_case=self.usecase, review_type=review_type)
        self.assertEqual(review.trigger_count, 4)
        self.assertEqual(review.true_incidents, 3)
        self.assertEqual(review.false_positives, 1)

        metric = DetectionMetric.objects.get(use_case=self.usecase, period_key=review_type)
        self.assertEqual(metric.review, review)
        self.assertEqual(metric.precision_rate, Decimal("75.0"))
        self.assertEqual(metric.effectiveness_score, Decimal("83.8"))
        self.assertEqual(metric.health_status, DetectionMetric.HEALTH_GOOD)

        transition = LifecycleTransition.objects.get(use_case=self.usecase, review=review)
        self.assertEqual(transition.transition_type, LifecycleTransition.TYPE_REVIEW_COMPLETED)
        self.assertEqual(transition.metadata["metric_id"], metric.pk)

    def test_lifecycle_review_validation_rejects_more_classified_alerts_than_total(self):
        errors = lifecycle_completion_errors(self.usecase, {
            "validation_result": LifecycleReview.RESULT_CURRENT,
            "trigger_count": "2",
            "true_incidents": "2",
            "false_positives": "1",
            "notes": "Evidencia suficiente.",
        })

        self.assertIn(
            "La suma de incidentes reales y falsos positivos no puede superar la cantidad de alertas.",
            errors,
        )
