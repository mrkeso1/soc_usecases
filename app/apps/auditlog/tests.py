from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.usecases.models import UseCase, UseCaseChangeLog

from .alerts import emit_operational_alert, resolve_operational_alert
from .models import ActionRateLimit, AuditLog, OperationalAlert
from .middleware import _safe_post_keys
from .rate_limits import consume_action_rate_limit
from .service import client_ip
from .timeline import build_audit_timeline_context


class AuditClientIpTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @override_settings(USE_X_FORWARDED_FOR=False)
    def test_client_ip_uses_remote_addr_by_default(self):
        request = self.factory.get(
            "/",
            REMOTE_ADDR="10.0.0.10",
            HTTP_X_FORWARDED_FOR="203.0.113.8, 10.0.0.1",
        )

        self.assertEqual(client_ip(request), "10.0.0.10")

    @override_settings(USE_X_FORWARDED_FOR=True)
    def test_client_ip_uses_forwarded_for_when_enabled(self):
        request = self.factory.get(
            "/",
            REMOTE_ADDR="10.0.0.10",
            HTTP_X_FORWARDED_FOR="203.0.113.8, 10.0.0.1",
        )

        self.assertEqual(client_ip(request), "203.0.113.8")

    def test_safe_post_keys_excludes_sensitive_fields(self):
        request = self.factory.post("/", {
            "name": "Role",
            "password": "secret",
            "csrfmiddlewaretoken": "token",
            "api_secret": "hidden",
        })

        self.assertEqual(_safe_post_keys(request), ["name"])

    def test_request_context_adds_request_id_header(self):
        response = self.client.get("/login/", HTTP_X_REQUEST_ID="trace-123")

        self.assertEqual(response["X-Request-ID"], "trace-123")


class OperationalAlertTests(TestCase):
    def test_same_fingerprint_is_deduplicated(self):
        first = emit_operational_alert(
            code="inventory_sync_failed",
            fingerprint="inventory_sync_failed:ad",
            title="Falló AD",
            message="Primer error",
        )
        second = emit_operational_alert(
            code="inventory_sync_failed",
            fingerprint="inventory_sync_failed:ad",
            title="Falló AD",
            message="Segundo error",
        )

        self.assertEqual(first.pk, second.pk)
        self.assertEqual(OperationalAlert.objects.count(), 1)
        second.refresh_from_db()
        self.assertEqual(second.occurrences, 2)
        self.assertEqual(second.message, "Segundo error")

    def test_resolved_alert_can_be_created_again(self):
        first = emit_operational_alert(
            code="inventory_sync_failed",
            fingerprint="inventory_sync_failed:siem",
            title="Falló SIEM",
            message="Error",
        )
        self.assertEqual(resolve_operational_alert(first.fingerprint), 1)

        second = emit_operational_alert(
            code="inventory_sync_failed",
            fingerprint="inventory_sync_failed:siem",
            title="Falló SIEM",
            message="Nuevo error",
        )

        self.assertNotEqual(first.pk, second.pk)
        self.assertEqual(OperationalAlert.objects.count(), 2)


class ActionRateLimitTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("rate-limited-user")

    def test_limit_is_shared_in_database_and_blocks_excess(self):
        first = consume_action_rate_limit(
            user=self.user,
            scope="inventory",
            limit=2,
            window_seconds=60,
        )
        second = consume_action_rate_limit(
            user=self.user,
            scope="inventory",
            limit=2,
            window_seconds=60,
        )
        blocked = consume_action_rate_limit(
            user=self.user,
            scope="inventory",
            limit=2,
            window_seconds=60,
        )

        self.assertTrue(first.allowed)
        self.assertTrue(second.allowed)
        self.assertFalse(blocked.allowed)
        self.assertGreater(blocked.retry_after, 0)
        state = ActionRateLimit.objects.get(user=self.user, scope="inventory")
        self.assertEqual(state.request_count, 2)
        self.assertEqual(state.blocked_count, 1)

    def test_expired_window_is_reset(self):
        consume_action_rate_limit(
            user=self.user,
            scope="inventory",
            limit=1,
            window_seconds=60,
        )
        ActionRateLimit.objects.filter(user=self.user, scope="inventory").update(
            window_started_at=timezone.now() - timedelta(minutes=2),
        )

        result = consume_action_rate_limit(
            user=self.user,
            scope="inventory",
            limit=1,
            window_seconds=60,
        )

        self.assertTrue(result.allowed)
        state = ActionRateLimit.objects.get(user=self.user, scope="inventory")
        self.assertEqual(state.request_count, 1)
        self.assertEqual(state.blocked_count, 0)


class AuditPermissionTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user("inventory-auditor", password="pass")
        self.user.user_permissions.add(Permission.objects.get(codename="view_inventory_audit"))
        self.usecase = UseCase.objects.create(name="Audit visible use case")
        self.usecase.case_code = "Audit visible use case"
        self.usecase.save(update_fields=["case_code"])
        self.change = UseCaseChangeLog.objects.create(
            use_case=self.usecase,
            changed_by=self.user,
            field_name="name",
            old_value="Old",
            new_value="New",
        )
        self.security_log = AuditLog.objects.create(
            actor=self.user,
            action="login_failed",
            entity_type="auth",
            entity_id="inventory-auditor",
            ip_address="127.0.0.1",
        )

    def test_area_permission_limits_visible_audit_filters(self):
        self.client.login(username="inventory-auditor", password="pass")

        response = self.client.get(reverse("audit_list"))

        self.assertEqual(response.status_code, 200)
        choices = dict(response.context["area_choices"])
        self.assertIn("inventory", choices)
        self.assertNotIn("security", choices)
        self.assertNotIn("lifecycle", choices)

    def test_area_permission_blocks_direct_security_detail(self):
        self.client.login(username="inventory-auditor", password="pass")

        response = self.client.get(reverse("audit_timeline_detail", args=["audit", self.security_log.pk]))

        self.assertEqual(response.status_code, 403)

    def test_export_requires_explicit_export_permission(self):
        self.client.login(username="inventory-auditor", password="pass")

        response = self.client.get(reverse("audit_export_csv"))

        self.assertEqual(response.status_code, 403)

    def test_export_permission_exports_only_allowed_areas(self):
        self.user.user_permissions.add(Permission.objects.get(codename="export_audit"))
        self.client.login(username="inventory-auditor", password="pass")

        response = self.client.get(reverse("audit_export_csv"))
        content = response.content.decode("utf-8-sig")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Inventario", content)
        self.assertIn("Audit visible use case", content)
        self.assertNotIn("Inicio fallido", content)

    def test_inventory_audit_uses_editable_usecase_identifier(self):
        self.usecase.case_code = "CUSTOM-AUDIT-CODE"
        self.usecase.save(update_fields=["case_code"])

        context = build_audit_timeline_context({"area": "inventory"}, self.user, paginate=False)
        item = next(item for item in context["items"] if item.source == "usecase_change")

        self.assertEqual(item.entity_id, "CUSTOM-AUDIT-CODE")
