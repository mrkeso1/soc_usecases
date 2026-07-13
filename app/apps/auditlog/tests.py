from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from apps.usecases.models import UseCase, UseCaseChangeLog

from .models import AuditLog
from .middleware import _safe_post_keys
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
