from django.test import SimpleTestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from .admin import LDAPSettingsAdminForm
from .ldap_utils import escape_ldap_dn_value, escape_ldap_filter_value, safe_ldap_error_message
from .models import LDAPSettings


class LDAPUtilsTests(SimpleTestCase):
    def test_escape_ldap_filter_value_escapes_special_chars(self):
        self.assertEqual(
            escape_ldap_filter_value("user*)(|(uid=*))"),
            "user\\2a\\29\\28|\\28uid=\\2a\\29\\29",
        )

    def test_escape_ldap_dn_value_escapes_dn_separators(self):
        self.assertEqual(escape_ldap_dn_value("Doe, John"), "Doe\\, John")

    def test_safe_ldap_error_message_redacts_sensitive_errors(self):
        message = safe_ldap_error_message(Exception("bind password=secret failed"), "LDAP error")

        self.assertEqual(message, "LDAP error")


class LDAPSettingsValidationTests(TestCase):
    def test_server_uri_must_be_ldap_or_ldaps(self):
        settings = LDAPSettings(
            name="Invalid URI",
            server_uri="https://ldap.example.test",
            auth_mode=LDAPSettings.AUTH_MODE_LOCAL_ONLY,
        )

        with self.assertRaises(ValidationError) as ctx:
            settings.full_clean()

        self.assertIn("server_uri", ctx.exception.message_dict)

    def test_search_mode_requires_username_placeholder_and_bind_fields(self):
        settings = LDAPSettings(
            name="Search mode",
            server_uri="ldap://ldap.example.test:389",
            auth_mode=LDAPSettings.AUTH_MODE_LDAP_WITH_FALLBACK,
            user_search_filter="(mail=test@example.test)",
        )

        with self.assertRaises(ValidationError) as ctx:
            settings.full_clean()

        self.assertIn("user_search_filter", ctx.exception.message_dict)
        self.assertIn("bind_dn", ctx.exception.message_dict)
        self.assertIn("bind_password", ctx.exception.message_dict)
        self.assertIn("user_search_base", ctx.exception.message_dict)

    def test_user_dn_template_satisfies_username_requirement(self):
        settings = LDAPSettings(
            name="DN template",
            server_uri="ldaps://ldap.example.test:636",
            use_ssl=True,
            auth_mode=LDAPSettings.AUTH_MODE_LDAP_ONLY,
            user_dn_template="uid={username},ou=users,dc=example,dc=test",
        )

        settings.full_clean()

    def test_only_one_enabled_ldap_config_is_allowed(self):
        LDAPSettings.objects.create(
            name="Active",
            is_enabled=True,
            server_uri="ldap://ldap.example.test:389",
            auth_mode=LDAPSettings.AUTH_MODE_LOCAL_ONLY,
        )
        settings = LDAPSettings(
            name="Second active",
            is_enabled=True,
            server_uri="ldap://ldap2.example.test:389",
            auth_mode=LDAPSettings.AUTH_MODE_LOCAL_ONLY,
        )

        with self.assertRaises(ValidationError) as ctx:
            settings.full_clean()

        self.assertIn("is_enabled", ctx.exception.message_dict)


class LDAPSettingsAdminTests(TestCase):
    def test_admin_form_keeps_existing_masked_password(self):
        settings = LDAPSettings.objects.create(
            name="LDAP",
            server_uri="ldap://ldap.example.test:389",
            auth_mode=LDAPSettings.AUTH_MODE_LOCAL_ONLY,
            bind_password="secret-value",
        )
        form = LDAPSettingsAdminForm(
            data={
                "name": settings.name,
                "server_uri": settings.server_uri,
                "auth_mode": settings.auth_mode,
                "bind_password": "********",
                "user_search_filter": settings.user_search_filter,
                "first_name_attr": settings.first_name_attr,
                "last_name_attr": settings.last_name_attr,
                "email_attr": settings.email_attr,
                "display_name_attr": settings.display_name_attr,
            },
            instance=settings,
        )

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["bind_password"], "secret-value")

    def test_activate_admin_action_disables_previous_config(self):
        User = get_user_model()
        admin_user = User.objects.create_superuser("admin", "admin@example.test", "pass")
        active = LDAPSettings.objects.create(
            name="Active",
            is_enabled=True,
            server_uri="ldap://ldap.example.test:389",
            auth_mode=LDAPSettings.AUTH_MODE_LOCAL_ONLY,
        )
        target = LDAPSettings.objects.create(
            name="Target",
            is_enabled=False,
            server_uri="ldap://ldap2.example.test:389",
            auth_mode=LDAPSettings.AUTH_MODE_LOCAL_ONLY,
        )
        self.client.force_login(admin_user)

        response = self.client.get(reverse("admin:accounts_ldapsettings_activate", args=[target.pk]))

        self.assertEqual(response.status_code, 302)
        active.refresh_from_db()
        target.refresh_from_db()
        self.assertFalse(active.is_enabled)
        self.assertTrue(target.is_enabled)
