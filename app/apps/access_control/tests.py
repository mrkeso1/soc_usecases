from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import TestCase
from django.urls import reverse

class AccessControlPermissionTests(TestCase):
    def test_staff_user_without_admin_role_cannot_manage_access(self):
        User = get_user_model()
        user = User.objects.create_user("staff", password="pass", is_staff=True)
        self.client.login(username="staff", password="pass")

        response = self.client.get(reverse("access_control_home"))

        self.assertEqual(response.status_code, 403)

    def test_admin_role_can_manage_access(self):
        User = get_user_model()
        admin_group = Group.objects.create(name="Admin")
        user = User.objects.create_user("admin-role", password="pass")
        user.groups.add(admin_group)
        self.client.login(username="admin-role", password="pass")

        response = self.client.get(reverse("access_control_home"))

        self.assertEqual(response.status_code, 200)

    def test_admin_role_can_open_admin_console(self):
        User = get_user_model()
        admin_group = Group.objects.create(name="Admin")
        user = User.objects.create_user("admin-console", password="pass")
        user.groups.add(admin_group)
        self.client.login(username="admin-console", password="pass")

        response = self.client.get(reverse("admin_console"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Catálogos de fuentes")
        self.assertContains(response, "Admin cobertura")
        self.assertContains(response, reverse("server_heatmap_administration"))
        self.assertContains(response, 'class="admin-console-link"')
        self.assertNotContains(response, ">Abrir</a>")
        self.assertNotContains(response, reverse("admin:server_heatmap_serverasset_changelist"))

    def test_roles_page_exposes_current_user_roles_for_safe_assignment(self):
        User = get_user_model()
        admin_group = Group.objects.create(name="Admin")
        analyst_group = Group.objects.create(name="Analyst")
        admin = User.objects.create_user("roles-admin", password="pass")
        admin.groups.add(admin_group)
        analyst = User.objects.create_user("assigned-analyst")
        analyst.groups.add(analyst_group)
        self.client.login(username="roles-admin", password="pass")

        response = self.client.get(reverse("access_control_home"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user_role_map"][str(analyst.id)], [analyst_group.id])
        self.assertContains(response, 'id="user-role-map"')
        self.assertContains(response, 'class="table data-table access-role-table')

    def test_editing_role_preserves_permissions_outside_visible_catalog(self):
        User = get_user_model()
        admin_group = Group.objects.create(name="Admin")
        admin = User.objects.create_user("permission-admin", password="pass")
        admin.groups.add(admin_group)
        technical_permission = Permission.objects.get(
            content_type__app_label="auth",
            codename="view_permission",
        )
        admin_group.permissions.add(technical_permission)
        self.client.login(username="permission-admin", password="pass")

        response = self.client.post(
            reverse("access_role_edit", args=[admin_group.id]),
            {"name": "Admin"},
        )

        self.assertRedirects(response, reverse("access_control_home"))
        self.assertTrue(admin_group.permissions.filter(pk=technical_permission.pk).exists())
