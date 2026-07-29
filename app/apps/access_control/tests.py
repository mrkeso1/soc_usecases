from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
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
        self.assertNotContains(response, reverse("admin:server_heatmap_serverasset_changelist"))
