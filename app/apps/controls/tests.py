from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from apps.auditlog.models import AuditLog
from apps.sources.models import EventSource
from apps.usecases.models import UseCase

from .forms import ControlForm
from .models import Control, ControlInventoryChange, ControlVersion


class ControlPermissionTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin_group = Group.objects.create(name="Admin")
        self.analyst_group = Group.objects.create(name="Analyst")
        self.readonly_group = Group.objects.create(name="ReadOnly")
        self.admin = User.objects.create_user("admin", password="pass")
        self.admin.groups.add(self.admin_group)
        self.analyst = User.objects.create_user("analyst", password="pass")
        self.analyst.groups.add(self.analyst_group)
        self.readonly = User.objects.create_user("readonly", password="pass")
        self.readonly.groups.add(self.readonly_group)
        self.source = EventSource.objects.create(name="EDR", source_type=EventSource.TYPE_EDR)
        self.control = Control.objects.create(
            name="Endpoint telemetry control",
            source=self.source,
            status=Control.STATUS_PRODUCTION,
        )

    def test_analyst_can_view_controls(self):
        self.client.login(username="analyst", password="pass")

        response = self.client.get(reverse("control_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Endpoint telemetry control")
        self.assertContains(response, 'data-ui="bootstrap"')
        self.assertContains(response, "vendor/bootstrap/5.3.8/bootstrap.min.css")

    def test_readonly_cannot_view_controls(self):
        self.client.login(username="readonly", password="pass")

        response = self.client.get(reverse("control_list"))

        self.assertEqual(response.status_code, 403)

    def test_analyst_can_create_control_and_records_audit_and_version(self):
        usecase = UseCase.objects.create(name="PowerShell use case")
        self.client.login(username="analyst", password="pass")

        response = self.client.post(reverse("control_create"), {
            "classification": Control.CLASS_INTERNAL,
            "source": self.source.pk,
            "use_cases": [usecase.pk],
            "name": "PowerShell logging control",
            "status": Control.STATUS_PRODUCTION,
            "objective": "Ensure command visibility",
            "description": "Collect process telemetry",
            "mitigated_risk": "Execution blind spot",
            "evidence": "Dashboard",
            "owner": "SOC",
            "review_frequency_days": 90,
            "control_conditions_text": '[{"field":"event.type","operator":"equals","value":"process"}]',
        })

        self.assertEqual(response.status_code, 302)
        control = Control.objects.get(name="PowerShell logging control")
        self.assertEqual(control.created_by, self.analyst)
        self.assertEqual(control.control_conditions[0]["field"], "event.type")
        self.assertTrue(control.use_cases.filter(pk=usecase.pk).exists())
        self.assertTrue(ControlInventoryChange.objects.filter(control=control, action=ControlInventoryChange.ACTION_CREATED).exists())
        self.assertTrue(ControlVersion.objects.filter(control=control, version=control.version).exists())
        self.assertTrue(AuditLog.objects.filter(action="control_created", entity_id=str(control.pk)).exists())

    def test_admin_can_delete_control_and_records_inventory_change(self):
        self.client.login(username="admin", password="pass")

        response = self.client.post(reverse("control_delete", args=[self.control.pk]))

        self.assertRedirects(response, reverse("control_list"))
        self.assertFalse(Control.objects.filter(pk=self.control.pk).exists())
        self.assertTrue(ControlInventoryChange.objects.filter(
            action=ControlInventoryChange.ACTION_DELETED,
            control_code=self.control.code,
        ).exists())


class ControlFormTests(TestCase):
    def setUp(self):
        self.source = EventSource.objects.create(name="SIEM", source_type=EventSource.TYPE_SIEM)

    def test_control_conditions_must_be_json_list(self):
        form = ControlForm(data={
            "classification": Control.CLASS_INTERNAL,
            "source": self.source.pk,
            "name": "Bad JSON control",
            "status": Control.STATUS_DRAFT,
            "review_frequency_days": 90,
            "control_conditions_text": '{"field":"event.type"}',
        })

        self.assertFalse(form.is_valid())
        self.assertIn("control_conditions_text", form.errors)

    def test_control_widgets_use_bootstrap_classes(self):
        form = ControlForm()

        self.assertIn("form-select", form.fields["classification"].widget.attrs["class"])
        self.assertIn("form-control", form.fields["name"].widget.attrs["class"])
        self.assertIn("form-check-input", form.fields["use_cases"].widget.attrs["class"])
