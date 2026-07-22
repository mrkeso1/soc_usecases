from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from apps.usecases.models import UseCase

from .forms import EventSourceForm, SourceCategoryForm, SourceSubcategoryForm, SourceTypeForm
from .matching import resolve_event_source, sync_usecase_sources
from .models import EventSource, SourceAlias, SourceCategory, SourceDeliveryMethod, SourceType


class SourceTaxonomyTests(TestCase):
    def test_source_list_filters_each_ingestion_field(self):
        admin_group = Group.objects.create(name="Admin")
        user = get_user_model().objects.create_user("source-filter-admin", password="pass")
        user.groups.add(admin_group)
        syslog = SourceDeliveryMethod.objects.create(code="syslog_test", name="Syslog Test")
        EventSource.objects.create(
            name="Fuente coincidente",
            delivery_method=syslog,
            port=6514,
            protocol="TCP/TLS",
            service_account="svc_siem_prod",
            host="logs.internal.example",
        )
        EventSource.objects.create(name="Fuente no coincidente", port=514, protocol="UDP", host="other.example")
        self.client.login(username="source-filter-admin", password="pass")

        response = self.client.get(reverse("source_list"), {
            "delivery_method": syslog.pk,
            "port": "6514",
            "protocol": "TCP/TLS",
            "service_account": "siem",
            "host": "internal",
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual([item.name for item in response.context["sources"].object_list], ["Fuente coincidente"])
        self.assertContains(response, "Método de envío")
        self.assertContains(response, "Cuenta de servicio")
        self.assertContains(response, "Host / endpoint")

        sorted_response = self.client.get(reverse("source_list"), {"sort": "port", "direction": "desc"})
        sorted_names = [item.name for item in sorted_response.context["sources"].object_list]
        self.assertEqual(sorted_names[:2], ["Fuente coincidente", "Fuente no coincidente"])
        self.assertContains(sorted_response, "direction=asc")

    def test_event_source_form_uses_managed_taxonomy(self):
        category, _ = SourceCategory.objects.get_or_create(name="Endpoint", parent=None)
        subcategory, _ = SourceCategory.objects.get_or_create(name="EDR", parent=category)

        form = EventSourceForm(data={
            "code": "EDR01",
            "name": "Primary EDR",
            "protection": EventSource.PROTECTION_INTERNAL,
            "source_type": EventSource.TYPE_EDR,
            "category_ref": category.pk,
            "subcategory_ref": subcategory.pk,
            "status": EventSource.STATUS_ACTIVE,
        })

        self.assertTrue(form.is_valid(), form.errors)
        source = form.save()
        self.assertEqual(source.taxonomy_label, "Endpoint / EDR")
        self.assertEqual(source.source_type_label, "EDR")

    def test_event_source_form_accepts_custom_managed_type(self):
        category, _ = SourceCategory.objects.get_or_create(name="Analitica", parent=None)
        SourceType.objects.create(code="ueba", name="UEBA")

        form = EventSourceForm(data={
            "code": "UEBA01",
            "name": "Behavior analytics",
            "protection": EventSource.PROTECTION_INTERNAL,
            "source_type": "ueba",
            "category_ref": category.pk,
            "status": EventSource.STATUS_ACTIVE,
        })

        self.assertTrue(form.is_valid(), form.errors)
        source = form.save()
        self.assertEqual(source.source_type, "ueba")
        self.assertEqual(source.source_type_label, "UEBA")

    def test_source_type_form_normalizes_code(self):
        form = SourceTypeForm(data={
            "code": "Cloud Native",
            "name": "Cloud Native",
            "description": "",
            "is_active": "on",
        })

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["code"], "cloud_native")

    def test_category_form_does_not_ask_for_parent(self):
        form = SourceCategoryForm()

        self.assertNotIn("parent", form.fields)

    def test_subcategory_form_requires_parent_category(self):
        category = SourceCategory.objects.create(name="Sistemas operativos")

        form = SourceSubcategoryForm(data={
            "name": "Linux / Unix",
            "parent": category.pk,
            "description": "",
            "is_active": "on",
        })

        self.assertTrue(form.is_valid(), form.errors)
        item = form.save()
        self.assertEqual(item.parent, category)

    def test_admin_role_can_manage_source_catalogs(self):
        User = get_user_model()
        admin_group = Group.objects.create(name="Admin")
        user = User.objects.create_user("source-admin", password="pass")
        user.groups.add(admin_group)
        self.client.login(username="source-admin", password="pass")

        list_response = self.client.get(reverse("source_admin_catalog"))
        create_response = self.client.post(reverse("source_type_create"), {
            "code": "Cloud Native",
            "name": "Cloud Native",
            "description": "Fuentes cloud administradas.",
            "is_active": "on",
        })

        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(create_response.status_code, 302)
        self.assertTrue(SourceType.objects.filter(code="cloud_native", name="Cloud Native").exists())

    def test_admin_role_can_create_subcategory_from_catalog_flow(self):
        User = get_user_model()
        admin_group = Group.objects.create(name="Admin")
        user = User.objects.create_user("source-admin", password="pass")
        user.groups.add(admin_group)
        category, _ = SourceCategory.objects.get_or_create(name="Aplicacion", parent=None)
        self.client.login(username="source-admin", password="pass")

        response = self.client.post(reverse("source_subcategory_create"), {
            "name": "Subcategoria Test Catalogo",
            "parent": category.pk,
            "description": "",
            "is_active": "on",
        })

        self.assertEqual(response.status_code, 302)
        self.assertTrue(SourceCategory.objects.filter(name="Subcategoria Test Catalogo", parent=category).exists())

    def test_source_catalog_paginates_source_types(self):
        User = get_user_model()
        admin_group = Group.objects.create(name="Admin")
        user = User.objects.create_user("source-admin", password="pass")
        user.groups.add(admin_group)
        self.client.login(username="source-admin", password="pass")
        for index in range(25):
            SourceType.objects.create(code=f"type_{index:02d}", name=f"Tipo {index:02d}")
        expected_total = SourceType.objects.count()
        expected_pages = (expected_total + 19) // 20

        first_page = self.client.get(reverse("source_admin_catalog"))
        second_page = self.client.get(reverse("source_admin_catalog"), {"types_page": 2})

        self.assertEqual(first_page.status_code, 200)
        self.assertEqual(len(first_page.context["source_types"]), 20)
        self.assertEqual(first_page.context["source_type_count"], expected_total)
        self.assertContains(first_page, f"Página 1 de {expected_pages}")
        self.assertEqual(len(second_page.context["source_types"]), min(20, expected_total - 20))

    def test_source_rejects_subcategory_from_another_category(self):
        category, _ = SourceCategory.objects.get_or_create(name="Endpoint", parent=None)
        other, _ = SourceCategory.objects.get_or_create(name="Cloud", parent=None)
        subcategory, _ = SourceCategory.objects.get_or_create(name="Identity", parent=other)
        source = EventSource(
            name="Bad source",
            source_type=EventSource.TYPE_CLOUD,
            category_ref=category,
            subcategory_ref=subcategory,
        )

        with self.assertRaises(ValidationError):
            source.full_clean()

    def test_source_matching_resolves_alias(self):
        source = EventSource.objects.create(name="Juniper Netscreen", source_type=EventSource.TYPE_FIREWALL)
        SourceAlias.objects.create(source=source, alias="netscreen")

        resolved, created = resolve_event_source("netscreen")

        self.assertFalse(created)
        self.assertEqual(resolved, source)

    def test_sync_usecase_sources_creates_missing_source(self):
        usecase = UseCase.objects.create(name="Case with legacy device", device="pbps")

        result = sync_usecase_sources(usecase, usecase.device, create_missing=True)

        self.assertEqual(result["linked"], 1)
        self.assertEqual(result["created"], 1)
        self.assertEqual(usecase.source_links.first().source.name, "pbps")
