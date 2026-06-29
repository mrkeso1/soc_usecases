from django.conf import settings
from django.db import models

from apps.usecases.models import UseCase


class SourceType(models.Model):
    code = models.SlugField("Código", max_length=40, unique=True)
    name = models.CharField("Nombre", max_length=80, unique=True)
    description = models.TextField("Descripción", blank=True)
    is_active = models.BooleanField("Activo", default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "Tipo de fuente"
        verbose_name_plural = "Tipos de fuentes"

    def __str__(self):
        return self.name


class SourceDeliveryMethod(models.Model):
    code = models.SlugField("Codigo", max_length=40, unique=True)
    name = models.CharField("Nombre", max_length=80, unique=True)
    description = models.TextField("Descripcion", blank=True)
    is_active = models.BooleanField("Activo", default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "Metodo de envio"
        verbose_name_plural = "Metodos de envio"

    def __str__(self):
        return self.name


class EventSource(models.Model):
    STATUS_ACTIVE = "active"
    STATUS_INACTIVE = "inactive"
    STATUS_PLANNED = "planned"
    STATUS_RETIRED = "retired"
    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Activa"),
        (STATUS_INACTIVE, "Inactiva"),
        (STATUS_PLANNED, "Planificada"),
        (STATUS_RETIRED, "Retirada"),
    ]

    PROTECTION_INTERNAL = "internal"
    PROTECTION_EXTERNAL = "external"
    PROTECTION_MIXED = "mixed"
    PROTECTION_THIRD_PARTY = "third_party"
    PROTECTION_CHOICES = [
        (PROTECTION_INTERNAL, "Interna"),
        (PROTECTION_EXTERNAL, "Externa"),
        (PROTECTION_MIXED, "Mixta"),
        (PROTECTION_THIRD_PARTY, "Tercero"),
    ]

    TYPE_SIEM = "siem"
    TYPE_EDR = "edr"
    TYPE_FIREWALL = "firewall"
    TYPE_IDENTITY = "identity"
    TYPE_CLOUD = "cloud"
    TYPE_NETWORK = "network"
    TYPE_APPLICATION = "application"
    TYPE_OTHER = "other"
    TYPE_CHOICES = [
        (TYPE_SIEM, "SIEM"),
        (TYPE_EDR, "EDR"),
        (TYPE_FIREWALL, "Firewall"),
        (TYPE_IDENTITY, "Identidad"),
        (TYPE_CLOUD, "Cloud"),
        (TYPE_NETWORK, "Red"),
        (TYPE_APPLICATION, "Aplicación"),
        (TYPE_OTHER, "Otro"),
    ]

    code = models.CharField("Código", max_length=64, unique=True, null=True, blank=True)
    name = models.CharField("Nombre", max_length=180, unique=True)
    protection = models.CharField("Proteccion", max_length=24, choices=PROTECTION_CHOICES, default=PROTECTION_INTERNAL)
    source_type = models.CharField("Tipo", max_length=40, default=TYPE_OTHER)
    category = models.CharField("Categoría", max_length=120, blank=True)
    category_ref = models.ForeignKey(
        "SourceCategory",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="sources",
        verbose_name="Categoría",
        limit_choices_to={"parent__isnull": True, "is_active": True},
    )
    subcategory_ref = models.ForeignKey(
        "SourceCategory",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="subcategory_sources",
        verbose_name="Subcategoría",
        limit_choices_to={"parent__isnull": False, "is_active": True},
    )
    vendor = models.CharField("Fabricante", max_length=120, blank=True)
    product = models.CharField("Producto", max_length=160, blank=True)
    environment = models.CharField("Ambiente", max_length=80, blank=True)
    host = models.CharField("Host / endpoint", max_length=255, blank=True)
    delivery_method = models.ForeignKey(
        SourceDeliveryMethod,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="sources",
        verbose_name="Metodo de envio",
    )
    port = models.PositiveIntegerField("Puerto", null=True, blank=True)
    protocol = models.CharField("Protocolo", max_length=40, blank=True)
    service_account = models.CharField("Cuenta de servicio", max_length=160, blank=True)
    status = models.CharField("Estado", max_length=20, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    owner = models.CharField("Responsable", max_length=150, blank=True)
    description = models.TextField("Descripción", blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_event_sources",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="updated_event_sources",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "Fuente de eventos"
        verbose_name_plural = "Fuentes de eventos"
        permissions = [
            ("link_eventsource", "Can link event sources to use cases"),
        ]

    def __str__(self):
        return self.display_name

    @property
    def display_name(self):
        if self.code:
            return f"{self.code} - {self.name}"
        return self.name

    @property
    def source_type_label(self):
        source_type = SourceType.objects.filter(code=self.source_type).first()
        if source_type:
            return source_type.name
        fallback = dict(self.TYPE_CHOICES).get(self.source_type)
        return fallback or self.source_type or ""

    @property
    def taxonomy_label(self):
        if self.subcategory_ref_id:
            return str(self.subcategory_ref)
        if self.category_ref_id:
            return str(self.category_ref)
        return self.category or ""

    @property
    def ingestion_label(self):
        parts = []
        if self.delivery_method_id:
            parts.append(str(self.delivery_method))
        if self.protocol:
            parts.append(self.protocol)
        if self.port:
            parts.append(str(self.port))
        return " / ".join(parts)

    def clean(self):
        super().clean()
        if self.subcategory_ref_id and self.category_ref_id:
            if self.subcategory_ref.parent_id != self.category_ref_id:
                from django.core.exceptions import ValidationError

                raise ValidationError({
                    "subcategory_ref": "La subcategoría debe pertenecer a la categoría seleccionada.",
                })


class SourceCategory(models.Model):
    name = models.CharField("Nombre", max_length=120)
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="subcategories",
        verbose_name="Categoría padre",
    )
    description = models.TextField("Descripción", blank=True)
    is_active = models.BooleanField("Activa", default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["parent__name", "name"]
        verbose_name = "Categoría de fuente"
        verbose_name_plural = "Categorías de fuentes"
        constraints = [
            models.UniqueConstraint(
                fields=["name"],
                condition=models.Q(parent__isnull=True),
                name="unique_root_source_category_name",
            ),
            models.UniqueConstraint(
                fields=["parent", "name"],
                condition=models.Q(parent__isnull=False),
                name="unique_child_source_category_name",
            )
        ]

    def __str__(self):
        if self.parent_id:
            return f"{self.parent.name} / {self.name}"
        return self.name

    @property
    def is_subcategory(self):
        return bool(self.parent_id)

    def clean(self):
        super().clean()
        if self.parent_id and self.parent.parent_id:
            from django.core.exceptions import ValidationError

            raise ValidationError({"parent": "La taxonomía solo admite categoría y subcategoría."})


class SourceAlias(models.Model):
    source = models.ForeignKey(
        EventSource,
        on_delete=models.CASCADE,
        related_name="aliases",
        verbose_name="Fuente",
    )
    alias = models.CharField("Alias", max_length=180, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["alias"]
        verbose_name = "Alias de fuente"
        verbose_name_plural = "Aliases de fuentes"

    def __str__(self):
        return f"{self.alias} -> {self.source.display_name}"


class UseCaseSource(models.Model):
    ROLE_PRIMARY = "primary"
    ROLE_SUPPORTING = "supporting"
    ROLE_DEPENDENCY = "dependency"
    ROLE_CONTEXT = "context"
    ROLE_CHOICES = [
        (ROLE_PRIMARY, "Principal"),
        (ROLE_SUPPORTING, "Soporte"),
        (ROLE_DEPENDENCY, "Dependencia"),
        (ROLE_CONTEXT, "Contexto"),
    ]

    use_case = models.ForeignKey(
        UseCase,
        on_delete=models.CASCADE,
        related_name="source_links",
        verbose_name="Caso de uso",
    )
    source = models.ForeignKey(
        EventSource,
        on_delete=models.PROTECT,
        related_name="use_case_links",
        verbose_name="Fuente",
    )
    role = models.CharField("Rol", max_length=24, choices=ROLE_CHOICES, default=ROLE_PRIMARY)
    is_required = models.BooleanField("Obligatoria", default=True)
    notes = models.TextField("Notas", blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_usecase_sources",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["use_case__name", "source__name"]
        verbose_name = "Fuente por caso de uso"
        verbose_name_plural = "Fuentes por caso de uso"
        constraints = [
            models.UniqueConstraint(
                fields=["use_case", "source"],
                name="unique_usecase_event_source",
            )
        ]

    def __str__(self):
        return f"{self.use_case} -> {self.source}"
