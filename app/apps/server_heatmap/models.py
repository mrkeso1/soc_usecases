import re

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone


class ServerAsset(models.Model):
    DNS_UNCHECKED = "unchecked"
    DNS_RESOLVED = "resolved"
    DNS_FAILED = "failed"
    DNS_CHOICES = [
        (DNS_UNCHECKED, "Sin verificar"),
        (DNS_RESOLVED, "Resuelto"),
        (DNS_FAILED, "No resuelto"),
    ]
    REACHABILITY_UNCHECKED = "unchecked"
    REACHABILITY_REACHABLE = "reachable"
    REACHABILITY_UNREACHABLE = "unreachable"
    REACHABILITY_ERROR = "error"
    REACHABILITY_CHOICES = [
        (REACHABILITY_UNCHECKED, "Sin verificar"),
        (REACHABILITY_REACHABLE, "Responde"),
        (REACHABILITY_UNREACHABLE, "No responde"),
        (REACHABILITY_ERROR, "No disponible"),
    ]
    OS_WINDOWS = "windows"
    OS_LINUX = "linux"
    OS_UNIX = "unix"
    OS_OTHER = "other"
    OS_UNKNOWN = "unknown"
    OS_CHOICES = [
        (OS_WINDOWS, "Windows"),
        (OS_LINUX, "Linux"),
        (OS_UNIX, "Unix"),
        (OS_OTHER, "Otro"),
        (OS_UNKNOWN, "Sin identificar"),
    ]

    TYPE_AD = "ad"
    TYPE_APPLICATION = "application"
    TYPE_DATABASE = "database"
    TYPE_FILESERVER = "fileserver"
    TYPE_WEB = "web"
    TYPE_MAIL = "mail"
    TYPE_SECURITY = "security"
    TYPE_NETWORK = "network"
    TYPE_OTHER = "other"
    TYPE_UNKNOWN = "unknown"
    SERVER_TYPE_CHOICES = [
        (TYPE_AD, "Domain Controllers"),
        (TYPE_APPLICATION, "Aplicaciones"),
        (TYPE_DATABASE, "Base de datos"),
        (TYPE_FILESERVER, "File server"),
        (TYPE_WEB, "Web"),
        (TYPE_MAIL, "Correo"),
        (TYPE_SECURITY, "Seguridad"),
        (TYPE_NETWORK, "Red / infraestructura"),
        (TYPE_OTHER, "Otro"),
        (TYPE_UNKNOWN, "Sin identificar"),
    ]

    CLASSIFICATION_AUTO = "auto"
    CLASSIFICATION_MANUAL = "manual"
    CLASSIFICATION_CHOICES = [
        (CLASSIFICATION_AUTO, "Automática por reglas"),
        (CLASSIFICATION_MANUAL, "Manual"),
    ]

    hostname = models.CharField("Hostname", max_length=255, unique=True)
    display_name = models.CharField("Nombre visible", max_length=255, blank=True)
    domain = models.CharField("Dominio", max_length=180, blank=True)
    ip_address = models.GenericIPAddressField("Dirección IP", null=True, blank=True)
    os_family = models.CharField("Sistema operativo", max_length=20, choices=OS_CHOICES, default=OS_UNKNOWN)
    server_type = models.CharField("Tipo de servidor", max_length=30, choices=SERVER_TYPE_CHOICES, default=TYPE_UNKNOWN)
    category = models.ForeignKey(
        "ServerCategory",
        on_delete=models.SET_NULL,
        related_name="assets",
        null=True,
        blank=True,
        verbose_name="Sección funcional",
    )
    application_name = models.CharField("Aplicación interna", max_length=180, blank=True)
    environment = models.CharField("Ambiente", max_length=80, blank=True)
    os_name = models.CharField("Sistema operativo informado", max_length=180, blank=True)
    organizational_unit = models.CharField("Unidad organizativa (OU)", max_length=500, blank=True)
    siem_groups = models.TextField("Grupos SIEM", blank=True)
    inventory_source = models.CharField("Origen del inventario", max_length=40, blank=True)
    legacy_classification = models.CharField("Clasificación anterior", max_length=80, blank=True)
    in_active_directory = models.BooleanField("Presente en AD", default=False)
    in_siem = models.BooleanField("Con ingesta en SIEM", default=False)
    ad_last_seen_at = models.DateTimeField("Última observación AD", null=True, blank=True)
    ad_last_logon_at = models.DateTimeField("Última actividad AD", null=True, blank=True)
    siem_last_seen_at = models.DateTimeField("Última observación SIEM", null=True, blank=True)
    dns_status = models.CharField(
        "Estado DNS",
        max_length=20,
        choices=DNS_CHOICES,
        default=DNS_UNCHECKED,
    )
    resolved_fqdn = models.CharField("Nombre resuelto", max_length=255, blank=True)
    resolved_ip_address = models.GenericIPAddressField("IP resuelta", null=True, blank=True)
    reachability_status = models.CharField(
        "Estado de conectividad",
        max_length=20,
        choices=REACHABILITY_CHOICES,
        default=REACHABILITY_UNCHECKED,
    )
    network_checked_at = models.DateTimeField("Último diagnóstico de red", null=True, blank=True)
    network_check_error = models.TextField("Detalle del diagnóstico", blank=True)
    is_enabled = models.BooleanField("Habilitado", default=True)
    classification_source = models.CharField(
        "Origen de clasificación",
        max_length=20,
        choices=CLASSIFICATION_CHOICES,
        default=CLASSIFICATION_AUTO,
    )
    notes = models.TextField("Notas", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["hostname"]
        verbose_name = "Servidor"
        verbose_name_plural = "Servidores"

    def __str__(self):
        return self.display_name or self.hostname

    @property
    def coverage_status(self):
        if self.in_active_directory and self.in_siem:
            return "both"
        if self.in_active_directory:
            return "ad_only"
        if self.in_siem:
            return "siem_only"
        return "neither"

    @property
    def coverage_label(self):
        return {
            "both": "AD + SIEM",
            "ad_only": "Solo AD",
            "siem_only": "Solo SIEM",
            "neither": "Sin origen",
        }[self.coverage_status]

    @property
    def diagnostic_result(self):
        if self.in_siem:
            return "Cubierto"
        if self.dns_status == self.DNS_FAILED:
            return "Revisar DNS / inventario AD"
        if self.reachability_status == self.REACHABILITY_REACHABLE:
            return "Configurar ingesta SIEM"
        if self.reachability_status == self.REACHABILITY_UNREACHABLE:
            return "Revisar disponibilidad"
        if self.reachability_status == self.REACHABILITY_ERROR:
            return "Ping no disponible"
        return "Pendiente de diagnóstico"


class ServerAssetDisableEvent(models.Model):
    asset = models.ForeignKey(
        ServerAsset,
        on_delete=models.CASCADE,
        related_name="disable_events",
        verbose_name="Equipo",
    )
    hostname = models.CharField("Hostname registrado", max_length=255)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="server_disable_events",
        null=True,
        blank=True,
        verbose_name="Usuario",
    )
    justification = models.TextField("Justificación")
    previous_enabled = models.BooleanField("Estado anterior", default=True)
    new_enabled = models.BooleanField("Estado nuevo", default=False)
    source_ip = models.GenericIPAddressField("IP de origen", null=True, blank=True)
    user_agent = models.CharField("Navegador", max_length=500, blank=True)
    created_at = models.DateTimeField("Fecha", auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Deshabilitación de servidor"
        verbose_name_plural = "Deshabilitaciones de servidores"

    def __str__(self):
        return f"{self.hostname} - {self.created_at:%Y-%m-%d %H:%M}"


class InventorySyncRun(models.Model):
    SOURCE_AD = "ad"
    SOURCE_SIEM = "siem"
    SOURCE_LEGACY = "legacy"
    SOURCE_CHOICES = [
        (SOURCE_AD, "Active Directory"),
        (SOURCE_SIEM, "SIEM"),
        (SOURCE_LEGACY, "Importación anterior"),
    ]
    STATUS_RUNNING = "running"
    STATUS_SUCCESS = "success"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_RUNNING, "En ejecución"),
        (STATUS_SUCCESS, "Finalizada"),
        (STATUS_FAILED, "Fallida"),
    ]

    source = models.CharField("Origen", max_length=20, choices=SOURCE_CHOICES)
    status = models.CharField("Estado", max_length=20, choices=STATUS_CHOICES, default=STATUS_RUNNING)
    started_at = models.DateTimeField("Inicio", auto_now_add=True)
    finished_at = models.DateTimeField("Fin", null=True, blank=True)
    records_read = models.PositiveIntegerField("Registros leídos", default=0)
    assets_created = models.PositiveIntegerField("Equipos creados", default=0)
    assets_updated = models.PositiveIntegerField("Equipos actualizados", default=0)
    issues_count = models.PositiveIntegerField("Conflictos", default=0)
    error_message = models.TextField("Error", blank=True)
    metadata = models.JSONField("Metadatos", default=dict, blank=True)

    class Meta:
        ordering = ["-started_at"]
        verbose_name = "Ejecución de inventario"
        verbose_name_plural = "Ejecuciones de inventario"

    def __str__(self):
        return f"{self.get_source_display()} - {self.started_at:%Y-%m-%d %H:%M}"


class InventoryJob(models.Model):
    TYPE_FULL_SYNC = "full_sync"
    TYPE_REPROCESS = "reprocess"
    TYPE_APPLY_FILTERS = "apply_filters"
    TYPE_CHOICES = [
        (TYPE_FULL_SYNC, "Actualizar AD y SIEM"),
        (TYPE_REPROCESS, "Cruzar inventario almacenado"),
        (TYPE_APPLY_FILTERS, "Aplicar filtros"),
    ]
    STATUS_PENDING = "pending"
    STATUS_RUNNING = "running"
    STATUS_RETRYING = "retrying"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"
    STATUS_CANCELLED = "cancelled"
    ACTIVE_STATUSES = [STATUS_PENDING, STATUS_RUNNING, STATUS_RETRYING]
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pendiente"),
        (STATUS_RUNNING, "En ejecución"),
        (STATUS_RETRYING, "Reintentando"),
        (STATUS_COMPLETED, "Finalizado"),
        (STATUS_FAILED, "Fallido"),
        (STATUS_CANCELLED, "Cancelado"),
    ]

    job_type = models.CharField("Tipo", max_length=30, choices=TYPE_CHOICES, db_index=True)
    idempotency_key = models.CharField(
        "Clave de idempotencia",
        max_length=100,
        unique=True,
    )
    status = models.CharField(
        "Estado",
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        db_index=True,
    )
    payload = models.JSONField("Parámetros", default=dict, blank=True)
    result = models.JSONField("Resultado", default=dict, blank=True)
    progress = models.JSONField("Progreso", default=dict, blank=True)
    attempts = models.PositiveSmallIntegerField("Intentos", default=0)
    max_attempts = models.PositiveSmallIntegerField("Máximo de intentos", default=3)
    rerun_requested = models.BooleanField("Repetición solicitada", default=False)
    available_at = models.DateTimeField("Disponible desde", default=timezone.now, db_index=True)
    started_at = models.DateTimeField("Inicio", null=True, blank=True)
    heartbeat_at = models.DateTimeField("Último heartbeat", null=True, blank=True)
    lease_expires_at = models.DateTimeField("Vencimiento de lease", null=True, blank=True, db_index=True)
    finished_at = models.DateTimeField("Fin", null=True, blank=True)
    worker_id = models.CharField("Worker", max_length=150, blank=True)
    last_error = models.TextField("Último error", blank=True)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="server_inventory_jobs",
        verbose_name="Solicitado por",
    )
    created_at = models.DateTimeField("Creado", auto_now_add=True)
    updated_at = models.DateTimeField("Actualizado", auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["job_type"],
                condition=models.Q(status__in=["pending", "running", "retrying"]),
                name="uniq_active_inventory_job_type",
            ),
        ]
        indexes = [
            models.Index(fields=["status", "available_at"]),
        ]
        verbose_name = "Trabajo de inventario"
        verbose_name_plural = "Trabajos de inventario"

    def __str__(self):
        return f"{self.get_job_type_display()} - {self.get_status_display()}"


class InventoryObservation(models.Model):
    sync_run = models.ForeignKey(
        InventorySyncRun,
        on_delete=models.CASCADE,
        related_name="observations",
        verbose_name="Ejecución",
    )
    asset = models.ForeignKey(
        ServerAsset,
        on_delete=models.SET_NULL,
        related_name="inventory_observations",
        null=True,
        blank=True,
        verbose_name="Equipo conciliado",
    )
    source = models.CharField("Origen", max_length=20, choices=InventorySyncRun.SOURCE_CHOICES)
    external_id = models.CharField("Identificador externo", max_length=255)
    hostname = models.CharField("Hostname", max_length=255, blank=True)
    fqdn = models.CharField("FQDN", max_length=255, blank=True)
    ip_address = models.GenericIPAddressField("Dirección IP", null=True, blank=True)
    os_name = models.CharField("Sistema operativo", max_length=180, blank=True)
    organizational_unit = models.CharField("Unidad organizativa (OU)", max_length=500, blank=True)
    environment = models.CharField("Ambiente", max_length=80, blank=True)
    groups = models.TextField("Grupos", blank=True)
    server_type_hint = models.CharField("Tipo sugerido", max_length=80, blank=True)
    observed_at = models.DateTimeField("Fecha observada", null=True, blank=True)
    raw_data = models.JSONField("Dato original", default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["hostname", "external_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["sync_run", "source", "external_id"],
                name="uniq_inventory_observation_per_run",
            ),
        ]
        verbose_name = "Observación de inventario"
        verbose_name_plural = "Observaciones de inventario"


class AssetIdentifier(models.Model):
    KIND_HOSTNAME = "hostname"
    KIND_FQDN = "fqdn"
    KIND_IP = "ip"
    KIND_CHOICES = [
        (KIND_HOSTNAME, "Hostname"),
        (KIND_FQDN, "FQDN"),
        (KIND_IP, "Dirección IP"),
    ]

    asset = models.ForeignKey(ServerAsset, on_delete=models.CASCADE, related_name="identifiers")
    kind = models.CharField("Tipo", max_length=20, choices=KIND_CHOICES)
    value = models.CharField("Valor", max_length=255)
    normalized_value = models.CharField("Valor normalizado", max_length=255, db_index=True)
    source = models.CharField("Origen", max_length=20, choices=InventorySyncRun.SOURCE_CHOICES)
    last_seen_at = models.DateTimeField("Última observación", null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["asset", "kind", "normalized_value", "source"],
                name="uniq_asset_identifier_source",
            ),
        ]
        indexes = [models.Index(fields=["kind", "normalized_value"])]
        verbose_name = "Identificador de equipo"
        verbose_name_plural = "Identificadores de equipos"


class ReconciliationIssue(models.Model):
    TYPE_AMBIGUOUS = "ambiguous"
    TYPE_MISSING_IDENTIFIER = "missing_identifier"
    TYPE_NOT_IN_AD = "not_in_ad"
    TYPE_INVALID = "invalid"
    TYPE_CHOICES = [
        (TYPE_AMBIGUOUS, "Coincidencia ambigua"),
        (TYPE_MISSING_IDENTIFIER, "Sin identificador"),
        (TYPE_NOT_IN_AD, "No encontrado en AD"),
        (TYPE_INVALID, "Dato inválido"),
    ]

    sync_run = models.ForeignKey(
        InventorySyncRun,
        on_delete=models.CASCADE,
        related_name="issues",
        verbose_name="Ejecución",
    )
    observation = models.ForeignKey(
        InventoryObservation,
        on_delete=models.CASCADE,
        related_name="issues",
        null=True,
        blank=True,
        verbose_name="Observación",
    )
    issue_type = models.CharField("Tipo", max_length=40, choices=TYPE_CHOICES)
    identifier = models.CharField("Identificador", max_length=255, blank=True)
    details = models.JSONField("Detalle", default=dict, blank=True)
    is_resolved = models.BooleanField("Resuelto", default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["is_resolved", "-created_at"]
        verbose_name = "Conflicto de conciliación"
        verbose_name_plural = "Conflictos de conciliación"


class ServerNamingRule(models.Model):
    MATCH_WILDCARD = "wildcard"
    MATCH_REGEX = "regex"
    MATCH_TYPE_CHOICES = [
        (MATCH_WILDCARD, "Comodín simple (* y ?)"),
        (MATCH_REGEX, "Expresión regular avanzada"),
    ]

    name = models.CharField("Nombre", max_length=120, unique=True)
    pattern = models.CharField(
        "Patrón del nombre",
        max_length=255,
        help_text="No distingue mayúsculas. Ejemplo con comodín: arpads*",
    )
    match_type = models.CharField(
        "Tipo de patrón",
        max_length=20,
        choices=MATCH_TYPE_CHOICES,
        default=MATCH_WILDCARD,
    )
    os_family = models.CharField("Sistema operativo sugerido", max_length=20, choices=ServerAsset.OS_CHOICES, blank=True)
    server_type = models.CharField("Tipo sugerido", max_length=30, choices=ServerAsset.SERVER_TYPE_CHOICES, blank=True)
    category = models.ForeignKey(
        "ServerCategory",
        on_delete=models.SET_NULL,
        related_name="naming_rules",
        null=True,
        blank=True,
        verbose_name="Sección funcional sugerida",
    )
    priority = models.PositiveIntegerField("Prioridad", default=100, help_text="Las reglas con menor número se evalúan primero.")
    is_active = models.BooleanField("Activa", default=True)
    notes = models.TextField("Notas", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["priority", "name"]
        verbose_name = "Nomenclatura anterior"
        verbose_name_plural = "Nomenclaturas anteriores"

    def __str__(self):
        return f"{self.priority} - {self.name}"

    def save(self, *args, **kwargs):
        with transaction.atomic():
            return super().save(*args, **kwargs)


class ServerCategory(models.Model):
    name = models.CharField("Nombre", max_length=100, unique=True)
    code = models.SlugField(
        "Código",
        max_length=60,
        unique=True,
        help_text="Identificador interno estable. Ejemplo: domain-controllers.",
    )
    order = models.PositiveSmallIntegerField("Orden", default=100)
    is_active = models.BooleanField("Activa", default=True)
    description = models.TextField("Descripción", blank=True)

    class Meta:
        ordering = ["order", "name"]
        verbose_name = "Sección de servidores"
        verbose_name_plural = "Secciones de servidores"

    def __str__(self):
        return self.name


class ServerInventoryConfiguration(models.Model):
    ad_active_days = models.PositiveSmallIntegerField(
        "Actividad máxima en AD (días)",
        default=60,
        help_text=(
            "Solo se importan equipos habilitados cuya última actividad en Active Directory "
            "esté dentro de este período. Use 0 para no filtrar por fecha."
        ),
    )
    retention_days = models.PositiveSmallIntegerField(
        "Eliminar equipos sin conexión después de (días)",
        default=90,
        help_text=(
            "Después de una sincronización AD exitosa se eliminan los equipos cuya última "
            "actividad AD sea anterior a este período. Use 0 para no eliminar."
        ),
    )
    inventory_history_days = models.PositiveSmallIntegerField(
        "Conservar ejecuciones de inventario (días)",
        default=180,
        help_text=(
            "El mantenimiento elimina ejecuciones y observaciones más antiguas, "
            "pero siempre conserva la última ejecución de cada origen. Use 0 para no eliminar."
        ),
    )
    job_history_days = models.PositiveSmallIntegerField(
        "Conservar trabajos finalizados (días)",
        default=90,
        help_text=(
            "El mantenimiento elimina trabajos finalizados, fallidos o cancelados más antiguos. "
            "Los trabajos activos nunca se eliminan. Use 0 para no eliminar."
        ),
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Configuración del inventario"
        verbose_name_plural = "Configuración del inventario"

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        return None

    def __str__(self):
        return "Configuración general"

    @classmethod
    def load(cls):
        configuration, _ = cls.objects.get_or_create(pk=1)
        return configuration


class InventoryFilterRule(models.Model):
    SOURCE_BOTH = "both"
    SOURCE_CHOICES = [
        (SOURCE_BOTH, "AD y SIEM"),
        (InventorySyncRun.SOURCE_AD, "Active Directory"),
        (InventorySyncRun.SOURCE_SIEM, "SIEM"),
    ]
    FIELD_HOSTNAME = "hostname"
    FIELD_FQDN = "fqdn"
    FIELD_IP = "ip_address"
    FIELD_OU = "organizational_unit"
    FIELD_OS = "os_name"
    FIELD_GROUPS = "groups"
    FIELD_DEVICE_TYPE = "server_type_hint"
    FIELD_ENVIRONMENT = "environment"
    FIELD_CHOICES = [
        (FIELD_HOSTNAME, "Hostname"),
        (FIELD_FQDN, "FQDN"),
        (FIELD_IP, "Dirección IP"),
        (FIELD_OU, "Unidad organizativa (OU)"),
        (FIELD_OS, "Sistema operativo informado"),
        (FIELD_GROUPS, "Grupos SIEM"),
        (FIELD_DEVICE_TYPE, "Tipo de dispositivo SIEM"),
        (FIELD_ENVIRONMENT, "Ambiente"),
    ]
    OP_EXACT = "exact"
    OP_CONTAINS = "contains"
    OP_WILDCARD = "wildcard"
    OP_REGEX = "regex"
    OP_WORD = "word"
    OPERATOR_CHOICES = [
        (OP_EXACT, "Igual"),
        (OP_CONTAINS, "Contiene"),
        (OP_WILDCARD, "Comodín (* y ?)"),
        (OP_REGEX, "Expresión regular"),
        (OP_WORD, "Palabra completa"),
    ]
    ACTION_EXCLUDE = "exclude"
    ACTION_INCLUDE = "include"
    ACTION_CLASSIFY = "classify"
    ACTION_CHOICES = [
        (ACTION_EXCLUDE, "Excluir"),
        (ACTION_INCLUDE, "Incluir"),
        (ACTION_CLASSIFY, "Clasificar"),
    ]

    name = models.CharField("Nombre", max_length=140, unique=True)
    source = models.CharField(
        "Origen",
        max_length=20,
        choices=SOURCE_CHOICES,
        default=SOURCE_BOTH,
    )
    field = models.CharField("Campo evaluado", max_length=40, choices=FIELD_CHOICES)
    operator = models.CharField(
        "Operador",
        max_length=20,
        choices=OPERATOR_CHOICES,
        default=OP_WILDCARD,
    )
    pattern = models.CharField("Patrón", max_length=500)
    action = models.CharField("Acción", max_length=20, choices=ACTION_CHOICES)
    category = models.ForeignKey(
        ServerCategory,
        on_delete=models.SET_NULL,
        related_name="inventory_filter_rules",
        null=True,
        blank=True,
        verbose_name="Sección asignada",
    )
    os_family = models.CharField(
        "Sistema operativo asignado",
        max_length=20,
        choices=ServerAsset.OS_CHOICES,
        blank=True,
    )
    environment_value = models.CharField(
        "Ambiente asignado",
        max_length=80,
        blank=True,
    )
    server_type_value = models.CharField(
        "Tipo interno asignado",
        max_length=30,
        choices=ServerAsset.SERVER_TYPE_CHOICES,
        blank=True,
    )
    legacy_naming_rule_id = models.PositiveBigIntegerField(
        "ID de nomenclatura anterior",
        null=True,
        blank=True,
        unique=True,
        editable=False,
        help_text="Referencia de transición para reglas migradas desde el motor anterior.",
    )
    priority = models.PositiveIntegerField(
        "Prioridad",
        default=100,
        help_text="Las reglas con menor número se evalúan primero.",
    )
    is_active = models.BooleanField("Activa", default=False)
    reason = models.TextField("Motivo", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["priority", "name"]
        verbose_name = "Regla de inventario"
        verbose_name_plural = "Reglas de inventario"

    def clean(self):
        super().clean()
        if self.operator == self.OP_REGEX:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValidationError({"pattern": f"Expresión regular inválida: {exc}"}) from exc
        if self.action == self.ACTION_CLASSIFY and not (
            self.category_id
            or self.os_family
            or self.environment_value
            or self.server_type_value
        ):
            raise ValidationError(
                "Una regla de clasificación debe asignar sección, sistema operativo o ambiente."
            )

    def __str__(self):
        return f"{self.priority} - {self.name}"

    def save(self, *args, **kwargs):
        with transaction.atomic():
            return super().save(*args, **kwargs)


class InventoryRuleRevision(models.Model):
    TYPE_NAMING = "naming"
    TYPE_FILTER = "filter"
    TYPE_CHOICES = [
        (TYPE_NAMING, "Nomenclatura anterior"),
        (TYPE_FILTER, "Regla de inventario"),
    ]
    ACTION_BASELINE = "baseline"
    ACTION_CREATED = "created"
    ACTION_UPDATED = "updated"
    ACTION_DELETED = "deleted"
    ACTION_CHOICES = [
        (ACTION_BASELINE, "Estado inicial"),
        (ACTION_CREATED, "Creación"),
        (ACTION_UPDATED, "Modificación"),
        (ACTION_DELETED, "Eliminación"),
    ]

    rule_type = models.CharField("Tipo de regla", max_length=20, choices=TYPE_CHOICES)
    rule_object_id = models.PositiveBigIntegerField("ID original")
    rule_name = models.CharField("Nombre de la regla", max_length=140)
    version = models.PositiveIntegerField("Versión")
    action = models.CharField("Acción", max_length=20, choices=ACTION_CHOICES)
    before_snapshot = models.JSONField("Valores anteriores", default=dict, blank=True)
    after_snapshot = models.JSONField("Valores nuevos", default=dict, blank=True)
    changed_fields = models.JSONField("Campos modificados", default=list, blank=True)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="inventory_rule_revisions",
        verbose_name="Modificado por",
    )
    request_id = models.CharField("ID de solicitud", max_length=128, blank=True)
    created_at = models.DateTimeField("Fecha", auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["rule_type", "rule_object_id", "version"],
                name="uniq_inventory_rule_revision_version",
            ),
        ]
        indexes = [
            models.Index(fields=["rule_type", "rule_object_id", "-version"]),
            models.Index(fields=["changed_by", "-created_at"]),
        ]
        verbose_name = "Versión de regla de inventario"
        verbose_name_plural = "Versiones de reglas de inventario"

    def __str__(self):
        return f"{self.rule_name} · v{self.version}"


class InventoryFilterDecision(models.Model):
    sync_run = models.ForeignKey(
        InventorySyncRun,
        on_delete=models.CASCADE,
        related_name="filter_decisions",
        null=True,
        blank=True,
        verbose_name="Ejecución",
    )
    rule = models.ForeignKey(
        InventoryFilterRule,
        on_delete=models.SET_NULL,
        related_name="decisions",
        null=True,
        blank=True,
        verbose_name="Regla aplicada",
    )
    source = models.CharField(
        "Origen",
        max_length=20,
        choices=InventorySyncRun.SOURCE_CHOICES,
    )
    identifier = models.CharField("Identificador", max_length=255, blank=True)
    action = models.CharField(
        "Acción",
        max_length=20,
        choices=InventoryFilterRule.ACTION_CHOICES,
    )
    reason = models.TextField("Motivo", blank=True)
    raw_data = models.JSONField("Datos originales", default=dict, blank=True)
    is_reviewed = models.BooleanField("Revisada", default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Decisión de filtro"
        verbose_name_plural = "Decisiones de filtros"

    def __str__(self):
        return f"{self.source}: {self.identifier} - {self.action}"
