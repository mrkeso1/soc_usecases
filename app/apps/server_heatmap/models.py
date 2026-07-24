from django.db import models


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
        (TYPE_AD, "Active Directory"),
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
        (CLASSIFICATION_AUTO, "Automática por nomenclatura"),
        (CLASSIFICATION_MANUAL, "Manual"),
    ]

    hostname = models.CharField("Hostname", max_length=255, unique=True)
    display_name = models.CharField("Nombre visible", max_length=255, blank=True)
    domain = models.CharField("Dominio", max_length=180, blank=True)
    ip_address = models.GenericIPAddressField("Dirección IP", null=True, blank=True)
    os_family = models.CharField("Sistema operativo", max_length=20, choices=OS_CHOICES, default=OS_UNKNOWN)
    server_type = models.CharField("Tipo de servidor", max_length=30, choices=SERVER_TYPE_CHOICES, default=TYPE_UNKNOWN)
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
    priority = models.PositiveIntegerField("Prioridad", default=100, help_text="Las reglas con menor número se evalúan primero.")
    is_active = models.BooleanField("Activa", default=True)
    notes = models.TextField("Notas", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["priority", "name"]
        verbose_name = "Regla de nomenclatura"
        verbose_name_plural = "Reglas de nomenclatura"

    def __str__(self):
        return f"{self.priority} - {self.name}"


class ServerInventoryConfiguration(models.Model):
    ad_active_days = models.PositiveSmallIntegerField(
        "Actividad máxima en AD (días)",
        default=60,
        help_text=(
            "Solo se importan equipos habilitados cuya última actividad en Active Directory "
            "esté dentro de este período. Use 0 para no filtrar por fecha."
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
