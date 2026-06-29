import hashlib

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.usecases.models import UseCase


class SigmaConversion(models.Model):
    MODE_EPL_TO_SIGMA = "epl_to_sigma"
    MODE_SIGMA_TO_TARGET = "sigma_to_target"
    MODE_CHOICES = [
        (MODE_EPL_TO_SIGMA, "EPL a Sigma"),
        (MODE_SIGMA_TO_TARGET, "Sigma a SIEM"),
    ]

    TARGET_NETWITNESS = "netwitness"
    TARGET_SPLUNK = "splunk"
    TARGET_SENTINEL = "sentinel"
    TARGET_ELASTIC = "elastic"
    TARGET_QRADAR = "qradar"
    TARGET_CHOICES = [
        (TARGET_NETWITNESS, "RSA NetWitness ESA Advanced"),
        (TARGET_SPLUNK, "Splunk Enterprise Security"),
        (TARGET_SENTINEL, "Microsoft Sentinel"),
        (TARGET_ELASTIC, "Elastic Security"),
        (TARGET_QRADAR, "IBM QRadar"),
    ]

    use_case = models.ForeignKey(
        UseCase,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="sigma_conversions",
    )
    mode = models.CharField(max_length=32, choices=MODE_CHOICES)
    target = models.CharField(max_length=32, choices=TARGET_CHOICES, blank=True)
    input_text = models.TextField()
    output_text = models.TextField()
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="sigma_conversions",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        permissions = [
            ("run_sigmaconversion", "Can run Sigma conversions"),
        ]

    def __str__(self):
        return f"{self.get_mode_display()} - {self.created_at:%Y-%m-%d %H:%M}"


class UseCaseTechnicalBackup(models.Model):
    TYPE_LOGIC = "logic"
    TYPE_SIGMA = "sigma"
    TYPE_BOTH = "both"
    TYPE_CHOICES = [
        (TYPE_LOGIC, "Lógica"),
        (TYPE_SIGMA, "Sigma"),
        (TYPE_BOTH, "Lógica + Sigma"),
    ]

    use_case = models.ForeignKey(
        UseCase,
        on_delete=models.CASCADE,
        related_name="technical_backups",
        verbose_name="Caso de uso",
    )
    version = models.PositiveIntegerField("Versión", blank=True)
    backup_type = models.CharField("Tipo", max_length=20, choices=TYPE_CHOICES, default=TYPE_BOTH)
    title = models.CharField("Titulo", max_length=180, blank=True)
    logic_text = models.TextField("Lógica / regla SIEM", blank=True)
    sigma_text = models.TextField("Sigma", blank=True)
    checksum = models.CharField("Checksum SHA-256", max_length=64, editable=False)
    is_current = models.BooleanField("Versión vigente", default=True)
    source_conversion = models.ForeignKey(
        SigmaConversion,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="technical_backups",
        verbose_name="Conversión origen",
    )
    notes = models.TextField("Notas", blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_technical_backups",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["use_case__name", "-version"]
        verbose_name = "Backup técnico de caso"
        verbose_name_plural = "Backups técnicos de casos"
        constraints = [
            models.UniqueConstraint(
                fields=["use_case", "version"],
                name="unique_usecase_technical_backup_version",
            )
        ]
        permissions = [
            ("manage_technicalbackup", "Can manage technical backups"),
        ]

    def __str__(self):
        return f"{self.use_case} v{self.version}"

    @property
    def short_checksum(self):
        return self.checksum[:12] if self.checksum else ""

    @classmethod
    def current_for_usecase(cls, usecase):
        return cls.objects.filter(use_case=usecase, is_current=True).order_by("-version").first()

    @staticmethod
    def calculate_checksum(logic_text, sigma_text):
        payload = f"logic:\n{logic_text or ''}\n---sigma:\n{sigma_text or ''}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def clean(self):
        super().clean()
        if not (self.logic_text or "").strip() and not (self.sigma_text or "").strip():
            raise ValidationError("El backup debe incluir logica, Sigma o ambos.")
        if self.backup_type == self.TYPE_LOGIC and not (self.logic_text or "").strip():
            raise ValidationError({"logic_text": "La lógica es obligatoria para este tipo de backup."})
        if self.backup_type == self.TYPE_SIGMA and not (self.sigma_text or "").strip():
            raise ValidationError({"sigma_text": "Sigma es obligatorio para este tipo de backup."})

    def save(self, *args, **kwargs):
        if not self.version:
            latest = (
                type(self).objects
                .filter(use_case=self.use_case)
                .order_by("-version")
                .values_list("version", flat=True)
                .first()
            )
            self.version = (latest or 0) + 1
        self.checksum = self.calculate_checksum(self.logic_text, self.sigma_text)
        self.full_clean()
        super().save(*args, **kwargs)
        if self.is_current:
            type(self).objects.filter(use_case=self.use_case, is_current=True).exclude(pk=self.pk).update(is_current=False)
