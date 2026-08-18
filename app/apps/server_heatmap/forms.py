from django import forms

from .models import (
    InventoryFilterRule,
    ServerAsset,
    ServerCategory,
    ServerInventoryConfiguration,
)


class BootstrapFormMixin:
    """Apply Bootstrap controls without changing each form's validation contract."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, forms.HiddenInput):
                continue
            if isinstance(widget, forms.CheckboxInput):
                css_class = "form-check-input"
            elif isinstance(widget, forms.Select):
                css_class = "form-select"
            else:
                css_class = "form-control"
            current_classes = widget.attrs.get("class", "").split()
            if css_class not in current_classes:
                widget.attrs["class"] = " ".join((*current_classes, css_class))


class InventoryConfigurationForm(BootstrapFormMixin, forms.ModelForm):
    class Meta:
        model = ServerInventoryConfiguration
        fields = (
            "siem_sync_enabled",
            "siem_sync_interval_days",
            "siem_sync_time",
            "ad_active_days",
            "retention_days",
            "inventory_history_days",
            "job_history_days",
            "dashboard_period_days",
            "ingestion_sla_days",
            "dashboard_default_environment",
            "dashboard_enabled_only",
            "dashboard_page_size",
        )
        widgets = {
            "siem_sync_time": forms.TimeInput(format="%H:%M", attrs={"type": "time"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["siem_sync_enabled"].label = "Actualización automática de AD y SIEM"
        self.fields["siem_sync_enabled"].help_text = (
            "Consulta Active Directory y luego descarga y procesa el archivo configurado "
            "en SERVER_INVENTORY_SIEM_URL."
        )
        self.fields["siem_sync_interval_days"].label = "Periodicidad del inventario (días)"
        self.fields["siem_sync_time"].label = "Horario de actualización del inventario"

    def clean_siem_sync_interval_days(self):
        value = self.cleaned_data["siem_sync_interval_days"]
        if value < 1:
            raise forms.ValidationError("La periodicidad debe ser de al menos un día.")
        return value

    def clean_dashboard_period_days(self):
        value = self.cleaned_data["dashboard_period_days"]
        if not 1 <= value <= 365:
            raise forms.ValidationError("El período debe estar entre 1 y 365 días.")
        return value

    def clean_ingestion_sla_days(self):
        value = self.cleaned_data["ingestion_sla_days"]
        if not 1 <= value <= 365:
            raise forms.ValidationError("El SLA debe estar entre 1 y 365 días.")
        return value

    def clean_dashboard_default_environment(self):
        return (self.cleaned_data["dashboard_default_environment"] or "PROD").strip().upper()

    def clean_dashboard_page_size(self):
        value = self.cleaned_data["dashboard_page_size"]
        if not 10 <= value <= 100:
            raise forms.ValidationError("La cantidad de filas debe estar entre 10 y 100.")
        return value


class ServerAssetForm(BootstrapFormMixin, forms.ModelForm):
    MANUAL_CLASSIFICATION_FIELDS = {
        "os_family",
        "category",
        "application_name",
        "environment",
    }

    class Meta:
        model = ServerAsset
        fields = (
            "display_name",
            "ip_address",
            "os_family",
            "category",
            "application_name",
            "environment",
            "is_critical",
            "classification_source",
            "is_enabled",
            "notes",
        )

    def save(self, commit=True):
        if self.MANUAL_CLASSIFICATION_FIELDS.intersection(self.changed_data):
            self.instance.classification_source = ServerAsset.CLASSIFICATION_MANUAL
        return super().save(commit=commit)


class ServerCategoryForm(BootstrapFormMixin, forms.ModelForm):
    class Meta:
        model = ServerCategory
        fields = ("name", "code", "order", "is_active", "description")


class InventoryFilterRuleForm(BootstrapFormMixin, forms.ModelForm):
    class Meta:
        model = InventoryFilterRule
        fields = (
            "name",
            "source",
            "field",
            "operator",
            "pattern",
            "action",
            "category",
            "os_family",
            "environment_value",
            "server_type_value",
            "priority",
            "is_active",
            "reason",
        )

    def clean_pattern(self):
        pattern = self.cleaned_data["pattern"].strip()
        if self.cleaned_data.get("operator") == InventoryFilterRule.OP_WILDCARD:
            if pattern == "*.":
                raise forms.ValidationError(
                    "El patrón '*.' no identifica un prefijo válido. Usá un comodín concreto."
                )
        return pattern
