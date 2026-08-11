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
            "ad_active_days",
            "retention_days",
            "inventory_history_days",
            "job_history_days",
        )


class ServerAssetForm(BootstrapFormMixin, forms.ModelForm):
    class Meta:
        model = ServerAsset
        fields = (
            "display_name",
            "ip_address",
            "os_family",
            "category",
            "application_name",
            "environment",
            "classification_source",
            "is_enabled",
            "notes",
        )


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
