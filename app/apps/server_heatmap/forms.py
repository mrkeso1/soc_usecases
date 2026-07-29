from django import forms

from .models import (
    InventoryFilterRule,
    ServerAsset,
    ServerCategory,
    ServerInventoryConfiguration,
)


class InventoryConfigurationForm(forms.ModelForm):
    class Meta:
        model = ServerInventoryConfiguration
        fields = (
            "ad_active_days",
            "retention_days",
            "inventory_history_days",
            "job_history_days",
        )


class ServerAssetForm(forms.ModelForm):
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


class ServerCategoryForm(forms.ModelForm):
    class Meta:
        model = ServerCategory
        fields = ("name", "code", "order", "is_active", "description")


class InventoryFilterRuleForm(forms.ModelForm):
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
