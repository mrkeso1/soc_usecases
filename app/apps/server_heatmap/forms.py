from django import forms

from .models import ServerAsset, ServerCategory, ServerInventoryConfiguration, ServerNamingRule


class InventoryConfigurationForm(forms.ModelForm):
    class Meta:
        model = ServerInventoryConfiguration
        fields = ("ad_active_days", "retention_days")


class ServerNamingRuleForm(forms.ModelForm):
    class Meta:
        model = ServerNamingRule
        fields = (
            "name",
            "pattern",
            "match_type",
            "os_family",
            "category",
            "priority",
            "is_active",
            "notes",
        )

    def clean_pattern(self):
        return self.cleaned_data["pattern"].strip()


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
