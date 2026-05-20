from django import forms
from .models import UseCase


class UseCaseForm(forms.ModelForm):
    class Meta:
        model = UseCase
        fields = [
            "group_name",
            "device",
            "case_type",
            "objective",
            "blocking_type",
            "name",
            "owner_name",
            "monitoring",
            "status",
            "created_or_adjusted_at",
            "production_date",
            "mitre_attacks",
            "severity",
            "escalation",
            "sent_to_ho",
            "ho_flag",
            "last_validation_date",
            "validation_status",
            "validation_result",
            "is_enabled",
            # last_review_date y next_review_date son gestionados exclusivamente
            # por el sistema de lifecycle reviews — no deben editarse aquí.
            "comments",
        ]
        widgets = {
            "group_name": forms.TextInput(attrs={"class": "form-control"}),
            "device": forms.TextInput(attrs={"class": "form-control"}),
            "case_type": forms.TextInput(attrs={"class": "form-control"}),
            "objective": forms.Textarea(attrs={"class": "form-control", "rows": 4}),
            "blocking_type": forms.Select(attrs={"class": "form-control"}),
            "name": forms.TextInput(attrs={"class": "form-control"}),
            "owner_name": forms.TextInput(attrs={"class": "form-control"}),
            "monitoring": forms.TextInput(attrs={"class": "form-control"}),
            "status": forms.Select(attrs={"class": "form-control"}),
            "created_or_adjusted_at": forms.DateInput(
                attrs={"class": "form-control", "type": "date"}, format="%Y-%m-%d"
            ),
            "production_date": forms.DateInput(
                attrs={"class": "form-control", "type": "date"}, format="%Y-%m-%d"
            ),
            "mitre_attacks": forms.SelectMultiple(attrs={"class": "form-control", "style": "display:none;"}),
            "severity": forms.Select(attrs={"class": "form-control"}),
            "escalation": forms.Select(attrs={"class": "form-control"}),
            "sent_to_ho": forms.Select(attrs={"class": "form-control"}),
            "ho_flag": forms.TextInput(attrs={"class": "form-control"}),
            "last_validation_date": forms.DateInput(
                attrs={"class": "form-control", "type": "date"}, format="%Y-%m-%d"
            ),
            "validation_status": forms.Select(attrs={"class": "form-control"}),
            "validation_result": forms.Select(attrs={"class": "form-control"}),
            "is_enabled": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "comments": forms.Textarea(attrs={"class": "form-control", "rows": 4}),
        }
        help_texts = {
            "mitre_attacks": "Mantené Ctrl presionado para seleccionar varias técnicas.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["mitre_attacks"].queryset = self.fields["mitre_attacks"].queryset.filter(is_enabled=True)
