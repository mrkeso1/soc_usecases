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
            "d3fends",
            "severity",
            "escalation",
            "sent_to_ho",
            "ho_flag",
            "last_validation_date",
            "validation_status",
            "validation_result",
            "is_enabled",
            "last_review_date",
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
            "created_or_adjusted_at": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
            "production_date": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
            "mitre_attacks": forms.SelectMultiple(attrs={"class": "form-control", "style": "display:none;"}),
            "d3fends": forms.SelectMultiple(attrs={"class": "form-control", "style": "display:none;"}),
            "severity": forms.Select(attrs={"class": "form-control"}),
            "escalation": forms.Select(attrs={"class": "form-control"}),
            "sent_to_ho": forms.Select(attrs={"class": "form-control"}),
            "ho_flag": forms.TextInput(attrs={"class": "form-control"}),
            "last_validation_date": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
            "validation_status": forms.Select(attrs={"class": "form-control"}),
            "validation_result": forms.Select(attrs={"class": "form-control"}),
            "is_enabled": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "last_review_date": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
            "comments": forms.Textarea(attrs={"class": "form-control", "rows": 4}),
        }
        help_texts = {
            "mitre_attacks": "Mantené Ctrl presionado para seleccionar varias técnicas.",
            "d3fends": "Mantené Ctrl presionado para seleccionar varios controles.",
        }