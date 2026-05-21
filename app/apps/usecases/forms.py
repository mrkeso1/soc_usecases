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
            "disabled_reason",
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
            "disabled_reason": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
            "comments": forms.Textarea(attrs={"class": "form-control", "rows": 4}),
        }
        labels = {
            "group_name": "Grupo",
            "device": "Dispositivo",
            "case_type": "Tipo",
            "objective": "Objetivo",
            "blocking_type": "Tipo de bloqueo",
            "name": "Nombre NetWitness",
            "owner_name": "Responsable desarrollo",
            "monitoring": "Monitoreo",
            "status": "Estado",
            "created_or_adjusted_at": "Fecha alta/ajuste",
            "production_date": "Fecha producción",
            "mitre_attacks": "MITRE ATT&CK relacionado",
            "severity": "Severidad",
            "escalation": "Escalamiento",
            "sent_to_ho": "Envío HO",
            "ho_flag": "HO",
            "last_validation_date": "Última validación",
            "validation_status": "Estado validación",
            "validation_result": "Resultado",
            "is_enabled": "Habilitado",
            "disabled_reason": "Motivo de deshabilitación",
            "comments": "Comentarios",
        }
        help_texts = {
            "mitre_attacks": "Buscá por ID, nombre o táctica. D3FEND se infiere automáticamente.",
            "disabled_reason": "Obligatorio si el caso queda deshabilitado.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["mitre_attacks"].queryset = self.fields["mitre_attacks"].queryset.filter(is_enabled=True)

    def clean(self):
        cleaned_data = super().clean()
        status = cleaned_data.get("status")
        mitre_attacks = cleaned_data.get("mitre_attacks")

        if status == "Producción" and not mitre_attacks:
            self.add_error(
                "mitre_attacks",
                "Un caso en Producción debe tener al menos una técnica MITRE ATT&CK asociada.",
            )

        return cleaned_data
