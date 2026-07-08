import json

from django import forms
from django.forms import inlineformset_factory

from apps.sources.models import EventSource

from .models import UseCase, UseCaseRuleCondition
from .text_utils import normalize_multi_text, split_multi_value


class MitreAttackM2MBridgeMixin(forms.ModelForm):
    """Bridge para que UseCase.clean() valide MITRE ATT&CK antes de guardar M2M."""

    def clean(self):
        cleaned_data = super().clean()
        mitre_attacks = cleaned_data.get("mitre_attacks")

        if mitre_attacks is not None:
            self.instance._clean_mitre_attack_ids = {
                item.pk for item in mitre_attacks if item.pk
            }

        return cleaned_data


class UseCaseForm(MitreAttackM2MBridgeMixin, forms.ModelForm):
    event_sources = forms.ModelMultipleChoiceField(
        label="Fuentes de eventos",
        queryset=EventSource.objects.none(),
        required=False,
        help_text="Fuentes relacionadas al caso desde el catalogo de fuentes de eventos.",
        widget=forms.SelectMultiple(attrs={
            "class": "form-control",
            "data-multi-select": "true",
            "data-placeholder": "Buscar fuente...",
        }),
    )

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
            "full_rule_text",
            "functional_description",
            "event_sources",
        ]
        widgets = {
            "group_name": forms.TextInput(attrs={
                "class": "form-control",
                "data-multi-tags": "true",
                "data-placeholder": "Agregar grupo...",
            }),
            "device": forms.TextInput(attrs={
                "class": "form-control",
                "data-multi-tags": "true",
                "data-placeholder": "Agregar dispositivo...",
            }),
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
            "full_rule_text": forms.Textarea(attrs={"class": "form-control code-input", "rows": 12, "spellcheck": "false"}),
            "functional_description": forms.Textarea(attrs={"class": "form-control", "rows": 5}),
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
            "full_rule_text": "Regla completa",
            "functional_description": "Descripcion funcional",
            "event_sources": "Fuentes de eventos",
        }
        help_texts = {
            "event_sources": "Selecciona fuentes del catalogo normalizado; no uses el dispositivo legacy como reemplazo.",
            "full_rule_text": "Pega la regla completa del SIEM/EPL/Sigma. Se usa para backups tecnicos y auditoria.",
            "functional_description": "Explica en lenguaje operativo que detecta el caso, alcance y criterio de validacion.",
            "mitre_attacks": "Busca por ID, nombre o tactica. D3FEND se infiere automaticamente.",
            "disabled_reason": "Obligatorio si el caso queda deshabilitado.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["mitre_attacks"].queryset = self.fields["mitre_attacks"].queryset.filter(is_enabled=True)
        self.fields["event_sources"].queryset = EventSource.objects.order_by("name")
        self.fields["group_name"].widget.attrs["data-options"] = json.dumps(self._multi_value_options("group_name"))
        self.fields["device"].widget.attrs["data-options"] = json.dumps(self._multi_value_options("device"))
        if self.instance and self.instance.pk:
            self.fields["event_sources"].initial = self.instance.source_links.values_list("source_id", flat=True)

    @staticmethod
    def _multi_value_options(field_name):
        values = []
        seen = set()
        for raw_value in UseCase.objects.exclude(**{field_name: ""}).values_list(field_name, flat=True):
            for value in split_multi_value(raw_value):
                key = value.casefold()
                if key not in seen:
                    values.append(value)
                    seen.add(key)
        return sorted(values, key=str.casefold)

    def clean_group_name(self):
        return normalize_multi_text(self.cleaned_data.get("group_name"))

    def clean_device(self):
        return normalize_multi_text(self.cleaned_data.get("device"))


class UseCaseRuleConditionForm(forms.ModelForm):
    class Meta:
        model = UseCaseRuleCondition
        fields = ["position", "condition_type", "field_name", "operator", "value"]
        widgets = {
            "position": forms.NumberInput(attrs={"class": "form-control condition-position", "min": 1}),
            "condition_type": forms.Select(attrs={"class": "form-control condition-type"}),
            "field_name": forms.TextInput(attrs={"class": "form-control", "placeholder": "source, environment, user, action..."}),
            "operator": forms.Select(attrs={"class": "form-control"}),
            "value": forms.TextInput(attrs={"class": "form-control", "placeholder": "Valor esperado"}),
        }
        labels = {
            "position": "#",
            "condition_type": "Tipo",
            "field_name": "Campo",
            "operator": "Operador",
            "value": "Valor",
        }


UseCaseRuleConditionFormSet = inlineformset_factory(
    UseCase,
    UseCaseRuleCondition,
    form=UseCaseRuleConditionForm,
    extra=0,
    can_delete=True,
)
