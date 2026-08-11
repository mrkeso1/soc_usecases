import json

from django import forms
from django.utils import timezone

from apps.sources.models import EventSource
from apps.usecases.models import UseCase

from .models import Control


class ControlForm(forms.ModelForm):
    control_conditions_text = forms.CharField(
        label="Condiciones del control",
        required=False,
        widget=forms.Textarea(attrs={
            "rows": 6,
            "placeholder": '[{"accion":"incluir","campo":"event.type","operador":"igual","valor":"login"}]',
        }),
        help_text="JSON opcional con condiciones estructuradas. Usalo solo si necesitas reglas tecnicas.",
    )

    class Meta:
        model = Control
        fields = [
            "classification",
            "source",
            "use_cases",
            "name",
            "status",
            "deployed_at",
            "objective",
            "description",
            "mitigated_risk",
            "evidence",
            "owner",
            "review_frequency_days",
            "next_review_at",
        ]
        widgets = {
            "deployed_at": forms.DateInput(attrs={"type": "date"}),
            "next_review_at": forms.DateInput(attrs={"type": "date"}),
            "objective": forms.Textarea(attrs={"rows": 3}),
            "description": forms.Textarea(attrs={"rows": 4}),
            "mitigated_risk": forms.Textarea(attrs={"rows": 3}),
            "evidence": forms.Textarea(attrs={"rows": 3}),
            "use_cases": forms.CheckboxSelectMultiple,
        }
        labels = {
            "classification": "Clasificación",
            "source": "Fuente de eventos",
            "use_cases": "Casos de uso vinculados",
            "name": "Nombre del control",
            "status": "Estado",
            "deployed_at": "Fecha de despliegue",
            "objective": "Objetivo",
            "description": "Descripción",
            "mitigated_risk": "Riesgo mitigado",
            "evidence": "Evidencia",
            "owner": "Responsable",
            "review_frequency_days": "Frecuencia de revisión (días)",
            "next_review_at": "Próxima revisión",
        }
        help_texts = {
            "classification": "Agrupacion funcional del control.",
            "source": "Fuente de eventos o tecnologia donde se valida el control.",
            "use_cases": "Casos de uso cubiertos o soportados por este control.",
            "review_frequency_days": "Cantidad de días entre revisiones periódicas.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, (forms.CheckboxInput, forms.CheckboxSelectMultiple)):
                bootstrap_class = "form-check-input"
            elif isinstance(widget, forms.Select):
                bootstrap_class = "form-select"
            else:
                bootstrap_class = "form-control"
            existing_classes = widget.attrs.get("class", "").split()
            if bootstrap_class not in existing_classes:
                widget.attrs["class"] = " ".join([*existing_classes, bootstrap_class])
        self.fields["source"].queryset = EventSource.objects.order_by("name")
        self.fields["use_cases"].queryset = UseCase.objects.order_by("name")
        if self.instance and self.instance.pk and not self.is_bound:
            self.initial["control_conditions_text"] = json.dumps(
                self.instance.control_conditions or [],
                ensure_ascii=False,
                indent=2,
            )

    def clean_control_conditions_text(self):
        raw = (self.cleaned_data.get("control_conditions_text") or "").strip()
        if not raw:
            return []
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise forms.ValidationError(f"JSON invalido: {exc.msg}") from exc
        if not isinstance(value, list):
            raise forms.ValidationError("Las condiciones deben ser una lista.")
        return value

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.control_conditions = self.cleaned_data["control_conditions_text"]
        if instance.status == Control.STATUS_PRODUCTION and not instance.deployed_at:
            instance.deployed_at = timezone.localdate()
        if commit:
            instance.save()
            self.save_m2m()
        return instance
