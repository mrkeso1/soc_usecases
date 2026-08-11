from django import forms

from apps.usecases.models import UseCase

from .models import SigmaConversion


class SigmaConversionForm(forms.Form):
    input_text = forms.CharField(
        label="Entrada",
        widget=forms.Textarea(attrs={"rows": 18, "class": "form-control"}),
    )
    target = forms.ChoiceField(
        label="Destino",
        choices=SigmaConversion.TARGET_CHOICES,
        required=False,
        initial=SigmaConversion.TARGET_NETWITNESS,
        widget=forms.Select(attrs={"class": "form-select"}),
    )
    use_case = forms.ModelChoiceField(
        label="Caso de uso relacionado",
        queryset=UseCase.objects.order_by("name"),
        required=False,
        widget=forms.Select(attrs={"class": "form-select"}),
    )
