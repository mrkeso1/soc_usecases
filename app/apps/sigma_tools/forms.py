from django import forms

from apps.usecases.models import UseCase

from .models import SigmaConversion


class SigmaConversionForm(forms.Form):
    input_text = forms.CharField(label="Entrada", widget=forms.Textarea(attrs={"rows": 18}))
    target = forms.ChoiceField(
        label="Destino",
        choices=SigmaConversion.TARGET_CHOICES,
        required=False,
        initial=SigmaConversion.TARGET_NETWITNESS,
    )
    use_case = forms.ModelChoiceField(
        label="Caso de uso relacionado",
        queryset=UseCase.objects.order_by("name"),
        required=False,
    )
