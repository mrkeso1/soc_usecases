from django import forms

from .models import ReportTemplateConfig
from .services import REPORT_SECTION_CHOICES


class ReportTemplateConfigForm(forms.ModelForm):
    sections = forms.MultipleChoiceField(
        choices=(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
        label="Secciones",
    )
    remove_logo = forms.BooleanField(required=False, label="Quitar logo")

    class Meta:
        model = ReportTemplateConfig
        fields = [
            "organization_name",
            "document_label",
            "report_title",
            "introduction_text",
            "primary_color",
            "accent_color",
            "footer_text",
            "confidentiality_label",
            "logo",
            "sections",
            "show_header",
            "show_footer",
            "show_generation_date",
            "show_page_numbers",
        ]
        widgets = {
            "primary_color": forms.TextInput(attrs={"type": "color"}),
            "accent_color": forms.TextInput(attrs={"type": "color"}),
            "introduction_text": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args, report_type=None, **kwargs):
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
        report_type = report_type or getattr(self.instance, "report_type", "")
        choices = [
            (key, f"{label} - {description}")
            for key, label, description in REPORT_SECTION_CHOICES.get(report_type, [])
        ]
        self.fields["sections"].choices = choices
        if not self.is_bound:
            self.initial["sections"] = self.instance.sections or [key for key, *_ in REPORT_SECTION_CHOICES.get(report_type, [])]
