from django import forms
from django.utils.text import slugify

from .models import EventSource, SourceCategory, SourceDeliveryMethod, SourceType, UseCaseSource


def _apply_bootstrap_widget_classes(form):
    for field in form.fields.values():
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


class EventSourceForm(forms.ModelForm):
    source_type = forms.ChoiceField(label="Tipo")

    class Meta:
        model = EventSource
        fields = [
            "code",
            "name",
            "protection",
            "source_type",
            "category_ref",
            "subcategory_ref",
            "delivery_method",
            "protocol",
            "port",
            "service_account",
            "host",
            "status",
            "vendor",
            "product",
            "environment",
            "owner",
            "description",
        ]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 4}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _apply_bootstrap_widget_classes(self)
        type_choices = list(
            SourceType.objects.filter(is_active=True)
            .order_by("name")
            .values_list("code", "name")
        )
        current_type = self.instance.source_type if self.instance and self.instance.pk else None
        if current_type and current_type not in {code for code, _label in type_choices}:
            label = EventSource(source_type=current_type).source_type_label or current_type
            type_choices.append((current_type, label))
        if not type_choices:
            type_choices = EventSource.TYPE_CHOICES

        self.fields["source_type"].choices = type_choices
        self.fields["category_ref"].queryset = SourceCategory.objects.filter(
            parent__isnull=True,
            is_active=True,
        ).order_by("name")
        self.fields["category_ref"].required = True
        self.fields["subcategory_ref"].queryset = SourceCategory.objects.filter(
            parent__isnull=False,
            is_active=True,
        ).select_related("parent").order_by("parent__name", "name")
        self.fields["delivery_method"].queryset = SourceDeliveryMethod.objects.filter(
            is_active=True,
        ).order_by("name")

    def clean(self):
        cleaned = super().clean()
        category = cleaned.get("category_ref")
        subcategory = cleaned.get("subcategory_ref")
        if subcategory and category and subcategory.parent_id != category.id:
            self.add_error("subcategory_ref", "La subcategoria debe pertenecer a la categoria seleccionada.")
        if subcategory and not category:
            cleaned["category_ref"] = subcategory.parent
        return cleaned


class SourceCategoryForm(forms.ModelForm):
    class Meta:
        model = SourceCategory
        fields = ["name", "description", "is_active"]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _apply_bootstrap_widget_classes(self)

    def save(self, commit=True):
        self.instance.parent = None
        return super().save(commit=commit)


class SourceSubcategoryForm(forms.ModelForm):
    class Meta:
        model = SourceCategory
        fields = ["name", "parent", "description", "is_active"]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _apply_bootstrap_widget_classes(self)
        qs = SourceCategory.objects.filter(parent__isnull=True, is_active=True).order_by("name")
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        self.fields["parent"].queryset = qs
        self.fields["parent"].required = True
        self.fields["parent"].label = "Categoria padre"
        self.fields["parent"].help_text = "Elegir la categoria principal a la que pertenece esta subcategoria."


class SourceTypeForm(forms.ModelForm):
    code = forms.CharField(label="Codigo", max_length=40)

    class Meta:
        model = SourceType
        fields = ["code", "name", "description", "is_active"]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _apply_bootstrap_widget_classes(self)

    def clean_code(self):
        code = slugify(self.cleaned_data["code"]).replace("-", "_")
        if not code:
            raise forms.ValidationError("Indica un codigo valido.")
        return code[:40]


class SourceDeliveryMethodForm(forms.ModelForm):
    code = forms.CharField(label="Codigo", max_length=40)

    class Meta:
        model = SourceDeliveryMethod
        fields = ["code", "name", "description", "is_active"]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _apply_bootstrap_widget_classes(self)

    def clean_code(self):
        code = slugify(self.cleaned_data["code"]).replace("-", "_")
        if not code:
            raise forms.ValidationError("Indica un codigo valido.")
        return code[:40]


class UseCaseSourceForm(forms.ModelForm):
    class Meta:
        model = UseCaseSource
        fields = ["use_case", "source", "role", "is_required", "notes"]
        widgets = {
            "notes": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _apply_bootstrap_widget_classes(self)
