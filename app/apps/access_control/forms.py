from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission


PERMISSION_CATALOG = [
    ("Dashboard", [
        ("dashboard.view_executive_dashboard", "Ver dashboard ejecutivo"),
        ("dashboard.view_mitre_dashboard", "Ver dashboard MITRE"),
    ]),
    ("Inventario", [
        ("usecases.view_usecase", "Ver casos de uso"),
        ("usecases.add_usecase", "Crear casos de uso"),
        ("usecases.change_usecase", "Editar casos de uso"),
        ("usecases.delete_usecase", "Eliminar casos de uso"),
        ("usecases.manage_lifecycle_controls", "Gestionar controles de lifecycle"),
    ]),
    ("Fuentes", [
        ("sources.view_eventsource", "Ver fuentes"),
        ("sources.add_eventsource", "Crear fuentes"),
        ("sources.change_eventsource", "Editar fuentes"),
        ("sources.delete_eventsource", "Eliminar fuentes"),
        ("sources.link_eventsource", "Vincular fuentes a casos"),
        ("sources.view_sourcecategory", "Ver taxonomia de fuentes"),
        ("sources.add_sourcecategory", "Crear taxonomia de fuentes"),
        ("sources.change_sourcecategory", "Editar taxonomia de fuentes"),
        ("sources.delete_sourcecategory", "Eliminar taxonomia de fuentes"),
    ]),
    ("Sigma", [
        ("sigma_tools.view_sigmaconversion", "Ver conversiones Sigma"),
        ("sigma_tools.add_sigmaconversion", "Ejecutar conversiones Sigma"),
        ("sigma_tools.change_sigmaconversion", "Editar historial Sigma"),
        ("sigma_tools.delete_sigmaconversion", "Eliminar historial Sigma"),
        ("sigma_tools.view_usecasetechnicalbackup", "Ver backups técnicos"),
        ("sigma_tools.add_usecasetechnicalbackup", "Crear backups técnicos"),
        ("sigma_tools.change_usecasetechnicalbackup", "Editar backups técnicos"),
        ("sigma_tools.delete_usecasetechnicalbackup", "Eliminar backups técnicos"),
        ("sigma_tools.manage_technicalbackup", "Gestionar backups técnicos"),
    ]),
    ("Controles", [
        ("controls.view_control", "Ver controles"),
        ("controls.add_control", "Crear controles"),
        ("controls.change_control", "Editar controles"),
        ("controls.delete_control", "Eliminar controles"),
        ("controls.view_controlinventorychange", "Ver historial de controles"),
    ]),
    ("Reportes", [
        ("reports.view_reportdownload", "Ver centro de reportes"),
        ("reports.export_reports", "Exportar reportes PDF"),
    ]),
    ("Auditoria", [
        ("auditlog.view_auditlog", "Ver auditoria"),
        ("auditlog.view_security_audit", "Ver auditoria SOC"),
        ("auditlog.view_inventory_audit", "Ver auditoria de inventario"),
        ("auditlog.view_lifecycle_audit", "Ver auditoria de ciclo de vida"),
        ("auditlog.view_controls_audit", "Ver auditoria de controles"),
        ("auditlog.view_reports_audit", "Ver auditoria de reportes"),
        ("auditlog.view_sigma_audit", "Ver auditoria Sigma"),
        ("auditlog.export_audit", "Exportar auditoria"),
    ]),
    ("Administracion", [
        ("auth.view_group", "Ver roles"),
        ("auth.add_group", "Crear roles"),
        ("auth.change_group", "Editar roles"),
        ("auth.delete_group", "Eliminar roles"),
        ("accounts.view_user", "Ver usuarios"),
        ("accounts.change_user", "Editar usuarios"),
    ]),
]


def catalog_permission_codenames():
    return [codename for _, items in PERMISSION_CATALOG for codename, _ in items]


class AccessRoleForm(forms.ModelForm):
    permissions = forms.ModelMultipleChoiceField(
        queryset=Permission.objects.none(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
        label="Permisos",
    )

    class Meta:
        model = Group
        fields = ["name", "permissions"]
        labels = {"name": "Nombre del rol"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        pairs = [item.split(".", 1) for item in catalog_permission_codenames()]
        query = Permission.objects.none()
        for app_label, codename in pairs:
            query |= Permission.objects.filter(content_type__app_label=app_label, codename=codename)
        self.fields["permissions"].queryset = query.select_related("content_type").order_by(
            "content_type__app_label",
            "codename",
        )


class UserRoleAssignmentForm(forms.Form):
    user = forms.ModelChoiceField(queryset=get_user_model().objects.order_by("username"), label="Usuario")
    groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.order_by("name"),
        required=False,
        widget=forms.CheckboxSelectMultiple,
        label="Roles",
    )
