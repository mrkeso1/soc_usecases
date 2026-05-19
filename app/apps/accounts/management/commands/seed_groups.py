from django.contrib.auth.models import Group, Permission
from django.core.management.base import BaseCommand

from apps.accounts.roles import ADMIN_GROUP, ANALYST_GROUP, LEGACY_GROUPS, READONLY_GROUP, ROLE_GROUPS


ANALYST_PERMISSIONS = {
    "usecases.view_usecase",
    "usecases.add_usecase",
    "usecases.change_usecase",
    "usecases.view_lifecyclereview",
    "usecases.add_lifecyclereview",
    "usecases.view_mitreattack",
    "usecases.view_d3fend",
}


class Command(BaseCommand):
    help = "Crea y normaliza los grupos base del sistema: Admin, Analyst y ReadOnly"

    def _permissions_by_natural_key(self):
        permissions = {}
        for permission in Permission.objects.select_related("content_type"):
            key = f"{permission.content_type.app_label}.{permission.codename}"
            permissions[key] = permission
        return permissions

    def handle(self, *args, **options):
        groups = {}
        for group_name in ROLE_GROUPS:
            group, created = Group.objects.get_or_create(name=group_name)
            groups[group_name] = group
            if created:
                self.stdout.write(self.style.SUCCESS(f"Grupo creado: {group_name}"))
            else:
                self.stdout.write(self.style.WARNING(f"Grupo ya existe: {group_name}"))

        permissions = self._permissions_by_natural_key()
        groups[ADMIN_GROUP].permissions.set(Permission.objects.all())
        self.stdout.write(self.style.SUCCESS("Permisos asignados: Admin puede hacer todo."))

        analyst_permissions = [
            permissions[key]
            for key in sorted(ANALYST_PERMISSIONS)
            if key in permissions
        ]
        groups[ANALYST_GROUP].permissions.set(analyst_permissions)
        self.stdout.write(self.style.SUCCESS("Permisos asignados: Analyst puede crear/ver casos y modificar solo los propios."))

        groups[READONLY_GROUP].permissions.clear()
        self.stdout.write(self.style.SUCCESS("Permisos asignados: ReadOnly solo accede al dashboard."))

        removed = Group.objects.filter(name__in=LEGACY_GROUPS).delete()[0]
        if removed:
            self.stdout.write(self.style.WARNING("Grupos legacy removidos: Engineer, Reviewer."))
