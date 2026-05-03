from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group


GROUPS = [
    "Admin",
    "Engineer",
    "Reviewer",
    "Analyst",
    "ReadOnly",
]


class Command(BaseCommand):
    help = "Crea los grupos base del sistema"

    def handle(self, *args, **options):
        for group_name in GROUPS:
            group, created = Group.objects.get_or_create(name=group_name)
            if created:
                self.stdout.write(self.style.SUCCESS(f"Grupo creado: {group_name}"))
            else:
                self.stdout.write(self.style.WARNING(f"Grupo ya existe: {group_name}"))