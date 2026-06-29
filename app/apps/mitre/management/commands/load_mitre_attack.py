from django.core.management.base import BaseCommand

from apps.mitre.mitre_sync import fetch_mitre_attack_enterprise, load_mitre_attack_data


class Command(BaseCommand):
    help = "Carga MITRE ATT&CK Enterprise desde el dataset oficial STIX 2.1"

    def handle(self, *args, **options):
        result = load_mitre_attack_data(fetch_mitre_attack_enterprise())
        self.stdout.write(self.style.SUCCESS("Carga ATT&CK finalizada"))
        self.stdout.write(f"Creados: {result.created}")
        self.stdout.write(f"Actualizados: {result.updated}")
        self.stdout.write(f"Omitidos: {result.skipped}")
