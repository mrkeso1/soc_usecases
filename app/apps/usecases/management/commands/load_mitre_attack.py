import requests
from django.core.management.base import BaseCommand

from apps.usecases.models import MitreAttack


ATTACK_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


class Command(BaseCommand):
    help = "Carga MITRE ATT&CK Enterprise desde el dataset oficial STIX 2.1"

    def handle(self, *args, **options):
        resp = requests.get(ATTACK_ENTERPRISE_URL, timeout=120)
        resp.raise_for_status()
        data = resp.json()

        created = 0
        updated = 0
        skipped = 0

        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
                continue

            ext_refs = obj.get("external_references", [])
            attack_id = None
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id")
                    break

            if not attack_id:
                skipped += 1
                continue

            name = obj.get("name", "").strip()
            tactics = obj.get("kill_chain_phases", [])
            tactic_names = []
            for phase in tactics:
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactic_names.append(phase.get("phase_name", "").replace("-", " ").title())

            tactic_value = ", ".join(sorted(set(filter(None, tactic_names))))

            item, was_created = MitreAttack.objects.update_or_create(
                external_id=attack_id,
                defaults={
                    "name": name,
                    "tactic": tactic_value,
                },
            )
            if was_created:
                created += 1
            else:
                updated += 1

        self.stdout.write(self.style.SUCCESS("Carga ATT&CK finalizada"))
        self.stdout.write(f"Creados: {created}")
        self.stdout.write(f"Actualizados: {updated}")
        self.stdout.write(f"Omitidos: {skipped}")