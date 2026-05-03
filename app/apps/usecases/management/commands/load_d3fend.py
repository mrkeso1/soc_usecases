import csv
from io import StringIO

import requests
from django.core.management.base import BaseCommand

from apps.usecases.models import D3Fend


D3FEND_CSV_URL = "https://d3fend.mitre.org/ontologies/d3fend/1.4.0/d3fend.csv"


class Command(BaseCommand):
    help = "Carga D3FEND desde el CSV oficial"

    def handle(self, *args, **options):
        response = requests.get(D3FEND_CSV_URL, timeout=120)
        response.raise_for_status()

        content = response.text
        reader = csv.DictReader(StringIO(content))

        created = 0
        updated = 0
        skipped = 0

        for row in reader:
            # Probamos varias columnas posibles porque el CSV puede cambiar levemente
            code = (
                row.get("ID")
                or row.get("id")
                or row.get("d3fend-id")
                or row.get("d3fend_id")
                or row.get("code")
                or ""
            ).strip()

            name = (
                row.get("Name")
                or row.get("name")
                or row.get("label")
                or ""
            ).strip()

            category = (
                row.get("Type")
                or row.get("type")
                or row.get("Category")
                or row.get("category")
                or ""
            ).strip()

            # Nos quedamos solo con IDs que parecen técnicas/capacidades D3FEND
            if not code or not code.startswith("D3"):
                skipped += 1
                continue

            _, was_created = D3Fend.objects.update_or_create(
                code=code,
                defaults={
                    "name": name,
                    "category": category,
                },
            )

            if was_created:
                created += 1
            else:
                updated += 1

        self.stdout.write(self.style.SUCCESS("Carga D3FEND finalizada"))
        self.stdout.write(f"Creados: {created}")
        self.stdout.write(f"Actualizados: {updated}")
        self.stdout.write(f"Omitidos: {skipped}")