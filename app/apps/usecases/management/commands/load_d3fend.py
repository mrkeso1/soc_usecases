import csv
from io import StringIO

import requests
from django.core.management.base import BaseCommand

from apps.usecases.models import D3Fend

"""
para actualizar solo defend detect:
python manage.py load_d3fend

para actualizar todos los módulos:
python manage.py load_d3fend --all
"""


D3FEND_CSV_URL = "https://d3fend.mitre.org/ontologies/d3fend/1.4.0/d3fend.csv"


def clean(value):
    return (value or "").strip()


def get_first(row, *keys):
    """
    Busca el primer valor disponible en varias columnas posibles.
    Sirve porque MITRE puede cambiar nombres de columnas entre versiones.
    """
    for key in keys:
        value = row.get(key)
        if value:
            return clean(value)
    return ""


class Command(BaseCommand):
    help = "Carga D3FEND desde el CSV oficial. Por defecto carga solo el módulo Detect."

    def add_arguments(self, parser):
        parser.add_argument(
            "--all",
            action="store_true",
            help="Carga todos los módulos de D3FEND, no solo Detect.",
        )

        parser.add_argument(
            "--url",
            type=str,
            default=D3FEND_CSV_URL,
            help="URL del CSV de D3FEND.",
        )

    def handle(self, *args, **options):
        load_all = options["all"]
        url = options["url"]

        self.stdout.write(f"Descargando D3FEND desde: {url}")

        response = requests.get(url, timeout=120)
        response.raise_for_status()

        content = response.text
        reader = csv.DictReader(StringIO(content))

        created = 0
        updated = 0
        skipped = 0
        skipped_not_detect = 0

        # Detectamos campos reales del modelo para no romper si tu modelo no tiene description/url/etc.
        model_fields = {
            field.name
            for field in D3Fend._meta.fields
        }

        for row in reader:
            # ID / código D3FEND
            code = get_first(
                row,
                "ID",
                "id",
                "D3FEND ID",
                "D3FEND_ID",
                "d3fend-id",
                "d3fend_id",
                "code",
                "Code",
            )

            # Nombre legible
            name = get_first(
                row,
                "Name",
                "name",
                "Label",
                "label",
                "Title",
                "title",
            )

            # Módulo / táctica / categoría
            category = get_first(
                row,
                "Tactic",
                "tactic",
                "Type",
                "type",
                "Category",
                "category",
                "Module",
                "module",
            )

            # Descripción, si existe en el CSV y si tu modelo la soporta
            description = get_first(
                row,
                "Description",
                "description",
                "Definition",
                "definition",
                "Comment",
                "comment",
            )

            # Algunas versiones del CSV pueden traer el ID en la primera columna
            # aunque el header tenga otro nombre raro.
            if not code:
                values = list(row.values())
                if values:
                    code = clean(values[0])

            # Algunas versiones pueden traer Detect como segunda columna y nombre como cuarta.
            if not category:
                values = list(row.values())
                if len(values) > 1:
                    category = clean(values[1])

            if not name:
                values = list(row.values())
                if len(values) > 3:
                    name = clean(values[3])

            # Validamos que sea algo D3FEND real
            if not code or not code.startswith("D3"):
                skipped += 1
                continue

            # Por defecto solo cargamos Detect
            if not load_all and category.lower() != "detect":
                skipped_not_detect += 1
                continue

            defaults = {}

            if "name" in model_fields:
                defaults["name"] = name or code

            if "category" in model_fields:
                defaults["category"] = category

            if "description" in model_fields:
                defaults["description"] = description

            _, was_created = D3Fend.objects.update_or_create(
                code=code,
                defaults=defaults,
            )

            if was_created:
                created += 1
            else:
                updated += 1

        self.stdout.write(self.style.SUCCESS("Carga D3FEND finalizada"))
        self.stdout.write(f"Creados: {created}")
        self.stdout.write(f"Actualizados: {updated}")
        self.stdout.write(f"Omitidos por ID inválido: {skipped}")
        self.stdout.write(f"Omitidos por no ser Detect: {skipped_not_detect}")