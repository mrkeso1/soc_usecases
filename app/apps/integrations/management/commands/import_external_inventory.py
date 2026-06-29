import csv
import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from apps.integrations.inventory import sync_inventory_records


def _load_json(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise CommandError(f"JSON invalido: {exc}") from exc

    if isinstance(data, dict):
        for key in ("records", "items", "usecases", "use_cases"):
            if isinstance(data.get(key), list):
                data = data[key]
                break

    if not isinstance(data, list):
        raise CommandError("El JSON debe ser una lista o un objeto con records/items/usecases.")

    records = []
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise CommandError(f"Registro JSON {index}: debe ser un objeto.")
        records.append(item)
    return records


def _load_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def load_external_inventory_file(path: str) -> list[dict]:
    file_path = Path(path)
    if not file_path.exists():
        raise CommandError(f"No existe el archivo: {file_path}")

    suffix = file_path.suffix.lower()
    if suffix == ".json":
        return _load_json(file_path)
    if suffix == ".csv":
        return _load_csv(file_path)

    raise CommandError("Formato no soportado. Usa .json o .csv.")


class Command(BaseCommand):
    help = "Importa inventario externo en JSON/CSV usando el adaptador de integraciones."

    def add_arguments(self, parser):
        parser.add_argument("path", help="Ruta al archivo .json o .csv exportado por la app externa.")
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Valida y muestra el resumen sin guardar cambios.",
        )
        parser.add_argument(
            "--no-update",
            action="store_true",
            help="No actualiza casos existentes; solo crea nuevos.",
        )

    def handle(self, *args, **options):
        records = load_external_inventory_file(options["path"])
        result = sync_inventory_records(
            records,
            update_existing=not options["no_update"],
            commit=not options["dry_run"],
        )

        prefix = "DRY-RUN " if options["dry_run"] else ""
        self.stdout.write(self.style.SUCCESS(f"{prefix}Importacion de inventario externo finalizada"))
        self.stdout.write(f"Registros leidos: {len(records)}")
        self.stdout.write(f"Creados: {result.created}")
        self.stdout.write(f"Actualizados: {result.updated}")
        self.stdout.write(f"Omitidos: {result.skipped}")

        if result.errors:
            self.stdout.write(self.style.WARNING("Errores/advertencias:"))
            for error in result.errors:
                self.stdout.write(self.style.WARNING(f"- {error}"))
