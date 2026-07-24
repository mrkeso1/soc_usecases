import csv
import ipaddress
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.server_heatmap.models import InventoryObservation, InventorySyncRun, ServerAsset


def _clean(value):
    return (value or "").strip()


def _as_bool(value):
    return _clean(value).lower() in {"1", "true", "si", "sí", "yes"}


def _valid_ip(value):
    value = _clean(value)
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _os_family(os_name):
    normalized = _clean(os_name).lower()
    if "windows" in normalized:
        return ServerAsset.OS_WINDOWS
    if any(token in normalized for token in ("linux", "sles", "red hat", "ubuntu", "debian", "centos")):
        return ServerAsset.OS_LINUX
    if any(token in normalized for token in ("aix", "unix", "solaris")):
        return ServerAsset.OS_UNIX
    return ServerAsset.OS_UNKNOWN


def _server_type(row):
    classification = _clean(row.get("ds_grupo_clasificacion")).lower()
    ou = _clean(row.get("ds_ou")).lower()
    hostname = _clean(row.get("ds_name")).lower()
    searchable = f"{ou} {hostname}"

    if classification == "dc" or any(token in searchable for token in ("domain controller", "windows_dc")):
        return ServerAsset.TYPE_AD
    if any(token in searchable for token in ("database", "sql", "oracle", " db")):
        return ServerAsset.TYPE_DATABASE
    if any(token in searchable for token in ("file server", "fileserver", " archivos")):
        return ServerAsset.TYPE_FILESERVER
    if any(token in searchable for token in ("iis", "web")):
        return ServerAsset.TYPE_WEB
    if any(token in searchable for token in ("mail", "exchange")):
        return ServerAsset.TYPE_MAIL
    if any(token in searchable for token in ("security", "seguridad")):
        return ServerAsset.TYPE_SECURITY
    if any(token in searchable for token in ("infraestructure", "infrastructure", "network")):
        return ServerAsset.TYPE_NETWORK
    if any(token in searchable for token in ("appl", "application", "xenapp", "xendesktop", "citrix")):
        return ServerAsset.TYPE_APPLICATION
    return ServerAsset.TYPE_UNKNOWN


def _application_name(ou):
    return _clean(ou).split(">", 1)[0].strip()[:180]


def _read_rows(paths):
    for path in paths:
        if not path.exists() or path.suffix.lower() != ".csv":
            raise CommandError(f"No existe un CSV válido: {path}")
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            yield from csv.DictReader(handle, delimiter=";")


class Command(BaseCommand):
    help = "Migra directamente servidores.csv y linux.csv al mapa de servidores."

    def add_arguments(self, parser):
        parser.add_argument(
            "csv_paths",
            type=Path,
            nargs="+",
            help="Rutas a servidores.csv y linux.csv.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Valida y muestra el resultado sin guardar cambios.",
        )
        parser.add_argument(
            "--disable-missing",
            action="store_true",
            help="Deshabilita equipos importados anteriormente que ya no aparezcan en el ZIP.",
        )

    def handle(self, *args, **options):
        rows = list(_read_rows(options["csv_paths"]))
        seen = set()
        created = updated = skipped = 0

        with transaction.atomic():
            run = InventorySyncRun.objects.create(
                source=InventorySyncRun.SOURCE_LEGACY,
                metadata={"files": [path.name for path in options["csv_paths"]]},
            )
            for row in rows:
                hostname = _clean(row.get("ds_name")).lower()
                if not hostname:
                    skipped += 1
                    continue
                seen.add(hostname)
                ou = _clean(row.get("ds_ou"))
                defaults = {
                    "display_name": _clean(row.get("ds_name")),
                    "ip_address": _valid_ip(row.get("ds_ip")),
                    "os_family": _os_family(row.get("ds_so")),
                    "os_name": _clean(row.get("ds_so")),
                    "server_type": _server_type(row),
                    "application_name": _application_name(ou),
                    "environment": _clean(row.get("ambiente")),
                    "organizational_unit": ou,
                    "siem_groups": _clean(row.get("ds_grupo_esm")),
                    "inventory_source": _clean(row.get("d_source")),
                    "legacy_classification": _clean(row.get("ds_grupo_clasificacion")),
                    "in_active_directory": True,
                    "in_siem": _as_bool(row.get("ingestado")),
                    "is_enabled": True,
                    "classification_source": ServerAsset.CLASSIFICATION_MANUAL,
                }
                asset, was_created = ServerAsset.objects.update_or_create(hostname=hostname, defaults=defaults)
                InventoryObservation.objects.create(
                    sync_run=run,
                    asset=asset,
                    source=InventorySyncRun.SOURCE_LEGACY,
                    external_id=hostname,
                    hostname=hostname,
                    ip_address=defaults["ip_address"],
                    os_name=defaults["os_name"],
                    organizational_unit=ou,
                    environment=defaults["environment"],
                    groups=defaults["siem_groups"],
                    server_type_hint=defaults["legacy_classification"],
                    raw_data={key: value for key, value in row.items() if key},
                )
                created += int(was_created)
                updated += int(not was_created)

            disabled = 0
            if options["disable_missing"]:
                disabled = (
                    ServerAsset.objects.exclude(hostname__in=seen)
                    .exclude(inventory_source="")
                    .update(is_enabled=False)
                )
            run.status = InventorySyncRun.STATUS_SUCCESS
            run.finished_at = timezone.now()
            run.records_read = len(rows)
            run.assets_created = created
            run.assets_updated = updated
            run.save()
            if options["dry_run"]:
                transaction.set_rollback(True)

        mode = "SIMULACIÓN" if options["dry_run"] else "IMPORTACIÓN"
        self.stdout.write(
            self.style.SUCCESS(
                f"{mode}: {len(rows)} filas; {created} nuevos; {updated} actualizados; "
                f"{skipped} omitidos; {disabled} deshabilitados."
            )
        )
