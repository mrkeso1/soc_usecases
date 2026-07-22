import csv
from dataclasses import dataclass
from io import StringIO

from django.db import transaction

from .models import D3Fend, MitreAttack, MitreAttackTactic


HEADERS = ("marco", "tipo", "id", "nombre", "descripcion_original", "descripcion_castellano")
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class TranslationImportResult:
    updated: int
    unchanged: int
    unknown: int


def export_translation_catalog() -> str:
    output = StringIO(newline="")
    writer = csv.writer(output, delimiter=";", lineterminator="\r\n")
    writer.writerow(HEADERS)
    for item in MitreAttackTactic.objects.order_by("external_id"):
        writer.writerow(("ATT&CK", "tactica", item.external_id, item.name, item.description, item.translated_description))
    for item in MitreAttack.objects.order_by("external_id"):
        item_type = "subtecnica" if "." in item.external_id else "tecnica"
        writer.writerow(("ATT&CK", item_type, item.external_id, item.name, item.description, item.translated_description))
    for item in D3Fend.objects.order_by("code"):
        writer.writerow(("D3FEND", "tecnica", item.code, item.name, item.description, item.translated_description))
    return output.getvalue()


def import_translation_catalog(uploaded_file) -> TranslationImportResult:
    if uploaded_file.size > MAX_UPLOAD_BYTES:
        raise ValueError("El archivo supera el máximo permitido de 10 MB.")
    try:
        text = uploaded_file.read().decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("El archivo debe estar guardado como CSV UTF-8.") from exc

    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=";,\t")
    except csv.Error:
        dialect = csv.excel
        dialect.delimiter = ";"
    reader = csv.DictReader(StringIO(text), dialect=dialect)
    if tuple(reader.fieldnames or ()) != HEADERS:
        raise ValueError("Las columnas del archivo no coinciden con el catálogo exportado.")

    lookups = {
        "tactica": {obj.external_id: obj for obj in MitreAttackTactic.objects.all()},
        "attack": {obj.external_id: obj for obj in MitreAttack.objects.all()},
        "d3fend": {obj.code: obj for obj in D3Fend.objects.all()},
    }
    updated = unchanged = unknown = 0
    with transaction.atomic():
        for row in reader:
            framework = (row.get("marco") or "").strip().upper()
            object_type = (row.get("tipo") or "").strip().lower()
            external_id = (row.get("id") or "").strip()
            translated = (row.get("descripcion_castellano") or "").strip()
            if framework == "D3FEND":
                obj = lookups["d3fend"].get(external_id)
            elif object_type == "tactica":
                obj = lookups["tactica"].get(external_id)
            else:
                obj = lookups["attack"].get(external_id)
            if obj is None:
                unknown += 1
                continue
            if obj.translated_description == translated:
                unchanged += 1
                continue
            obj.translated_description = translated
            obj.save(update_fields=["translated_description"])
            updated += 1
    return TranslationImportResult(updated=updated, unchanged=unchanged, unknown=unknown)
