import re
import time
from urllib.parse import quote

import requests
from django.core.management.base import BaseCommand
from django.db import transaction

from apps.mitre.models import D3Fend


D3FEND_BASE_URL = "https://d3fend.mitre.org"
D3FEND_CODE_RE = re.compile(r"\bD3-[A-Z0-9]+\b", re.IGNORECASE)

REQUEST_HEADERS = {
    "User-Agent": "SOC Use Cases Manager - D3FEND code normalizer/1.0",
    "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
}


KNOWN_FALLBACK_CODES = {
    # Fallbacks mínimos para los casos más comunes si la página/API no responde.
    # El comando intenta primero resolverlo online desde MITRE D3FEND.
    "accessmediation": "D3-AMED",
    "administrativenetworkactivityanalysis": "D3-ANAA",
    "emulatedfileanalysis": "D3-EFA",
    "networktrafficanalysis": "D3-NTA",
    "networktrafficsignatureanalysis": "D3-NTSA",
    "filehashreputationanalysis": "D3-FHRA",
    "fileanalysis": "D3-FA",
    "dynamicanalysis": "D3-DA",
    "filecontentanalysis": "D3-FCA",
    "filehashing": "D3-FH",
    "domainnamereputationanalysis": "D3-DNRA",
    "ipreputationanalysis": "D3-IPRA",
    "urlreputationanalysis": "D3-URA",
    "urlanalysis": "D3-UA",
    "messageanalysis": "D3-MA",
    "sendermtareputationanalysis": "D3-SMRA",
    "senderreputationanalysis": "D3-SRA",
    "certificateanalysis": "D3-CA",
    "activecertificateanalysis": "D3-ACA",
    "passivecertificateanalysis": "D3-PCA",
    "connectionattemptanalysis": "D3-CAA",
    "dnstrafficanalysis": "D3-DNSTA",
    "applicationprotocolcommandanalysis": "D3-APCA",
    "clientserverpayloadprofiling": "D3-CSPP",
    "inboundsessionvolumeanalysis": "D3-ISVA",
    "ipctrafficanalysis": "D3-IPCTA",
    "perhostdownloaduploadratioanalysis": "D3-PHDURA",
    "protocolmetadataanomalydetection": "D3-PMAD",
    "relaypatternanalysis": "D3-RPA",
    "remoteterminalsessiondetection": "D3-RTSD",
    "rpctrafficanalysis": "D3-RTAM",
    "userbehavioranalysis": "D3-UBA",
    "authenticationalertthresholding": "D3-AET",
    "authenticationeventthresholding": "D3-AET",
    "authorizationeventthresholding": "D3-AZT",
    "domainaccountmonitoring": "D3-DAM",
    "localaccountmonitoring": "D3-LAM",
    "sessiondurationanalysis": "D3-SDA",
    "websessionactivityanalysis": "D3-WSAA",
}


def _compact_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())


def _label_to_camel(value: str) -> str:
    value = str(value or "").strip()
    value = value.replace("d3f:", "")
    value = re.sub(r"[^A-Za-z0-9]+", " ", value)
    return "".join(part[:1].upper() + part[1:] for part in value.split())


def _candidate_slugs(d3fend: D3Fend) -> list[str]:
    values = []

    for raw_value in [d3fend.code, d3fend.name]:
        value = str(raw_value or "").strip()
        if not value or D3FEND_CODE_RE.fullmatch(value):
            continue

        value = value.replace("d3f:", "").strip()
        values.append(value)

        camel = _label_to_camel(value)
        if camel:
            values.append(camel)

    unique = []
    seen = set()

    for value in values:
        key = value.casefold()
        if not value or key in seen:
            continue
        seen.add(key)
        unique.append(value)

    return unique


def _urls_for_slug(slug: str) -> list[str]:
    subject = quote(f"d3f:{slug}", safe="")
    return [
        f"{D3FEND_BASE_URL}/api/technique/{subject}.json",
        f"{D3FEND_BASE_URL}/technique/{subject}/",
    ]


class Command(BaseCommand):
    help = (
        "Normaliza códigos D3FEND guardados como slugs internos "
        "AdministrativeNetworkActivityAnalysis -> D3-ANAA, etc."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help="Limita la cantidad de registros a procesar. Útil para probar.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Muestra qué cambiaría sin guardar cambios.",
        )
        parser.add_argument(
            "--sleep",
            type=float,
            default=0.08,
            help="Pausa entre requests a MITRE D3FEND.",
        )
        parser.add_argument(
            "--timeout",
            type=int,
            default=30,
            help="Timeout en segundos por request.",
        )
        parser.add_argument(
            "--no-fallback-map",
            action="store_true",
            help="No usar fallback local si no se puede resolver online.",
        )

    def handle(self, *args, **options):
        qs = D3Fend.objects.exclude(code__istartswith="D3-").order_by("code", "name")

        limit = options.get("limit") or 0
        if limit > 0:
            qs = qs[:limit]

        total = len(qs) if isinstance(qs, list) else qs.count()
        self.stdout.write(f"D3FEND con código no oficial a procesar: {total}")

        normalized = 0
        merged = 0
        unresolved = 0
        unchanged = 0
        errors = 0

        for d3fend in qs:
            old_code = d3fend.code

            try:
                official_code, source = self._resolve_official_code(d3fend, options)
            except Exception as exc:
                errors += 1
                self.stdout.write(self.style.ERROR(f"ERROR {old_code}: {exc}"))
                continue

            if not official_code:
                unresolved += 1
                self.stdout.write(self.style.WARNING(f"NO RESUELTO: {old_code} - {d3fend.name}"))
                continue

            if old_code.upper() == official_code.upper():
                unchanged += 1
                continue

            if options.get("dry_run"):
                normalized += 1
                self.stdout.write(f"DRY-RUN: {old_code} -> {official_code} ({d3fend.name}) [{source}]")
            else:
                result = self._apply_code_change(d3fend, official_code)
                if result == "merged":
                    merged += 1
                else:
                    normalized += 1
                self.stdout.write(self.style.SUCCESS(f"{old_code} -> {official_code} ({d3fend.name}) [{source}]"))

            sleep_seconds = options.get("sleep") or 0
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("Normalización D3FEND finalizada"))
        self.stdout.write(f"Normalizados: {normalized}")
        self.stdout.write(f"Fusionados con registros existentes: {merged}")
        self.stdout.write(f"Sin cambios: {unchanged}")
        self.stdout.write(f"No resueltos: {unresolved}")
        self.stdout.write(f"Errores: {errors}")
        self.stdout.write(
            f"Restantes sin D3-: {D3Fend.objects.exclude(code__istartswith='D3-').count()}"
        )

    def _resolve_official_code(self, d3fend: D3Fend, options) -> tuple[str, str]:
        timeout = options.get("timeout") or 30
        slugs = _candidate_slugs(d3fend)

        for slug in slugs:
            for url in _urls_for_slug(slug):
                code = self._fetch_code_from_url(url, timeout)
                if code:
                    return code, url

        if not options.get("no_fallback_map"):
            for value in [d3fend.code, d3fend.name, *slugs]:
                code = KNOWN_FALLBACK_CODES.get(_compact_key(value))
                if code:
                    return code, "fallback-map"

        return "", ""

    def _fetch_code_from_url(self, url: str, timeout: int) -> str:
        response = requests.get(url, headers=REQUEST_HEADERS, timeout=timeout)

        if response.status_code == 404:
            return ""

        response.raise_for_status()

        matches = D3FEND_CODE_RE.findall(response.text or "")
        if not matches:
            return ""

        # En la página/API de cada técnica, el primer código D3-XXX corresponde
        # al identificador oficial de esa técnica.
        return matches[0].upper()

    @transaction.atomic
    def _apply_code_change(self, d3fend: D3Fend, official_code: str) -> str:
        existing = D3Fend.objects.filter(code__iexact=official_code).exclude(pk=d3fend.pk).first()

        if existing:
            self._merge_records(source=d3fend, target=existing)
            return "merged"

        d3fend.code = official_code
        d3fend.save(update_fields=["code"])
        return "updated"

    def _merge_records(self, source: D3Fend, target: D3Fend):
        if hasattr(target, "related_attacks"):
            target.related_attacks.add(*source.related_attacks.all())

        if hasattr(target, "use_cases"):
            target.use_cases.add(*source.use_cases.all())

        changed_fields = []

        if not target.name and source.name:
            target.name = source.name
            changed_fields.append("name")

        if not target.category and source.category:
            target.category = source.category
            changed_fields.append("category")

        if hasattr(target, "description") and not target.description and getattr(source, "description", ""):
            target.description = source.description
            changed_fields.append("description")

        if changed_fields:
            target.save(update_fields=changed_fields)

        source.delete()
