import ast
import csv
import io
import ipaddress
from datetime import datetime
from pathlib import Path

import requests
from django.utils import timezone

from .base import InventoryRecord


def _clean(value):
    return (value or "").strip()


def _valid_ip(value):
    value = _clean(value)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _parse_datetime(value):
    value = _clean(value)
    if not value:
        return None
    for parser in (datetime.fromisoformat,):
        try:
            parsed = parser(value.replace("Z", "+00:00"))
            return timezone.make_aware(parsed) if timezone.is_naive(parsed) else parsed
        except ValueError:
            continue
    return None


def _groups(value):
    value = _clean(value)
    if not value:
        return ""
    try:
        parsed = ast.literal_eval(value)
    except (ValueError, SyntaxError):
        return value
    return ", ".join(str(item) for item in parsed) if isinstance(parsed, list) else value


class SiemCsvConnector:
    def __init__(
        self,
        *,
        path=None,
        url=None,
        text=None,
        timeout=30,
        use_environment_proxy=False,
    ):
        if not path and not url and text is None:
            raise ValueError("Se requiere una ruta, URL o contenido para el inventario SIEM.")
        self.path = Path(path) if path else None
        self.url = url
        self.text = text
        self.timeout = timeout
        self.use_environment_proxy = use_environment_proxy

    def _read_text(self):
        if self.text is not None:
            return self.text
        if self.path:
            return self.path.read_text(encoding="utf-8-sig")
        with requests.Session() as session:
            session.trust_env = self.use_environment_proxy
            response = session.get(self.url, timeout=self.timeout)
            response.raise_for_status()
            return response.content.decode("utf-8-sig")

    def collect(self):
        text = self._read_text()
        header = text.splitlines()[0] if text.splitlines() else ""
        delimiter = ";" if header.count(";") >= header.count(",") else ","
        rows = csv.DictReader(io.StringIO(text), delimiter=delimiter)
        headers = set(rows.fieldnames or [])
        supported = {"Ip-Hostname", "Resolved-Hostname", "ds_name", "ds_ip"}
        if not headers.intersection(supported):
            raise ValueError(
                "El CSV SIEM no contiene una columna identificadora compatible "
                "(Ip-Hostname, Resolved-Hostname, ds_name o ds_ip)."
            )
        records = []
        for index, row in enumerate(rows, start=1):
            device_type = _clean(row.get("TipoDispositivo") or row.get("ds_tipo"))
            identifier = _clean(
                row.get("Resolved-Hostname")
                or row.get("Ip-Hostname")
                or row.get("ds_name")
                or row.get("ds_ip")
            )
            if not identifier:
                continue
            ip = _valid_ip(row.get("ds_ip") or row.get("Ip-Hostname"))
            fqdn = "" if ip else identifier.lower().rstrip(".")
            hostname = fqdn.split(".", 1)[0] if fqdn else ""
            records.append(
                InventoryRecord(
                    external_id=f"{device_type}:{identifier}".lower(),
                    hostname=hostname,
                    fqdn=fqdn,
                    ip_address=ip,
                    os_name=_clean(row.get("ds_so")),
                    groups=_groups(row.get("GruposAsociados") or row.get("ds_grupo_esm")),
                    server_type_hint=device_type,
                    observed_at=_parse_datetime(row.get("UltimaFechaIngesta") or row.get("last_sens")),
                    raw_data={key: value for key, value in row.items() if key},
                )
            )
        return records
