import ast
import csv
import io
import ipaddress
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def _is_linux_device(device_type):
    normalized = _clean(device_type).casefold()
    return any(token in normalized for token in ("linux", "rhlinux", "aix", "unix"))


def _command_output(command, timeout):
    executable = shutil.which(command[0])
    if not executable:
        return ""
    try:
        completed = subprocess.run(
            [executable, *command[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return f"{completed.stdout or ''}\n{completed.stderr or ''}"


def resolve_hostname_from_ip(ip_address, *, timeout=3):
    """Replica el reverse DNS del hotmap original con límites de tiempo."""
    ip = _valid_ip(ip_address)
    if not ip:
        return ""

    output = _command_output(["getent", "hosts", ip], timeout)
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and _valid_ip(parts[0]) == ip:
            hostname = parts[1].strip().lower().rstrip(".")
            if hostname and hostname != ip:
                return hostname

    output = _command_output(["nslookup", ip], timeout)
    for line in output.splitlines():
        match = re.search(r"(?:name\s*=|name:)\s*(\S+)", line, re.IGNORECASE)
        if match:
            hostname = match.group(1).strip().lower().rstrip(".")
            if hostname and hostname != ip:
                return hostname

    output = _command_output(["host", ip], timeout)
    match = re.search(r"domain name pointer\s+(\S+)", output, re.IGNORECASE)
    if match:
        hostname = match.group(1).strip().lower().rstrip(".")
        if hostname and hostname != ip:
            return hostname
    return ""


class SiemCsvConnector:
    def __init__(
        self,
        *,
        path=None,
        url=None,
        text=None,
        timeout=30,
        use_environment_proxy=False,
        resolve_linux_names=True,
        dns_workers=12,
        dns_timeout=3,
    ):
        if not path and not url and text is None:
            raise ValueError("Se requiere una ruta, URL o contenido para el inventario SIEM.")
        self.path = Path(path) if path else None
        self.url = url
        self.text = text
        self.timeout = timeout
        self.use_environment_proxy = use_environment_proxy
        self.resolve_linux_names = resolve_linux_names
        self.dns_workers = max(1, min(int(dns_workers), 32))
        self.dns_timeout = max(1, int(dns_timeout))

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
        source_rows = list(rows)
        resolved_names = {}
        linux_ips = {
            ip
            for row in source_rows
            if _is_linux_device(row.get("TipoDispositivo") or row.get("ds_tipo"))
            if (ip := _valid_ip(row.get("ds_ip") or row.get("Ip-Hostname")))
        }
        if self.resolve_linux_names and linux_ips:
            with ThreadPoolExecutor(max_workers=self.dns_workers) as executor:
                futures = {
                    executor.submit(
                        resolve_hostname_from_ip,
                        ip,
                        timeout=self.dns_timeout,
                    ): ip
                    for ip in linux_ips
                }
                for future in as_completed(futures):
                    resolved_names[futures[future]] = future.result()

        records = []
        for index, row in enumerate(source_rows, start=1):
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
            resolved_hostname = resolved_names.get(ip, "") if ip else ""
            fqdn = resolved_hostname or ("" if ip else identifier.lower().rstrip("."))
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
                    raw_data={
                        **{key: value for key, value in row.items() if key},
                        "dns_resolution_attempted": bool(
                            ip and self.resolve_linux_names and _is_linux_device(device_type)
                        ),
                        "resolved_hostname": resolved_hostname,
                    },
                )
            )
        return records
