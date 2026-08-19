import math
import platform
import shutil
import socket
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from .models import ServerAsset, ServerAssetDisableEvent


@dataclass(slots=True)
class NetworkDiagnosticResult:
    asset_id: int
    dns_status: str
    resolved_fqdn: str = ""
    resolved_ip_address: str | None = None
    reachability_status: str = ServerAsset.REACHABILITY_UNCHECKED
    error: str = ""


@dataclass(slots=True)
class IdentityResolutionResult:
    hostname: str = ""
    fqdn: str = ""
    ip_address: str | None = None
    error: str = ""


def resolve_observation_identity(observation):
    """Completa una observación SIEM mediante DNS directo o inverso."""
    hostname = (observation.hostname or "").strip().lower().rstrip(".")
    fqdn = (observation.fqdn or "").strip().lower().rstrip(".")
    ip_value = str(observation.ip_address or "").strip()
    try:
        is_ip = bool(ip_value and ipaddress.ip_address(ip_value))
    except ValueError:
        is_ip = False

    errors = []
    if is_ip:
        try:
            resolved_fqdn = socket.gethostbyaddr(ip_value)[0].lower().rstrip(".")
            return IdentityResolutionResult(
                hostname=resolved_fqdn.split(".", 1)[0],
                fqdn=resolved_fqdn,
                ip_address=ip_value,
            )
        except OSError as exc:
            errors.append(f"DNS inverso: {exc}")

    candidate = fqdn or hostname
    if candidate:
        try:
            addresses = socket.getaddrinfo(candidate, None, type=socket.SOCK_STREAM)
            ips = [item[4][0] for item in addresses]
            resolved_ip = next((value for value in ips if ":" not in value), ips[0] if ips else None)
            resolved_fqdn = socket.getfqdn(candidate).lower().rstrip(".")
            return IdentityResolutionResult(
                hostname=hostname or resolved_fqdn.split(".", 1)[0],
                fqdn=resolved_fqdn,
                ip_address=resolved_ip,
            )
        except OSError as exc:
            errors.append(f"DNS directo: {exc}")

    if not errors:
        errors.append("El registro no contiene un nombre o una IP utilizable.")
    return IdentityResolutionResult(
        hostname=hostname,
        fqdn=fqdn,
        ip_address=ip_value or None,
        error=" | ".join(errors),
    )


def _resolve(asset):
    candidate = f"{asset.hostname}.{asset.domain}" if asset.domain else asset.hostname
    errors = []
    try:
        addresses = socket.getaddrinfo(candidate, None, type=socket.SOCK_STREAM)
        ips = [item[4][0] for item in addresses]
        ipv4 = next((ip for ip in ips if ":" not in ip), ips[0] if ips else None)
        fqdn = socket.getfqdn(candidate).lower().rstrip(".")
        return ServerAsset.DNS_RESOLVED, fqdn, ipv4, errors
    except OSError as exc:
        errors.append(f"DNS directo: {exc}")

    fallback_ip = str(asset.ip_address or "")
    if fallback_ip:
        try:
            fqdn = socket.gethostbyaddr(fallback_ip)[0].lower().rstrip(".")
            return ServerAsset.DNS_RESOLVED, fqdn, fallback_ip, errors
        except OSError as exc:
            errors.append(f"DNS inverso: {exc}")
    return ServerAsset.DNS_FAILED, "", None, errors


def _ping(target, timeout):
    executable = shutil.which("ping")
    if not executable:
        return ServerAsset.REACHABILITY_ERROR, "La imagen no tiene instalado el comando ping."
    if platform.system().lower() == "windows":
        command = [executable, "-n", "1", "-w", str(max(1, int(timeout * 1000))), target]
    else:
        command = [executable, "-c", "1", "-W", str(max(1, math.ceil(timeout))), target]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ServerAsset.REACHABILITY_ERROR, f"Ping: {exc}"
    if completed.returncode == 0:
        return ServerAsset.REACHABILITY_REACHABLE, ""
    return ServerAsset.REACHABILITY_UNREACHABLE, ""


def diagnose_asset(asset, *, timeout=2):
    dns_status, fqdn, resolved_ip, errors = _resolve(asset)
    target = resolved_ip or str(asset.ip_address or "")
    if target:
        reachability, ping_error = _ping(target, timeout)
        if ping_error:
            errors.append(ping_error)
    else:
        reachability = ServerAsset.REACHABILITY_ERROR
        errors.append("Ping: no se obtuvo una dirección IP para verificar el equipo.")
    return NetworkDiagnosticResult(
        asset_id=asset.id,
        dns_status=dns_status,
        resolved_fqdn=fqdn,
        resolved_ip_address=resolved_ip,
        reachability_status=reachability,
        error=" | ".join(errors),
    )


def diagnose_ingestion_gaps(
    *,
    limit=500,
    workers=12,
    timeout=2,
    only_unchecked=False,
    include_disabled=False,
    include_covered=False,
    auto_disable_failures=False,
    asset_ids=None,
):
    if asset_ids is not None:
        # El diagnóstico manual debe funcionar también para excepciones Solo SIEM,
        # equipos deshabilitados y equipos que ya tienen una medición anterior.
        queryset = ServerAsset.objects.filter(id__in=asset_ids)
    else:
        queryset = ServerAsset.objects.filter(in_active_directory=True)
        if not include_covered:
            queryset = queryset.filter(in_siem=False)
        if include_disabled:
            if only_unchecked:
                queryset = queryset.filter(
                    Q(network_checked_at__isnull=True)
                    | Q(is_enabled=False)
                    | Q(is_excluded_by_rule=True)
                    | Q(reachability_status=ServerAsset.REACHABILITY_UNCHECKED)
                    | Q(reachability_status=ServerAsset.REACHABILITY_ERROR)
                )
        else:
            queryset = queryset.filter(is_enabled=True, is_excluded_by_rule=False)
            if only_unchecked:
                queryset = queryset.filter(network_checked_at__isnull=True)
    queryset = queryset.order_by(
        F("network_checked_at").asc(nulls_first=True),
        "hostname",
    )
    if limit is not None:
        queryset = queryset[:limit]
    assets = list(queryset)
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 32))) as executor:
        futures = {
            executor.submit(diagnose_asset, asset, timeout=timeout): asset.id
            for asset in assets
        }
        for future in as_completed(futures):
            results.append(future.result())

    by_id = {asset.id: asset for asset in assets}
    checked_at = timezone.now()
    for result in results:
        asset = by_id[result.asset_id]
        asset.dns_status = result.dns_status
        asset.resolved_fqdn = result.resolved_fqdn
        asset.resolved_ip_address = result.resolved_ip_address
        asset.reachability_status = result.reachability_status
        asset.network_checked_at = checked_at
        asset.network_check_error = result.error
    automatically_disabled = [
        asset
        for asset in assets
        if auto_disable_failures
        and not asset.in_siem
        and asset.is_effectively_enabled
        and (
            asset.dns_status == ServerAsset.DNS_FAILED
            or asset.reachability_status == ServerAsset.REACHABILITY_UNREACHABLE
        )
    ]
    for asset in automatically_disabled:
        asset.is_enabled = False

    update_fields = [
        "dns_status",
        "resolved_fqdn",
        "resolved_ip_address",
        "reachability_status",
        "network_checked_at",
        "network_check_error",
    ]
    if auto_disable_failures:
        update_fields.append("is_enabled")
    with transaction.atomic():
        ServerAsset.objects.bulk_update(assets, update_fields)
        ServerAssetDisableEvent.objects.bulk_create([
            ServerAssetDisableEvent(
                asset=asset,
                hostname=asset.hostname,
                actor=None,
                justification=(
                    "Deshabilitado automáticamente: "
                    + (
                        "no resolvió DNS y no respondió al ping"
                        if asset.dns_status == ServerAsset.DNS_FAILED
                        and asset.reachability_status == ServerAsset.REACHABILITY_UNREACHABLE
                        else (
                            "no resolvió DNS"
                            if asset.dns_status == ServerAsset.DNS_FAILED
                            else "no respondió al ping"
                        )
                    )
                    + " durante el diagnóstico de red."
                ),
                previous_enabled=True,
                new_enabled=False,
            )
            for asset in automatically_disabled
        ])
    return {
        "checked": len(assets),
        "dns_resolved": sum(item.dns_status == ServerAsset.DNS_RESOLVED for item in assets),
        "reachable": sum(
            item.reachability_status == ServerAsset.REACHABILITY_REACHABLE
            for item in assets
        ),
        "unreachable": sum(
            item.reachability_status == ServerAsset.REACHABILITY_UNREACHABLE
            for item in assets
        ),
        "errors": sum(
            item.reachability_status == ServerAsset.REACHABILITY_ERROR
            for item in assets
        ),
        "disabled": len(automatically_disabled),
    }
