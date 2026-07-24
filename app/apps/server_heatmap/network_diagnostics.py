import math
import platform
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from django.utils import timezone

from .models import ServerAsset


@dataclass(slots=True)
class NetworkDiagnosticResult:
    asset_id: int
    dns_status: str
    resolved_fqdn: str = ""
    resolved_ip_address: str | None = None
    reachability_status: str = ServerAsset.REACHABILITY_UNCHECKED
    error: str = ""


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
        reachability = ServerAsset.REACHABILITY_UNCHECKED
    return NetworkDiagnosticResult(
        asset_id=asset.id,
        dns_status=dns_status,
        resolved_fqdn=fqdn,
        resolved_ip_address=resolved_ip,
        reachability_status=reachability,
        error=" | ".join(errors),
    )


def diagnose_ingestion_gaps(*, limit=500, workers=12, timeout=2, only_unchecked=False):
    queryset = ServerAsset.objects.filter(
        is_enabled=True,
        in_active_directory=True,
        in_siem=False,
    )
    if only_unchecked:
        queryset = queryset.filter(network_checked_at__isnull=True)
    assets = list(queryset.order_by("hostname")[:limit])
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
    ServerAsset.objects.bulk_update(
        assets,
        [
            "dns_status",
            "resolved_fqdn",
            "resolved_ip_address",
            "reachability_status",
            "network_checked_at",
            "network_check_error",
        ],
    )
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
    }
