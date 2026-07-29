#!/bin/sh
set -eu

umask 077

backup_dir="${BACKUP_DIR:-/backups}"
retention_days="${POSTGRES_BACKUP_RETENTION_DAYS:-14}"
database="${POSTGRES_DB:?POSTGRES_DB es obligatorio}"
host="${POSTGRES_HOST:-db}"
port="${POSTGRES_PORT:-5432}"
user="${POSTGRES_USER:?POSTGRES_USER es obligatorio}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
filename="${database}_${timestamp}.dump"
temporary="${backup_dir}/.${filename}.partial"
destination="${backup_dir}/${filename}"
checksum="${destination}.sha256"
lock_dir="${backup_dir}/.backup.lock"

case "${retention_days}" in
    ''|*[!0-9]*)
        echo "POSTGRES_BACKUP_RETENTION_DAYS debe ser un entero no negativo." >&2
        exit 2
        ;;
esac

mkdir -p "${backup_dir}"
if ! mkdir "${lock_dir}" 2>/dev/null; then
    echo "Ya hay otro backup PostgreSQL en ejecución." >&2
    exit 3
fi

cleanup() {
    rm -f "${temporary}"
    rmdir "${lock_dir}" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

export PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD es obligatorio}"

echo "Esperando PostgreSQL en ${host}:${port}..."
until pg_isready --host="${host}" --port="${port}" --username="${user}" --dbname="${database}" >/dev/null 2>&1; do
    sleep 2
done

echo "Generando ${destination}..."
pg_dump \
    --host="${host}" \
    --port="${port}" \
    --username="${user}" \
    --dbname="${database}" \
    --format=custom \
    --compress=6 \
    --no-owner \
    --no-acl \
    --file="${temporary}"

test -s "${temporary}"
pg_restore --list "${temporary}" >/dev/null
mv "${temporary}" "${destination}"

(
    cd "${backup_dir}"
    sha256sum "${filename}" > "${filename}.sha256"
)

echo "Backup validado: ${destination}"
cat "${checksum}"

if [ "${retention_days}" -gt 0 ]; then
    find "${backup_dir}" -maxdepth 1 -type f -name "${database}_*.dump" -mtime "+${retention_days}" -print -delete
    find "${backup_dir}" -maxdepth 1 -type f -name "${database}_*.dump.sha256" -mtime "+${retention_days}" -print -delete
fi

