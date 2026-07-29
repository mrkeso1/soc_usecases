#!/bin/sh
set -eu

backup_dir="${BACKUP_DIR:-/backups}"
source_database="${POSTGRES_DB:?POSTGRES_DB es obligatorio}"
target_database="${POSTGRES_RESTORE_DB:-${source_database}_restore}"
restore_file="${RESTORE_FILE:?Definí RESTORE_FILE con el nombre del archivo .dump}"
host="${POSTGRES_HOST:-db}"
port="${POSTGRES_PORT:-5432}"
user="${POSTGRES_USER:?POSTGRES_USER es obligatorio}"
expected_confirmation="RESTORE_${target_database}"

case "${restore_file}" in
    */*|*\\*)
        echo "RESTORE_FILE debe contener sólo el nombre del archivo, sin rutas." >&2
        exit 2
        ;;
    *.dump) ;;
    *)
        echo "RESTORE_FILE debe terminar en .dump." >&2
        exit 2
        ;;
esac

source_path="${backup_dir}/${restore_file}"
checksum_path="${source_path}.sha256"

if [ ! -s "${source_path}" ]; then
    echo "No existe el backup o está vacío: ${source_path}" >&2
    exit 3
fi

if [ "${RESTORE_CONFIRM:-}" != "${expected_confirmation}" ]; then
    echo "Confirmación inválida. Definí RESTORE_CONFIRM=${expected_confirmation}" >&2
    exit 4
fi

if [ "${target_database}" = "${source_database}" ] && [ "${ALLOW_PRODUCTION_RESTORE:-0}" != "1" ]; then
    echo "Restore sobre la base productiva bloqueado." >&2
    echo "Usá una base paralela o definí ALLOW_PRODUCTION_RESTORE=1 después de detener la aplicación." >&2
    exit 5
fi

export PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD es obligatorio}"

if [ -f "${checksum_path}" ]; then
    echo "Verificando checksum..."
    (
        cd "${backup_dir}"
        sha256sum -c "$(basename "${checksum_path}")"
    )
fi

pg_restore --list "${source_path}" >/dev/null

echo "Restaurando ${restore_file} en ${target_database}..."
dropdb \
    --host="${host}" \
    --port="${port}" \
    --username="${user}" \
    --force \
    --if-exists \
    "${target_database}"
createdb \
    --host="${host}" \
    --port="${port}" \
    --username="${user}" \
    "${target_database}"
pg_restore \
    --host="${host}" \
    --port="${port}" \
    --username="${user}" \
    --dbname="${target_database}" \
    --no-owner \
    --no-acl \
    --exit-on-error \
    "${source_path}"

table_count="$(
    psql \
        --host="${host}" \
        --port="${port}" \
        --username="${user}" \
        --dbname="${target_database}" \
        --tuples-only \
        --no-align \
        --command="SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname = 'public';"
)"

if [ "${table_count:-0}" -le 0 ]; then
    echo "La restauración terminó sin tablas públicas; se considera inválida." >&2
    exit 6
fi

echo "Restore validado: ${target_database} contiene ${table_count} tablas públicas."
