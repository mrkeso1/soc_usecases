#!/bin/sh
set -e

mkdir -p /logs /app/media /app/staticfiles
chown -R app:app /logs /app/media /app/staticfiles 2>/dev/null || true

exec su -s /bin/sh app -c "$*"
