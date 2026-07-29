# Transición de Producción

Este documento es acumulativo. Cada mejora nueva debe actualizar esta guía para
evitar cambios manuales dispersos en producción.

## Contrato actual de producción

- El archivo operativo se llama `docker-compose.yml`.
- Los servicios existentes son `db`, `web` y `mitre_scheduler`.
- Los contenedores usan las redes `internal` y `web`.
- La red `web` es externa y conecta con el reverse proxy.
- `web` monta `./app:/app` y `./logs:/logs`.
- Las variables de proxy se pasan en mayúsculas y minúsculas.
- Los contenedores deben heredar el DNS corporativo del host; no configurar
  `8.8.8.8` ni `1.1.1.1`.
- La configuración Django vigente es `app/config/settings.py`.
- Las variables nuevas deben tener valores predeterminados compatibles.
- No se debe volver a mantener un segundo archivo de settings de producción.

## Política para cambios nuevos

Cada funcionalidad debe indicar:

1. archivos de código modificados;
2. migraciones requeridas;
3. variables nuevas de `.env`;
4. cambios de `docker-compose.yml`;
5. comandos de despliegue;
6. validación y rollback.

Cuando una variable sea opcional, la aplicación debe arrancar aunque todavía no
esté definida en producción.

## Variables acumuladas pendientes de incorporar

```env
# Backup PostgreSQL
POSTGRES_BACKUP_RETENTION_DAYS=14
BACKUP_UID=1000
BACKUP_GID=1000

# Resolución de Linux informado por IP en SIEM
SERVER_INVENTORY_SIEM_RESOLVE_LINUX_NAMES=1
SERVER_INVENTORY_DNS_WORKERS=12
SERVER_INVENTORY_DNS_TIMEOUT=3

# Observabilidad y alertas exclusivamente internas.
OPS_JSON_LOGS=1
OPS_COVERAGE_DROP_THRESHOLD=5
OPS_DNS_FAILURE_THRESHOLD=20
OPS_RESOLVED_ALERT_RETENTION_DAYS=180
ADMIN_RATE_LIMIT_RETENTION_DAYS=7

# Cola interna de inventario en PostgreSQL.
SERVER_INVENTORY_JOB_POLL_SECONDS=5
SERVER_INVENTORY_JOB_LEASE_SECONDS=300
SERVER_INVENTORY_JOB_HEARTBEAT_SECONDS=30
SERVER_INVENTORY_JOB_MAX_ATTEMPTS=3

# Protección de acciones administrativas (PostgreSQL).
ADMIN_ACTION_RATE_LIMIT_WINDOW_SECONDS=60
ADMIN_ACTION_RATE_LIMIT_SYNC=3
ADMIN_ACTION_RATE_LIMIT_MUTATION=30
```

Las variables son opcionales: el código contiene estos mismos valores
predeterminados. Definirlas en `.env` hace explícita la configuración productiva.

## Servicio interno de trabajos de inventario

La cola usa la misma base PostgreSQL de Django. No requiere Redis, Celery,
RabbitMQ, correo, webhooks ni servicios de terceros.

En el `docker-compose.yml` real de producción, agregar este servicio junto a
`web` y `mitre_scheduler`. Conserva los mismos volúmenes, proxy y DNS
corporativo que ya utiliza la aplicación:

```yaml
  server_inventory_worker:
    build:
      context: .
      dockerfile: docker/django/Dockerfile
    container_name: soc_server_inventory_worker
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - ./app:/app
      - ./logs:/logs
    environment:
      LOG_DIR: ${LOG_DIR:-/logs}
      HTTP_PROXY: ${HTTP_PROXY:-}
      HTTPS_PROXY: ${HTTPS_PROXY:-}
      FTP_PROXY: ${FTP_PROXY:-}
      NO_PROXY: ${NO_PROXY:-}
      http_proxy: ${http_proxy:-}
      https_proxy: ${https_proxy:-}
      ftp_proxy: ${ftp_proxy:-}
      no_proxy: ${no_proxy:-}
    depends_on:
      - db
    healthcheck:
      disable: true
    networks:
      - internal
    command: python manage.py run_server_inventory_worker
```

El worker no necesita la red externa `web`. No agregarle DNS públicos: debe
resolver LDAP y los Linux con el DNS corporativo heredado del host.

## Secuencia estándar de despliegue

Desde el directorio productivo:

```bash
docker compose config --quiet
docker compose --profile tools run --rm db_backup
docker compose build web mitre_scheduler server_inventory_worker
docker compose run --rm web python manage.py migrate
docker compose up -d --force-recreate web mitre_scheduler server_inventory_worker
docker compose exec web python manage.py collectstatic --noinput
docker compose exec web python manage.py check
docker compose ps
```

El orden es importante: primero se ejecutan las migraciones y después arranca el
worker. La observabilidad agrega `auditlog.0003_operationalalert` y la cola
interna agrega `server_heatmap.0011_inventoryjob`. La protección de acciones
administrativas agrega `auditlog.0004_actionratelimit`. La migración
`auditlog.0005_remove_operationalalert_last_notified_at` retira el último campo
residual de notificaciones externas. No se agregan contenedores ni dependencias
externas. El historial de reglas agrega
`server_heatmap.0012_inventoryrulerevision`; durante la migración se crea una
versión inicial de cada regla de nomenclatura y filtro existentes.
La unificación agrega
`server_heatmap.0013_unify_inventory_rules_and_retention`; copia las
nomenclaturas existentes al motor único de Reglas de inventario y agrega las
políticas de retención técnica. La tabla anterior se conserva para rollback.
Después de desplegar se debe comprobar:

```bash
docker compose exec web python manage.py showmigrations auditlog
docker compose exec web python manage.py showmigrations server_heatmap
docker compose exec web python manage.py shell -c "from apps.auditlog.models import OperationalAlert; print(OperationalAlert.objects.count())"
docker compose exec web python manage.py shell -c "from apps.server_heatmap.models import InventoryJob; print(InventoryJob.objects.count())"
docker compose exec web python manage.py shell -c "from apps.server_heatmap.models import InventoryFilterRule,ServerNamingRule; print({'anteriores':ServerNamingRule.objects.count(),'migradas':InventoryFilterRule.objects.filter(legacy_naming_rule_id__isnull=False).count()})"
docker compose logs --tail=50 server_inventory_worker
tail -n 20 logs/operations.log
```

Validaciones funcionales:

```bash
docker compose exec web python manage.py showmigrations --plan
docker compose exec web getent hosts 10.214.139.77
docker compose exec web python manage.py shell -c "from django.conf import settings; print(settings.DEBUG)"
docker compose exec web python manage.py maintain_server_inventory
```

## Rollback de código

Antes de desplegar:

```bash
docker compose --profile tools run --rm db_backup
git rev-parse HEAD
```

Si falla la aplicación:

1. conservar los logs;
2. volver al commit anterior;
3. reconstruir `web` y schedulers;
4. restaurar la base sólo si la migración no es reversible o dañó datos;
5. ejecutar `python manage.py check`.

No ejecutar un restore productivo como primera medida. Las migraciones Django
deben revertirse con `migrate app_name migration_anterior` cuando sea seguro.

## Checklist de compatibilidad

- [ ] `docker compose config --quiet`.
- [ ] No hay DNS públicos en los servicios internos.
- [ ] La red externa `web` existe.
- [ ] El reverse proxy alcanza a `web`.
- [ ] PostgreSQL está saludable.
- [ ] Las migraciones terminaron.
- [ ] Los archivos estáticos fueron recolectados.
- [ ] Login local funciona.
- [ ] Login LDAP funciona.
- [ ] SIEM responde sin usar proxy.
- [ ] DNS inverso Linux funciona dentro de `web`.
- [ ] Dashboard y mapa de calor cargan.
- [ ] Scheduler MITRE continúa activo.
- [ ] `server_inventory_worker` está activo.
- [ ] Un trabajo manual pasa de pendiente a finalizado.
- [ ] Un POST sin token CSRF es rechazado.
- [ ] Las solicitudes administrativas repetidas devuelven HTTP 429.
- [ ] El historial muestra una versión inicial de las reglas existentes.
- [ ] Editar una regla crea una nueva versión con el usuario responsable.
- [ ] La cantidad de nomenclaturas anteriores coincide con las reglas migradas.
- [ ] Guardar una regla encola automáticamente su recálculo.
- [ ] `maintain_server_inventory` funciona primero en modo simulación.
- [ ] Backup PostgreSQL finaliza y genera checksum.
