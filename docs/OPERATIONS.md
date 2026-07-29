# Operacion

## Validacion

```bash
docker compose exec web python manage.py check
docker compose exec web python manage.py test --keepdb
docker compose exec web python manage.py makemigrations --check --dry-run
```

Estado validado: 223 tests OK, sin migraciones pendientes.

## Primer Arranque Local

```bash
cp .env.example .env
docker compose up -d --build
docker compose exec web python manage.py migrate
docker compose exec web python manage.py seed_groups
docker compose exec web python manage.py createsuperuser
```

Datos demo:

```bash
docker compose exec web python manage.py seed_demo_data
```

Reset demo:

```bash
docker compose exec web python manage.py seed_demo_data --reset
```

Usuarios demo:

| Usuario | Rol | Password |
| --- | --- | --- |
| `demo_admin` | Admin | `Demo12345!` |
| `demo_analyst` | Analyst | `Demo12345!` |
| `demo_owner` | Analyst/control owner | `Demo12345!` |
| `demo_readonly` | ReadOnly | `Demo12345!` |

## Importacion y Exportacion

Desde UI:

- `/usecases/import/excel/`: importa `.xlsx`.
- `/usecases/import/template/`: descarga plantilla.
- `/usecases/export/xlsx/`: exporta la vista filtrada.
- `/usecases/export/csv/`: exporta CSV.

Desde consola:

```bash
docker compose exec web python manage.py import_usecases /app/ruta/archivo.xlsx --update
```

Reglas:

- `.xlsm` no se acepta.
- `NOMBRE NETWITNESS` es la clave de actualizacion.
- `DISPOSITIVO` se conserva como legacy.
- `FUENTES` crea/vincula `EventSource`.
- D3FEND se infiere desde ATT&CK, no se importa manualmente.

## Fuentes de Eventos

Rutas:

- `/sources/`
- `/sources/new/`
- `/sources/admin/catalog/`

En catalogos se administran:

- categorias;
- subcategorias;
- tipos de fuente;
- metodos de envio.

Cuando se carga una fuente, la subcategoria debe pertenecer a la categoria seleccionada.

## Backups Tecnicos

Rutas:

- `/sigma/backups/`
- `/sigma/backups/from-usecase/<id>/`

El backup tecnico se genera automaticamente al guardar un caso de uso desde Inventario cuando existe regla completa o condiciones. Desde el detalle de un caso tambien aparece `Actualizar desde regla` para sincronizar casos existentes. Esa accion:

1. toma `UseCase.full_rule_text`;
2. si no existe, arma una logica con `UseCaseRuleCondition`;
3. crea una nueva version `UseCaseTechnicalBackup` solo si la logica cambio;
4. calcula checksum SHA-256;
5. marca la nueva version como vigente.

## Backup PostgreSQL

Los backups técnicos de reglas no reemplazan el backup de la base completa.
El servicio `db_backup` genera un dump PostgreSQL en formato custom, verifica
que `pg_restore` pueda leerlo y crea un checksum SHA-256.

Los archivos quedan en `./backups`, fuera del volumen `postgres_data`:

```bash
docker compose --profile tools run --rm db_backup
ls -lh backups/
```

La salida esperada incluye:

```text
Backup validado: /backups/soc_usecases_AAAAMMDDTHHMMSSZ.dump
```

Configuración:

```env
POSTGRES_BACKUP_RETENTION_DAYS=14
BACKUP_UID=1000
BACKUP_GID=1000
```

En Linux, `BACKUP_UID` y `BACKUP_GID` deben coincidir con el usuario propietario
del directorio:

```bash
id -u
id -g
mkdir -p backups
chown "$(id -u):$(id -g)" backups
chmod 700 backups
```

### Automatización diaria

Ejemplo de cron a las 02:15:

```cron
15 2 * * * cd "/opt/apps/SOC Control Manager" && /usr/bin/docker compose --profile tools run --rm db_backup >> /var/log/soc-db-backup.log 2>&1
```

El directorio `./backups` sigue estando en el mismo host. Después de cada
backup debe copiarse a un almacenamiento corporativo externo, cifrado y con
control de acceso. Un backup que sólo existe en el servidor productivo no
protege contra pérdida del host.

Política inicial recomendada:

- RPO: 24 horas.
- RTO: 4 horas.
- 14 backups diarios locales.
- 8 backups semanales externos.
- prueba mensual de restore.

### Restore de prueba

Listar backups:

```bash
ls -1 backups/*.dump
```

Restaurar en una base paralela, sin tocar producción:

```bash
export RESTORE_FILE=soc_usecases_AAAAMMDDTHHMMSSZ.dump
export POSTGRES_RESTORE_DB=soc_usecases_restore
export RESTORE_CONFIRM=RESTORE_soc_usecases_restore
docker compose --profile tools run --rm db_restore
```

Validar la base restaurada:

```bash
docker compose exec db psql -U "$POSTGRES_USER" -d soc_usecases_restore -c "\dt"
docker compose exec db psql -U "$POSTGRES_USER" -d soc_usecases_restore -c "SELECT count(*) FROM django_migrations;"
```

Eliminar la base de prueba después de verificarla:

```bash
docker compose exec db dropdb -U "$POSTGRES_USER" --if-exists soc_usecases_restore
```

### Restore sobre producción

Esta operación reemplaza completamente la base y requiere una ventana de
mantenimiento. Primero verificar el mismo dump en una base paralela.

```bash
docker compose stop web mitre_scheduler

export RESTORE_FILE=soc_usecases_AAAAMMDDTHHMMSSZ.dump
export POSTGRES_RESTORE_DB="$POSTGRES_DB"
export RESTORE_CONFIRM="RESTORE_${POSTGRES_DB}"
export ALLOW_PRODUCTION_RESTORE=1
docker compose --profile tools run --rm db_restore

docker compose start web mitre_scheduler
docker compose exec web python manage.py migrate --check
docker compose exec web python manage.py check
```

Después del restore validar:

- login local y LDAP;
- dashboard;
- casos de uso;
- fuentes;
- mapa de calor;
- últimas ejecuciones;
- logs de Django;
- versión de migraciones.

Desactivar las variables peligrosas al terminar:

```bash
unset RESTORE_FILE POSTGRES_RESTORE_DB RESTORE_CONFIRM ALLOW_PRODUCTION_RESTORE
```

## Sincronizacion MITRE/D3FEND

Configurar agenda en Django Admin:

```text
Admin Django > Sincronizaciones de frameworks
```

Campos importantes:

- `is_active`
- `interval_value`
- `interval_unit`
- `last_status`
- `last_message`
- `last_success_at`

El servicio Docker `mitre_scheduler` ejecuta:

```bash
python manage.py run_mitre_scheduler
```

Ese proceso despierta cada `MITRE_SYNC_POLL_SECONDS` y llama al comando completo cuando corresponde por DB.

Forzar sync manual:

```bash
docker compose exec web python manage.py sync_security_frameworks_scheduled --force
```

Cadena completa:

1. ATT&CK Enterprise.
2. D3FEND.
3. Mappings D3FEND -> ATT&CK.
4. Normalizacion de codigos D3FEND.
5. Recalculo de D3FEND inferido en casos.

El matching D3FEND se calcula por ID ATT&CK exacto:

- si el caso tiene `T1110`, solo considera mappings relacionados directamente con `T1110`;
- si el caso tiene `T1110.003`, solo considera mappings relacionados directamente con `T1110.003`;
- no expande automaticamente padre -> subtecnicas ni subtecnica -> padre, para evitar sobre-inferencia operativa.

El CSV oficial de D3FEND debe leerse como inferencia algoritmica, no como validacion humana. Para ajustar contexto local hay dos capas:

- exclusiones D3FEND por caso de uso desde el inventario;
- overrides globales de relacion D3FEND -> ATT&CK desde Django Admin.

Despues de cambiar mappings o esta logica, recalcular casos existentes:

```bash
docker compose exec web python manage.py sync_usecase_d3fends
```

`sync_mitre_attack_scheduled` queda disponible solo para actualizar ATT&CK, pero produccion debe usar `sync_security_frameworks_scheduled`.

## Snapshot Diario MITRE

```bash
docker compose exec web python manage.py capture_mitre_coverage_snapshot
```

Ejemplo cron Linux:

```cron
5 0 * * * cd /opt/soc_usecases && /usr/bin/docker compose exec -T web python manage.py capture_mitre_coverage_snapshot >> /var/log/soc-usecases-coverage.log 2>&1
```

## Reportes

Rutas:

- `/reports/`
- `/reports/template/`
- `/reports/<tipo>/preview/`
- `/reports/<tipo>/preview/pdf/`
- `/reports/<tipo>/download/`

Tipos:

- `executive`
- `mitre`
- `inventory`
- `lifecycle`
- `controls`

Las plantillas controlan logo, colores, footer, labels y secciones.

## LDAP

1. Crear `LDAPSettings` en Django Admin.
2. Validar `server_uri`, filtro o DN template.
3. Probar conexion.
4. Activar una sola configuracion.
5. Revisar `LDAPAuthLog` y `logs/auth.log`.

Usuarios LDAP autoaprovisionados quedan activos pero sin grupo operativo hasta que un admin asigne permisos.

## Trabajos internos de inventario

Las actualizaciones AD/SIEM, el reprocesamiento y la aplicación de filtros se
ejecutan mediante una cola persistente en PostgreSQL. Un mismo tipo de trabajo
no se ejecuta en paralelo: las solicitudes repetidas se agrupan y, si el
trabajo ya estaba corriendo, queda programada una repetición.

El worker mantiene un heartbeat y un lease. Si el contenedor se interrumpe, el
trabajo vencido vuelve automáticamente a la cola hasta alcanzar el máximo de
intentos. Los estados y errores se ven en el panel de administración de
servidores y en Django Admin.

Comandos útiles:

```bash
# Encolar la actualización completa de AD y SIEM.
docker compose exec web python manage.py enqueue_server_inventory --type full_sync

# Encolar solamente el entrecruzamiento y la aplicación de reglas.
docker compose exec web python manage.py enqueue_server_inventory --type reprocess

# Procesar un solo trabajo y terminar; útil para diagnóstico.
docker compose exec web python manage.py run_server_inventory_worker --once

# Estado y salida del worker permanente.
docker compose ps server_inventory_worker
docker compose logs --tail=100 server_inventory_worker
```

La implementación no utiliza ni notifica servicios externos. Las incidencias
quedan registradas exclusivamente en PostgreSQL, la interfaz administrativa y
`logs/operations.log`.

## Protección de acciones administrativas

Django valida CSRF en todos los formularios POST. Además, las sincronizaciones,
diagnósticos y cargas SIEM admiten por defecto hasta 3 solicitudes por usuario
en 60 segundos. Los cambios de configuración, reglas, filtros y equipos admiten
hasta 30 solicitudes por usuario en la misma ventana.

Los contadores se guardan en PostgreSQL y se comparten entre todos los procesos
Gunicorn. Cuando se supera un límite, la aplicación responde HTTP 429, informa
cuándo reintentar y no ejecuta la acción. Los botones protegidos también se
deshabilitan al primer envío para evitar dobles clics accidentales.

Configuración opcional:

```env
ADMIN_ACTION_RATE_LIMIT_WINDOW_SECONDS=60
ADMIN_ACTION_RATE_LIMIT_SYNC=3
ADMIN_ACTION_RATE_LIMIT_MUTATION=30
```

No se requiere Redis, un proxy adicional ni un servicio externo.

## Reglas unificadas de inventario

La clasificación por nomenclatura y los filtros de AD/SIEM utilizan un único
modelo: **Reglas de inventario**. Una regla puede incluir, excluir o clasificar
por hostname, FQDN, IP, OU, sistema operativo, grupos SIEM, tipo de dispositivo
o ambiente.

La migración `server_heatmap.0013_unify_inventory_rules_and_retention` convierte
automáticamente cada nomenclatura anterior en una regla de clasificación por
hostname. Conserva patrón, prioridad, estado, sistema operativo, tipo interno,
sección y notas. La tabla anterior queda preservada sin ejecución ni edición
durante la transición, para permitir rollback sin pérdida.

Las reglas activas se aplican automáticamente al guardarlas mediante el worker
de inventario. La simulación y vista previa son de solo lectura.

## Historial de reglas de inventario

Las reglas de inventario mantienen versiones inmutables. Se registra:

- tipo, nombre e ID original de la regla;
- número de versión y acción realizada;
- valores anteriores y nuevos;
- campos modificados;
- usuario, fecha e ID de solicitud.

El registro se genera desde el panel, Django Admin y cualquier guardado normal
del modelo. Las eliminaciones conservan el historial aunque la regla original
ya no exista. Si se elimina una sección funcional, también se registra la
desvinculación de las reglas afectadas.

El historial se consulta desde el botón **Historial** de Reglas de inventario o
en:

```text
/servers/administration/rule-history/
```

La migración crea automáticamente una versión inicial para todas las reglas
existentes y para las nomenclaturas convertidas. No requiere servicios
adicionales.

## Mantenimiento del inventario

El mantenimiento elimina únicamente datos técnicos vencidos:

- ejecuciones antiguas y sus observaciones, conservando siempre la última de
  cada origen;
- trabajos finalizados, fallidos o cancelados;
- alertas operativas resueltas;
- contadores de rate limit inactivos.

No elimina auditoría, versiones de reglas, eventos de deshabilitación, alertas
abiertas ni trabajos activos.

Los períodos de ejecuciones y trabajos se configuran en el Panel de
administración del mapa. La primera ejecución debe ser una simulación:

```bash
docker compose exec web python manage.py maintain_server_inventory
docker compose exec web python manage.py maintain_server_inventory --confirm
```

Variables opcionales:

```env
OPS_RESOLVED_ALERT_RETENTION_DAYS=180
ADMIN_RATE_LIMIT_RETENTION_DAYS=7
```

Cron diario sugerido a las 03:10:

```cron
10 3 * * * cd "/opt/apps/SOC Control Manager" && /usr/bin/docker compose exec -T web python manage.py maintain_server_inventory --confirm >> /var/log/soc-inventory-maintenance.log 2>&1
```

## Benchmark interno

El benchmark crea activos y observaciones sintéticas dentro de una transacción,
mide búsquedas, aplicación de reglas y consultas del dashboard, y revierte toda
la transacción al finalizar. No requiere Locust ni otro servicio.

Ejecutarlo en desarrollo o staging, no durante horario operativo de producción:

```bash
docker compose exec web python manage.py benchmark_server_inventory \
  --records 10000 \
  --coverage-percent 80 \
  --lookup-sample 1000 \
  --confirm \
  --fail-on-threshold
```

Referencia local validada con 10.000 equipos:

- 18.000 observaciones procesadas;
- reglas: 8,766 segundos;
- dashboard: 0,054 segundos;
- total: 13,285 segundos;
- cero datos sintéticos persistidos.

## Logs

Docker monta `./logs` en `/logs`.

| Archivo | Contenido |
| --- | --- |
| `logs/auth.log` | Login, logout, fallos y LDAP. |
| `logs/mitre_sync.log` | Sync ATT&CK/D3FEND. |
| `logs/app.log` | Warnings y errores HTTP. |
| `logs/operations.log` | Sincronizaciones, métricas y alertas operativas en JSON. |

PowerShell:

```powershell
Get-Content .\logs\auth.log -Wait
Get-Content .\logs\mitre_sync.log -Wait
Get-Content .\logs\app.log -Wait
Get-Content .\logs\operations.log -Wait
```

Docker:

```bash
docker compose logs -f web
docker compose logs -f mitre_scheduler
docker compose logs -f server_inventory_worker
```

Cada respuesta web incluye `X-Request-ID`. El mismo identificador aparece en
los logs JSON y permite correlacionar una acción del usuario con un error.

Las alertas operativas se consultan inicialmente en:

```text
Django Admin > Auditoría > Alertas operativas
```

Alertas automáticas iniciales:

- fallo de sincronización AD o SIEM;
- porcentaje elevado de DNS Linux sin resolver;
- caída de cobertura superior al umbral configurado.

Las alertas no se envían fuera de la plataforma. Se deduplican por huella,
acumulan ocurrencias y pueden reconocerse o resolverse desde Admin.

## Produccion

```bash
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml exec web python manage.py migrate
docker compose -f docker-compose.prod.yml exec web python manage.py collectstatic --noinput
```

Usar reverse proxy HTTPS y configurar cookies seguras.

## Troubleshooting Rapido

| Sintoma | Revisar |
| --- | --- |
| No actualiza MITRE/D3FEND | `logs/mitre_sync.log`, `MitreAttackSyncSettings`, salida HTTPS 443. |
| Dashboard no refleja inventario | Que el caso este productivo/habilitado y tenga ATT&CK/fuentes vinculadas segun metrica. |
| PDF preview rechaza conexion | Que `web` este arriba y la URL inline apunte al mismo host/puerto. |
| Backup tecnico vacio | Cargar regla completa o condiciones en el caso. |
| Usuario LDAP entra sin permisos | Asignar grupo en Access Control o Django Admin. |
