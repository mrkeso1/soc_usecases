# Operacion

## Validacion

```bash
docker compose exec web python manage.py check
docker compose exec web python manage.py test --keepdb
docker compose exec web python manage.py makemigrations --check --dry-run
```

Estado validado: 99 tests OK, sin migraciones pendientes.

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

## Logs

Docker monta `./logs` en `/logs`.

| Archivo | Contenido |
| --- | --- |
| `logs/auth.log` | Login, logout, fallos y LDAP. |
| `logs/mitre_sync.log` | Sync ATT&CK/D3FEND. |
| `logs/app.log` | Warnings y errores HTTP. |

PowerShell:

```powershell
Get-Content .\logs\auth.log -Wait
Get-Content .\logs\mitre_sync.log -Wait
Get-Content .\logs\app.log -Wait
```

Docker:

```bash
docker compose logs -f web
docker compose logs -f mitre_scheduler
```

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
