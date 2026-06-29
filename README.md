# SOC Use Cases Manager

SOC Use Cases Manager es una aplicacion Django/Docker para inventariar, gobernar y revisar casos de uso SOC. El inventario principal vive en `apps.usecases.UseCase`; las demas apps agregan capacidades alrededor de ese inventario sin duplicar la entidad central.

## Estado Actual

Validacion mas reciente:

```bash
docker compose exec web python manage.py test --keepdb
docker compose exec web python manage.py makemigrations --check --dry-run
```

Resultado: 110 tests OK y sin migraciones pendientes.

## Capacidades Principales

- Inventario de casos de uso con alta, edicion, bulk update, importacion/exportacion Excel y CSV.
- Regla tecnica por caso: condiciones incluir/excluir, regla completa y descripcion funcional.
- Backups tecnicos versionados por caso, con checksum SHA-256 y generacion directa desde la regla cargada en inventario.
- Fuentes de eventos normalizadas con tipo, categoria, subcategoria, metodo de envio, protocolo, puerto, host y cuenta de servicio.
- MITRE ATT&CK y D3FEND con sync completo, coverage admin, matrices y correlacion D3FEND -> ATT&CK.
- Dashboard ejecutivo y dashboard MITRE, con snapshots diarios de cobertura.
- Ciclo de vida con periodos configurables, responsables, revision por modal, metricas de deteccion, transiciones auditables, reset de periodo e inicio de ciclo.
- Reportes PDF ejecutivo, MITRE, inventario, ciclo de vida y controles, con preview real y plantillas configurables.
- Conversion EPL -> Sigma y Sigma -> destinos SIEM.
- Auditoria central con filtros y exportacion.
- LDAP administrable desde Django Admin y control de acceso por grupos/permisos.
- Logs rotativos para autenticacion, MITRE sync y errores HTTP.
- Guardrail de encoding para evitar mojibake visible en codigo, templates, static y docs.

## Arquitectura de Apps

| App | Responsabilidad |
| --- | --- |
| `accounts` | Usuario custom, roles, LDAP, logs de autenticacion y seed de grupos. |
| `usecases` | Inventario maestro, reglas del caso, import/export y changelog. |
| `sources` | Fuentes de eventos, taxonomia, metodos de envio y vinculacion con casos. |
| `mitre` | ATT&CK, D3FEND, coverage, matrices, autocompletes y sincronizacion. |
| `dashboard` | Dashboard ejecutivo/MITRE, PDF del dashboard y snapshots de cobertura. |
| `lifecycle` | Periodos, ciclos, revisiones, metricas de deteccion, transiciones, responsables y controles de ciclo de vida. |
| `reports` | Centro de reportes, plantillas, preview y descargas PDF. |
| `sigma_tools` | Conversion EPL/Sigma/SIEM y consulta de backups tecnicos versionados generados desde inventario. |
| `controls` | Inventario de controles y versionado. |
| `access_control` | Administracion delegada de grupos y permisos. |
| `auditlog` | Auditoria central, timeline y exportacion. |
| `integrations` | Entrada normalizada para inventarios externos. |

Algunos modelos movidos conservan `db_table` historico `usecases_*` para no romper bases existentes.

## Rutas Principales

| URL | Uso |
| --- | --- |
| `/dashboard/` | Dashboard ejecutivo. |
| `/dashboard/mitre/` | Dashboard MITRE/D3FEND. |
| `/usecases/` | Inventario principal. |
| `/usecases/import/excel/` | Importacion Excel. |
| `/sources/` | Fuentes de eventos. |
| `/sources/admin/catalog/` | Catalogos de fuentes. |
| `/lifecycle/` | Ciclo de vida. |
| `/lifecycle/periods/` | Administracion de periodos lifecycle. |
| `/mitre/attack-matrix/` | Matriz ATT&CK. |
| `/mitre/d3fend-matrix/` | Matriz D3FEND. |
| `/mitre/coverage-admin/` | Admin de cobertura MITRE/D3FEND. |
| `/reports/` | Centro de reportes. |
| `/reports/template/` | Plantillas PDF. |
| `/sigma/epl-to-sigma/` | Conversion EPL a Sigma. |
| `/sigma/converter/` | Conversion Sigma a SIEM. |
| `/sigma/backups/` | Cobertura e historial de backups tecnicos. |
| `/controls/` | Controles. |
| `/access/admin/` | Administracion funcional de accesos. |
| `/audit/` | Auditoria central. |
| `/admin/` | Django Admin. |

Las rutas legacy bajo `/usecases/lifecycle/`, `/usecases/attack-matrix/`, `/usecases/d3fend-matrix/` y `/usecases/coverage-admin/` se mantienen como redirects temporales.

## Docker Local

`docker-compose.yml` es solo para desarrollo local. Usa `runserver`, monta `./app` y `./logs`, publica `web:8000` y no publica PostgreSQL al host.

```bash
git clone https://github.com/mrkeso1/soc_usecases.git
cd soc_usecases
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

Abrir:

```text
http://localhost:8000/
```

## Docker Produccion

Para ambientes compartidos o productivos usar `docker-compose.prod.yml`, Gunicorn y reverse proxy HTTPS.

```bash
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml exec web python manage.py migrate
docker compose -f docker-compose.prod.yml exec web python manage.py collectstatic --noinput
```

Configurar en `.env`:

```env
DEBUG=0
SECRET_KEY=<valor-seguro>
ALLOWED_HOSTS=<hosts>
SECURE_SSL_REDIRECT=1
SESSION_COOKIE_SECURE=1
CSRF_COOKIE_SECURE=1
USE_X_FORWARDED_PROTO=1
```

## Comandos Operativos

```bash
# Validacion
docker compose exec web python manage.py check
docker compose exec web python manage.py test --keepdb
docker compose exec web python manage.py makemigrations --check --dry-run

# Roles
docker compose exec web python manage.py seed_groups

# Datos demo
docker compose exec web python manage.py seed_demo_data

# Importacion Excel desde consola
docker compose exec web python manage.py import_usecases /app/ruta/archivo.xlsx --update

# Sync completo ATT&CK + D3FEND + mappings + casos
docker compose exec web python manage.py sync_security_frameworks_scheduled --force

# Snapshot diario dashboard MITRE
docker compose exec web python manage.py capture_mitre_coverage_snapshot
```

Smoke visual opcional con Playwright:

```bash
pip install -r requirements-dev.txt
python -m playwright install chromium
VISUAL_USER=demo_admin VISUAL_PASSWORD=Demo12345! python tools/visual_smoke_playwright.py
```

Los screenshots quedan en `visual-artifacts/`.

## Sincronizacion MITRE/D3FEND

La frecuencia se configura en Django Admin sobre `MitreAttackSyncSettings`:

- `interval_value`
- `interval_unit`
- `is_active`
- ultimo estado/mensaje/fecha

El servicio Docker `mitre_scheduler` ejecuta `run_mitre_scheduler` cada `MITRE_SYNC_POLL_SECONDS` y el comando decide por DB si ya corresponde sincronizar.

La cadena completa:

1. Descarga ATT&CK Enterprise STIX 2.1.
2. Carga catalogo D3FEND.
3. Reconstruye mappings D3FEND -> ATT&CK.
4. Normaliza codigos D3FEND cuando hace falta.
5. Recalcula D3FEND inferido en casos.

## Fuentes Externas

La sincronizacion necesita salida HTTPS `443/tcp`:

| Fuente | Host | Uso |
| --- | --- | --- |
| ATT&CK STIX | `raw.githubusercontent.com` | Dataset oficial `mitre-attack/attack-stix-data`. |
| D3FEND | `d3fend.mitre.org` | Catalogo, mappings y tecnica. |
| D3FEND DAO | `d3fend.mitre.org/dao/` | Referencia conceptual/documental, no se scrapea en el sync. |

## Logs

Docker monta `./logs` en `/logs`.

| Archivo | Contenido |
| --- | --- |
| `logs/auth.log` | Login, logout, fallos, LDAP. |
| `logs/mitre_sync.log` | Descarga y sincronizacion ATT&CK/D3FEND. |
| `logs/app.log` | Warnings/errores HTTP de Django. |

Windows PowerShell:

```powershell
Get-Content .\logs\auth.log -Wait
Get-Content .\logs\mitre_sync.log -Wait
```

## Documentacion

- `docs/PROJECT_STATUS.md`: estado actual, hallazgos y pendientes.
- `docs/ARCHITECTURE.md`: arquitectura de apps.
- `docs/FUNCTIONAL_OVERVIEW.md`: mapa funcional.
- `docs/TECHNICAL_REQUIREMENTS.md`: requisitos, puertos, fuentes externas.
- `docs/OPERATIONS.md`: operacion diaria, comandos y troubleshooting.
- `docs/INTEGRATIONS.md`: contrato para inventarios externos.
- `docs/INTEGRATION_FINAL_REVIEW.md`: analisis historico de integracion con el proyecto nuevo.

## Deuda Tecnica Conocida

- Mantener el guardrail de encoding; solo quedan mojibakes historicos en migrations antiguas.
- Las rutas legacy bajo `/usecases/` siguen activas por compatibilidad; se pueden apagar con `ENABLE_LEGACY_USECASE_REDIRECTS=0` antes de removerlas.
- Seguir consolidando CSS inline de templates secundarios hacia archivos estaticos.
