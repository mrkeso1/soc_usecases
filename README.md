# SOC Use Cases Manager

SOC Use Cases Manager es una aplicación Django para inventariar, administrar y revisar casos de uso SOC. El sistema combina:

- Inventario de casos de uso con mapeos MITRE ATT&CK y D3FEND.
- Dashboard ejecutivo de cobertura sobre casos productivos.
- Cobertura D3FEND inferida desde técnicas ATT&CK relacionadas.
- Exportación PDF del dashboard con branding configurable.
- Exportación CSV del inventario filtrado.
- Ciclo de vida periódico con responsables de control y evidencia histórica.
- Autenticación local/LDAP configurable desde el admin.
- Roles operativos `Admin`, `Analyst` y `ReadOnly`.

## Requisitos técnicos

### Runtime

| Componente | Requisito |
| --- | --- |
| Python | 3.12 o superior recomendado para Django 6.x |
| Framework | Django `6.0.5` |
| Base de datos | PostgreSQL, vía `psycopg[binary]` |
| Servidor WSGI | Gunicorn `23.0.0` |
| Archivos estáticos | `STATIC_ROOT`, `STATICFILES_DIRS` y `collectstatic` para producción |
| Archivos media | `MEDIA_ROOT` para logos de reportes PDF |
| LDAP | Servidor LDAP/LDAPS accesible si se habilita autenticación LDAP |

### Dependencias Python principales

Las dependencias están fijadas en `requirements.txt`:

- `Django==6.0.5`: framework web.
- `psycopg[binary]==3.2.6`: driver PostgreSQL.
- `gunicorn==23.0.0`: servidor WSGI para despliegue.
- `python-dotenv==1.0.1`: soporte para variables de entorno.
- `openpyxl==3.1.5`: lectura de archivos Excel para importaciones.
- `requests==2.32.3`: cliente HTTP para integraciones/cargas externas.
- `ldap3==2.9.1`: autenticación y pruebas LDAP.
- `Pillow==10.4.0`: procesamiento de imágenes, requerido para logos en reportes.
- `reportlab==4.2.2`: generación de PDF.

### Variables de entorno

| Variable | Default local | Descripción |
| --- | --- | --- |
| `SECRET_KEY` | `django-insecure-dev-key` | Clave secreta de Django. Debe configurarse en producción. |
| `DEBUG` | `0` | Activa modo debug solo si vale `1`. |
| `ALLOWED_HOSTS` | `127.0.0.1,localhost` | Hosts permitidos separados por coma. |
| `POSTGRES_DB` | `soc_usecases` | Nombre de base PostgreSQL. |
| `POSTGRES_USER` | `soc_user` | Usuario PostgreSQL. |
| `POSTGRES_PASSWORD` | `soc_pass` | Password PostgreSQL. |
| `POSTGRES_HOST` | `db` | Host PostgreSQL. |
| `POSTGRES_PORT` | `5432` | Puerto PostgreSQL. |

### Servicios externos

- **PostgreSQL** es obligatorio: el proyecto usa `django.db.backends.postgresql`.
- **LDAP/LDAPS** es opcional: solo se usa si existe una configuración `LDAPSettings` activa y el modo de autenticación lo requiere.
- **Filesystem persistente** recomendado para `MEDIA_ROOT`, porque ahí se guardan logos de reportes PDF.

## Estructura del proyecto

```text
app/
├── apps/
│   ├── accounts/          # Usuario custom, LDAP, roles y seed de grupos
│   └── usecases/          # Dominio principal: casos, dashboard, lifecycle y reportes
├── config/                # Settings, URLs, ASGI/WSGI
├── templates/             # Layout base, dashboard, auth y pantallas de usecases
└── manage.py
```

Apps activas en `INSTALLED_APPS`:

- `apps.accounts`: usuarios, roles, LDAP y contexto de roles para templates.
- `apps.usecases`: inventario, dashboard, lifecycle, exportaciones y catálogos ATT&CK/D3FEND.

Las apps placeholder `core`, `catalog` y `workflow` fueron removidas porque no tenían modelos ni vistas funcionales y no estaban siendo utilizadas.

## Módulos relevantes

### `apps.accounts`

| Archivo | Responsabilidad |
| --- | --- |
| `models.py` | `User`, `LDAPSettings`, `LDAPAuthLog`. |
| `backends.py` | Autenticación LDAP y backend local controlado por modo LDAP. |
| `roles.py` | Constantes y helpers para `Admin`, `Analyst`, `ReadOnly`. |
| `context_processors.py` | Expone flags de rol a templates. |
| `admin.py` | Admin de usuarios, grupos permitidos, configuración LDAP y logs. |
| `management/commands/seed_groups.py` | Crea/normaliza los grupos base y permisos. |

### `apps.usecases`

| Archivo | Responsabilidad |
| --- | --- |
| `models.py` | Modelos de ATT&CK, D3FEND, correlación D3FEND→ATT&CK, casos de uso, lifecycle, report settings y changelog. |
| `views.py` | Request/response: pantallas, acciones POST, CSV, PDF, autocomplete. |
| `dashboard.py` | Agregación de métricas del dashboard compartida por UI y PDF. |
| `reports.py` | Construcción de PDF con ReportLab y settings de reporte. |
| `permissions.py` | Reglas de acceso por rol y ownership. |
| `lifecycle.py` | Ventanas de ciclo de vida y checkpoints del negocio. |
| `forms.py` | Formulario de casos, filtrando ATT&CK/D3FEND habilitados. |
| `urls.py` | Rutas del módulo de casos de uso. |
| `admin.py` | Admin de catálogos, casos, lifecycle y report settings. |

## Roles y permisos

El sistema normaliza tres grupos:

| Grupo | Alcance |
| --- | --- |
| `Admin` | Puede hacer todo. También se considera admin a `is_superuser=True`. |
| `Analyst` | Puede ver/crear casos y modificar solo casos propios. Puede finalizar controles de ciclo de vida solo si es responsable asignado. |
| `ReadOnly` | Solo accede al dashboard. No ve inventario, lifecycle ni admin desde la navegación. |

Para crear y normalizar grupos:

```bash
python app/manage.py seed_groups
```

El comando:

1. Crea `Admin`, `Analyst` y `ReadOnly`.
2. Asigna todos los permisos a `Admin`.
3. Asigna permisos operativos de casos/lifecycle a `Analyst`.
4. Limpia permisos de `ReadOnly`.
5. Elimina grupos legacy `Engineer` y `Reviewer`.

## Autenticación LDAP

La autenticación se define con dos backends:

1. `AdminConfiguredLDAPBackend`: intenta autenticar contra LDAP cuando hay configuración activa y el modo lo permite.
2. `AdminControlledModelBackend`: permite autenticación local según el modo configurado.

Modos LDAP disponibles:

| Modo | Descripción |
| --- | --- |
| `LDAP + fallback local` | Intenta LDAP y permite fallback local. |
| `Solo LDAP` | Bloquea usuarios locales no superuser. |
| `Solo local` | Ignora LDAP. |

La configuración LDAP se administra desde Django Admin en `LDAPSettings`. Desde el admin se puede ejecutar **Probar conexión**, que registra el resultado en `LDAPAuthLog`.

## Inventario de casos de uso

Funciones principales:

- Listado filtrable por texto, estado, dispositivo, severidad, habilitado, owner, revisión y mapeos.
- Vista compacta/detallada.
- Alta, edición, eliminación y detalle de casos.
- Bulk update con detección de filas modificadas.
- Mapeo ATT&CK/D3FEND vía autocomplete, limitado a elementos habilitados.
- Changelog automático para campos relevantes.
- Exportación CSV respetando filtros aplicados.

Ownership de un caso:

- Creador (`created_by`).
- Responsable de control (`lifecycle_control_owner`).
- Texto `owner_name`, comparado contra username, display name, email o nombre completo del usuario.

## Dashboard

URL principal:

```text
/dashboard/
```

Métricas incluidas:

- Total de casos productivos.
- Cobertura de técnicas ATT&CK habilitadas.
- Cobertura de tácticas ATT&CK habilitadas.
- Cobertura D3FEND inferida desde ATT&CK: cada control D3FEND recibe cobertura parcial según cuántas de sus técnicas ATT&CK relacionadas están cubiertas por casos productivos.
- Controles D3FEND totalmente cubiertos y parcialmente cubiertos.
- Casos productivos con D3FEND manual.
- Técnicas/controles pendientes.
- Top técnicas ATT&CK y controles D3FEND por uso.

La agregación está centralizada en `apps.usecases.dashboard.build_dashboard_context` para evitar que la vista y el PDF calculen cosas distintas.

### Lógica de correlación D3FEND → ATT&CK

D3FEND publica relaciones inferidas entre técnicas defensivas y técnicas ofensivas ATT&CK. El gestor permite cargar solo ATT&CK en los casos de uso y calcular cobertura D3FEND a partir de esas relaciones:

- Cada `D3Fend` puede tener varias técnicas ATT&CK relacionadas en `related_attacks`.
- Si un D3FEND tiene 4 ATT&CK relacionadas y los casos productivos cubren 1, ese control tiene 25% de cobertura.
- La cobertura global D3FEND suma esos porcentajes parciales como "equivalente cubierto" sobre el total de controles D3FEND con mapeo.
- Los mapeos se cargan con `python app/manage.py load_d3fend` después de haber cargado ATT&CK con `load_mitre_attack`.

## Exportación PDF

URL:

```text
/dashboard/export/pdf/
```

La exportación PDF:

- Reutiliza el mismo contexto del dashboard.
- Respeta filtros del dashboard enviados por querystring.
- Incluye KPIs, tablas de cobertura y pendientes.
- Usa `DashboardReportSettings` para título, subtítulo, footer y logo.
- Si la tabla de configuración aún no existe durante un despliegue/migración, usa defaults seguros.

La construcción PDF vive en `apps.usecases.reports`, no en `views.py`, para mantener separadas las responsabilidades de HTTP y rendering.

## Ciclo de vida

URL base:

```text
/usecases/lifecycle/
```

Comportamiento:

- Ventanas de revisión por checkpoints: 30/04, 31/08 y 31/12.
- `Admin` puede asignar responsables de control.
- `Analyst` puede finalizar controles solo si es responsable asignado.
- Al finalizar se actualiza la fecha de validación, se calcula próxima revisión y se registra `LifecycleReview`.
- `LifecycleSettings` define el intervalo en días para próxima revisión. Si no hay configuración activa se usa `120` días.

## Catálogos ATT&CK y D3FEND

- `MitreAttack` representa técnicas ATT&CK con `external_id`, nombre, táctica y flag `is_enabled`.
- `D3Fend` representa controles D3FEND con código, nombre, categoría, flag `is_enabled` y relaciones ATT&CK inferidas en `related_attacks`.
- Los formularios/autocomplete solo ofrecen elementos habilitados para nuevos mapeos.

## Importaciones y comandos útiles

```bash
# Normalizar roles y permisos
python app/manage.py seed_groups

# Importar casos desde Excel
python app/manage.py import_usecases <archivo.xlsx>

# Cargar técnicas MITRE ATT&CK
python app/manage.py load_mitre_attack

# Cargar controles D3FEND y relaciones inferidas D3FEND→ATT&CK
python app/manage.py load_d3fend

# Cargar D3FEND sin sincronizar relaciones
python app/manage.py load_d3fend --skip-mappings
```

## Instalación local orientativa

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app/manage.py migrate
python app/manage.py seed_groups
python app/manage.py createsuperuser
python app/manage.py runserver 0.0.0.0:8000
```

> Nota: la base PostgreSQL debe estar disponible antes de ejecutar `migrate`.

## Checklist de despliegue

1. Configurar variables de entorno seguras (`SECRET_KEY`, `ALLOWED_HOSTS`, PostgreSQL, `DEBUG=0`).
2. Instalar dependencias con `requirements.txt`.
3. Ejecutar migraciones.
4. Ejecutar `seed_groups`.
5. Crear o validar usuario admin/superuser.
6. Ejecutar `collectstatic`.
7. Montar volumen persistente para `MEDIA_ROOT` si se usarán logos de reportes.
8. Configurar LDAP desde admin solo si aplica.
9. Validar `/dashboard/`, `/dashboard/export/pdf/`, `/usecases/` y `/usecases/lifecycle/`.

## Convenciones de mantenimiento

- Las vistas deben quedar para request/response y delegar lógica de negocio a módulos específicos.
- No agregar lógica de PDF en `views.py`; usar `apps.usecases.reports`.
- No duplicar métricas del dashboard; usar `apps.usecases.dashboard`.
- Mantener reglas de permisos en `apps.usecases.permissions`.
- Mantener cálculos de ventanas de ciclo de vida en `apps.usecases.lifecycle`.
- Si se crea una app nueva, debe tener una responsabilidad funcional clara antes de sumarla a `INSTALLED_APPS`.
