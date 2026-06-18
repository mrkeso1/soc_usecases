# Requisitos tecnicos

Este documento resume lo necesario para desarrollar, probar y operar SOC Use Cases Manager.

## Plataforma

| Componente | Requisito |
| --- | --- |
| Runtime | Python 3.12+ |
| Framework | Django 6.0.5 |
| Base de datos | PostgreSQL |
| Servidor app | Gunicorn en produccion |
| Contenedores | Docker y Docker Compose |
| Sistema recomendado | Linux para produccion |

## Dependencias Python

Se instalan desde `requirements.txt`.

| Paquete | Uso principal |
| --- | --- |
| Django | Framework web y ORM. |
| psycopg[binary] | Driver PostgreSQL. |
| gunicorn | Servidor WSGI. |
| python-dotenv | Variables de entorno locales. |
| openpyxl | Importacion Excel. |
| requests | Descarga de datasets MITRE/D3FEND. |
| ldap3 | Autenticacion y pruebas LDAP/LDAPS. |
| Pillow | Logos de reportes. |
| reportlab | Exportacion PDF. |

## Variables de entorno

| Variable | Requerida | Comentario |
| --- | --- | --- |
| `SECRET_KEY` | Si | Usar un valor unico y secreto en produccion. |
| `DEBUG` | Si | `0` en produccion. |
| `ALLOWED_HOSTS` | Si | Hosts separados por coma. |
| `POSTGRES_DB` | Si | Nombre de la DB. |
| `POSTGRES_USER` | Si | Usuario DB. |
| `POSTGRES_PASSWORD` | Si | Password DB. |
| `POSTGRES_HOST` | Si | En Docker suele ser `db`. |
| `POSTGRES_PORT` | Si | Default `5432`. |
| `LOG_DIR` | No | Directorio de logs. En Docker se usa `/logs`. |
| `SECURE_SSL_REDIRECT` | No | `1` en produccion si Django debe redirigir HTTP a HTTPS. |
| `SESSION_COOKIE_SECURE` | No | `1` en produccion con HTTPS. |
| `CSRF_COOKIE_SECURE` | No | `1` en produccion con HTTPS. |
| `SECURE_HSTS_SECONDS` | No | Segundos de HSTS. Usar solo cuando HTTPS este validado. |
| `USE_X_FORWARDED_PROTO` | No | `1` si hay reverse proxy que envia `X-Forwarded-Proto`. |

## Servicios externos

- PostgreSQL es obligatorio.
- LDAP/LDAPS es opcional y se habilita desde `LDAPSettings`.
- MITRE ATT&CK se descarga desde la fuente oficial STIX 2.1 publicada por MITRE en GitHub (`mitre-attack/attack-stix-data`); el contenedor que ejecute la sincronizacion necesita salida HTTPS.
- D3FEND se carga desde los recursos oficiales de MITRE D3FEND (`d3fend.mitre.org`) con el comando existente `load_d3fend`.
- `MEDIA_ROOT` debe persistirse si se usan logos en PDF.
- `LOG_DIR` define la carpeta de logs. En Docker se usa `/logs`, montado desde `./logs` del host.

## Red, puertos y conexiones

### Puertos locales

| Servicio | Dentro de Docker | Host local | Uso |
| --- | --- | --- | --- |
| `web` | `8000/tcp` | `8000/tcp` | Django, UI, admin, descargas PDF/Excel. |
| `db` | `5432/tcp` | `5433/tcp` | PostgreSQL. Dentro de Docker la app usa `db:5432`; desde el host se expone como `localhost:5433`. |

En produccion se recomienda publicar Django detras de reverse proxy HTTPS. El puerto externo final depende del proxy, pero el contenedor sigue escuchando en `8000`.

### Salida HTTPS para catalogos

La sincronizacion completa `sync_security_frameworks_scheduled` necesita salida a internet por `443/tcp`.

| Fase | Fuente | Host | Puerto | URL | Timeout | Cantidad de consultas por corrida |
| --- | --- | --- | --- | --- | --- | --- |
| ATT&CK Enterprise | MITRE ATT&CK STIX 2.1 oficial, repo `mitre-attack/attack-stix-data` | `raw.githubusercontent.com` | `443/tcp` | `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` | 120s | 1 |
| Catalogo D3FEND | MITRE D3FEND Ontology Releases oficiales | `d3fend.mitre.org` | `443/tcp` | `https://d3fend.mitre.org/ontologies/d3fend/1.4.0/d3fend.csv` | 120s | 1 |
| Mappings D3FEND->ATT&CK | MITRE D3FEND API/recurso oficial de relaciones inferidas | `d3fend.mitre.org` | `443/tcp` | `https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.csv` | 120s | 2 en el flujo completo: una durante `load_d3fend` y otra despues de normalizar codigos |
| Normalizacion D3FEND | MITRE D3FEND API/sitio oficial | `d3fend.mitre.org` | `443/tcp` | `https://d3fend.mitre.org/api/technique/<slug>.json` y `https://d3fend.mitre.org/technique/<slug>/` | 30s | Hasta 2 por cada D3FEND local cuyo `code` no empiece con `D3-` |

Nota: aunque ATT&CK tambien se consulta humanamente desde `https://attack.mitre.org`, el dataset machine-readable que usa la aplicacion es el STIX oficial mantenido por MITRE en GitHub. MITRE documenta que `attack-stix-data` es el repositorio para ATT&CK en STIX 2.1.

Formula orientativa de consultas externas por corrida completa:

```text
4 + (hasta 2 * cantidad_de_d3fend_sin_codigo_oficial)
```

Las 4 consultas fijas son: ATT&CK, catalogo D3FEND, mappings iniciales y mappings de refresco. Si todos los D3FEND ya tienen codigo oficial `D3-*`, la normalizacion no consulta URLs adicionales.

### LDAP/LDAPS

LDAP solo se usa si existe una configuracion activa en `LDAPSettings` y el modo no es `Solo local`.

| Modo | Puerto tipico | Configuracion |
| --- | --- | --- |
| LDAP sin TLS | `389/tcp` | `server_uri=ldap://servidor:389` |
| LDAPS | `636/tcp` | `server_uri=ldaps://servidor:636` |

En cada login LDAP, el backend realiza una busqueda del usuario usando `user_search_base` y `user_search_filter` o arma el DN con `user_dn_template`. Luego intenta bind con el usuario y password recibidos. El boton `Probar conexion` del admin realiza una conexion/bind con `bind_dn` y `bind_password`.

## Validacion local

El proyecto esta preparado para probarse por Docker:

```bash
docker compose run --rm web python manage.py test
docker compose run --rm web python manage.py makemigrations --check --dry-run
```

El workflow de CI ejecuta esos mismos checks.

## Datos demo

Para validar la aplicacion sin datos reales:

```bash
docker compose run --rm web python manage.py seed_demo_data
```

Incluye:

- Usuarios demo por rol.
- Tecnicas ATT&CK y controles D3FEND relacionados.
- Casos productivos, test y desarrollo.
- Revisiones lifecycle y proximos controles.
- Overrides de cobertura.
- Configuraciones demo de PDF, lifecycle, LDAP inactivo y sync MITRE.

## Cron de frameworks

La frecuencia vive en la base de datos, en `MitreAttackSyncSettings`, visible en admin como `Sincronizaciones de frameworks`.

Campos importantes:

- `is_active`: solo una configuracion activa decide la agenda.
- `interval_value`: numero del intervalo.
- `interval_unit`: `hours` o `days`.
- `last_success_at`: ultima sincronizacion exitosa.
- `last_status`, `last_message`, `last_created`, `last_updated`, `last_skipped`: auditoria de la ultima corrida.

El cron del sistema puede correr frecuente, por ejemplo cada hora:

```bash
docker compose run --rm web python manage.py sync_security_frameworks_scheduled
```

El comando consulta la DB y solo ejecuta la cadena completa si ya vencio el intervalo configurado.
La cadena completa sincroniza ATT&CK, carga D3FEND, reconstruye mappings D3FEND->ATT&CK y recalcula D3FEND inferido en casos de uso.
Para forzar una corrida manual:

```bash
docker compose run --rm web python manage.py sync_security_frameworks_scheduled --force
```

`sync_mitre_attack_scheduled` queda disponible como comando puntual si se necesita actualizar solo ATT&CK.

En produccion:

- Usar `docker compose run --rm web ...` si el cron debe crear un contenedor efimero.
- Usar `docker compose exec -T web ...` si el contenedor `web` esta siempre corriendo.
- Registrar salida en un archivo de log del host.

## Docker produccion

El archivo `docker-compose.yml` queda orientado a desarrollo local con `runserver` y puerto publicado `8000`.
Para produccion se agrega `docker-compose.prod.yml`, que usa Gunicorn y no publica el puerto directamente:

```bash
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml exec web python manage.py migrate
docker compose -f docker-compose.prod.yml exec web python manage.py collectstatic --noinput
```

Se recomienda publicar `web:8000` detras de un reverse proxy HTTPS. En ese escenario configurar:

```env
DEBUG=0
SECURE_SSL_REDIRECT=1
SESSION_COOKIE_SECURE=1
CSRF_COOKIE_SECURE=1
SECURE_HSTS_SECONDS=31536000
USE_X_FORWARDED_PROTO=1
```

## Logs

La aplicacion escribe logs rotativos:

| Logger | Archivo | Uso |
| --- | --- | --- |
| `soc.auth` | `auth.log` | Login/logout, fallos de login y LDAP. |
| `soc.mitre_sync` | `mitre_sync.log` | Descarga y sincronizacion MITRE/frameworks. |
| `django.request` | `app.log` | Warnings y errores HTTP. |

Cada archivo rota a los 5 MB y conserva 5 backups.

## Checklist de produccion

1. Configurar variables de entorno.
2. Ejecutar migraciones.
3. Ejecutar `seed_groups`.
4. Crear superusuario.
5. Configurar `MitreAttackSyncSettings`.
6. Configurar cron externo para `sync_security_frameworks_scheduled`.
7. Configurar LDAP solo si aplica.
8. Montar volumen de `MEDIA_ROOT`.
9. Ejecutar tests y check de migraciones antes de desplegar.
