# Requisitos Tecnicos

## Plataforma

| Componente | Requisito |
| --- | --- |
| Runtime | Python 3.12+ |
| Framework | Django 5.2.15 LTS |
| DB | PostgreSQL 16 recomendado |
| App server dev | Django runserver |
| App server prod | Gunicorn |
| Contenedores | Docker + Docker Compose |
| PDF | ReportLab + Pillow |
| Excel | openpyxl |
| LDAP | ldap3 |

## Variables de Entorno

| Variable | Requerida | Uso |
| --- | --- | --- |
| `SECRET_KEY` | Si | Clave Django. No usar defaults en produccion. |
| `LDAP_SECRET_KEY` | No | Clave estable para cifrar `bind_password`; si falta se deriva de `SECRET_KEY`. |
| `DEBUG` | Si | `1` local, `0` produccion. |
| `ALLOWED_HOSTS` | Si | Hosts separados por coma. |
| `POSTGRES_DB` | Si | Nombre DB. |
| `POSTGRES_USER` | Si | Usuario DB. |
| `POSTGRES_PASSWORD` | Si | Password DB. |
| `POSTGRES_HOST` | Si | En Docker: `db`. |
| `POSTGRES_PORT` | Si | En Docker: `5432`. |
| `LOG_DIR` | No | En Docker: `/logs`. |
| `MITRE_SYNC_POLL_SECONDS` | No | Frecuencia de polling del scheduler Docker. |
| `SECURE_SSL_REDIRECT` | No | `1` si Django fuerza HTTPS. |
| `SESSION_COOKIE_SECURE` | No | `1` con HTTPS. |
| `CSRF_COOKIE_SECURE` | No | `1` con HTTPS. |
| `SECURE_HSTS_SECONDS` | No | HSTS en segundos. |
| `USE_X_FORWARDED_PROTO` | No | `1` detras de reverse proxy confiable. |
| `USE_X_FORWARDED_FOR` | No | `1` solo si el proxy confiable envia IP real. |

## Puertos

### Desarrollo (`docker-compose.yml`)

| Servicio | Puerto contenedor | Puerto host | Nota |
| --- | --- | --- | --- |
| `web` | `8000/tcp` | `8000/tcp` | UI Django. |
| `db` | `5432/tcp` | No publicado | Solo accesible dentro de la red Docker. |
| `mitre_scheduler` | N/A | N/A | Job interno. |

### Produccion (`docker-compose.prod.yml`)

| Servicio | Puerto contenedor | Publicacion |
| --- | --- | --- |
| `web` | `8000/tcp` | `expose`; publicar con reverse proxy. |
| `db` | `5432/tcp` | No publicar al host salvo necesidad controlada. |

## Fuentes Externas

La sincronizacion completa requiere salida HTTPS `443/tcp`.

| Fase | Host | URL | Consultas por corrida |
| --- | --- | --- | --- |
| ATT&CK Enterprise STIX | `raw.githubusercontent.com` | `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` | 1 |
| Catalogo D3FEND | `d3fend.mitre.org` | `https://d3fend.mitre.org/ontologies/d3fend/1.4.0/d3fend.csv` | 1 |
| Mappings D3FEND -> ATT&CK | `d3fend.mitre.org` | `https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.csv` | 1 o 2 segun flujo |
| Normalizacion D3FEND | `d3fend.mitre.org` | `https://d3fend.mitre.org/api/technique/<slug>.json` y fallback HTML | Hasta 2 por item sin codigo `D3-*` |
| D3FEND DAO | `d3fend.mitre.org` | `https://d3fend.mitre.org/dao/` | No se consulta automaticamente |

Formula orientativa:

```text
3 a 4 consultas fijas + hasta 2 * cantidad_de_d3fend_sin_codigo_oficial
```

ATT&CK se toma de STIX oficial de MITRE publicado en GitHub. D3FEND se toma de recursos oficiales de `d3fend.mitre.org`.

## LDAP

| Protocolo | Puerto tipico | Ejemplo |
| --- | --- | --- |
| LDAP | `389/tcp` | `ldap://ldap.local:389` |
| LDAPS | `636/tcp` | `ldaps://ldap.local:636` |

El backend usa una configuracion activa de `LDAPSettings`:

- `server_uri`
- `bind_dn`
- `bind_password`
- `user_search_base`
- `user_search_filter` con placeholder de usuario o `user_dn_template`
- modo local/LDAP

## Seguridad Operativa

- `docker-compose.yml` es desarrollo local.
- Produccion debe usar Gunicorn y reverse proxy HTTPS.
- No subir `.env`, `logs/`, `media/`, `staticfiles/` ni dumps.
- `LDAPSettings.bind_password` se cifra si hay clave disponible.
- `.xlsm` no se acepta en importacion.
- `USE_X_FORWARDED_FOR=1` solo con proxy confiable.

## Validacion CI/Local

```bash
docker compose exec web python manage.py check
docker compose exec web python manage.py test --keepdb
docker compose exec web python manage.py makemigrations --check --dry-run
```

El workflow `.github/workflows/django.yml` ejecuta:

```bash
docker compose build web
docker compose up -d db
docker compose run --rm web python manage.py check
docker compose run --rm web python manage.py test
docker compose run --rm web python manage.py makemigrations --check --dry-run
```

## Persistencia

| Ruta host | Ruta contenedor | Uso |
| --- | --- | --- |
| `./logs` | `/logs` | Logs rotativos. |
| `./app/media` | `/app/media` | Logos y uploads. |
| `./app/staticfiles` | `/app/staticfiles` | Static collect en prod. |
| `postgres_data` | `/var/lib/postgresql/data` | DB PostgreSQL. |

## Deuda Tecnica Detectada

- Mantener el guardrail de encoding para codigo, templates, static y docs; las migrations antiguas pueden conservar texto historico.
- Mantener los registros de admin dentro de la app dueña del modelo.
- Mantener `soc-control-manager-django-master/` fuera del repo/deploy final; esta incluido en `.gitignore`.
- Ejecutar `tools/visual_smoke_playwright.py` antes de releases con cambios de UI.
- Validar `ENABLE_LEGACY_USECASE_REDIRECTS=0` en staging antes de eliminar rutas viejas bajo `/usecases/`.
