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

## Servicios externos

- PostgreSQL es obligatorio.
- LDAP/LDAPS es opcional y se habilita desde `LDAPSettings`.
- MITRE ATT&CK se descarga desde GitHub mediante `requests`; el contenedor que ejecute la sincronizacion necesita salida HTTPS.
- D3FEND se carga con el comando existente `load_d3fend`.
- `MEDIA_ROOT` debe persistirse si se usan logos en PDF.

## Validacion local

El proyecto esta preparado para probarse por Docker:

```bash
docker compose run --rm web python manage.py test
docker compose run --rm web python manage.py makemigrations --check --dry-run
```

El workflow de CI ejecuta esos mismos checks.

## Cron MITRE

La frecuencia vive en la base de datos, en `MitreAttackSyncSettings`.

Campos importantes:

- `is_active`: solo una configuracion activa decide la agenda.
- `interval_value`: numero del intervalo.
- `interval_unit`: `hours` o `days`.
- `last_success_at`: ultima sincronizacion exitosa.
- `last_status`, `last_message`, `last_created`, `last_updated`, `last_skipped`: auditoria de la ultima corrida.

El cron del sistema puede correr frecuente, por ejemplo cada hora:

```bash
docker compose run --rm web python manage.py sync_mitre_attack_scheduled
```

El comando consulta la DB y solo descarga MITRE si ya vencio el intervalo configurado. Para forzar una corrida manual:

```bash
docker compose run --rm web python manage.py sync_mitre_attack_scheduled --force
```

## Checklist de produccion

1. Configurar variables de entorno.
2. Ejecutar migraciones.
3. Ejecutar `seed_groups`.
4. Crear superusuario.
5. Configurar `MitreAttackSyncSettings`.
6. Configurar cron externo para `sync_mitre_attack_scheduled`.
7. Configurar LDAP solo si aplica.
8. Montar volumen de `MEDIA_ROOT`.
9. Ejecutar tests y check de migraciones antes de desplegar.
