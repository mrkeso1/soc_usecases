# Operacion

## Comandos frecuentes

```bash
docker compose run --rm web python manage.py migrate
docker compose run --rm web python manage.py seed_groups
docker compose run --rm web python manage.py test
docker compose run --rm web python manage.py makemigrations --check --dry-run
```

## Datos base

1. Ejecutar migraciones.
2. Ejecutar `seed_groups`.
3. Crear superusuario.
4. Cargar ATT&CK:

```bash
docker compose run --rm web python manage.py load_mitre_attack
```

5. Cargar D3FEND:

```bash
docker compose run --rm web python manage.py load_d3fend
```

## Sincronizacion programada MITRE

La programacion se guarda en Django Admin:

```text
Usecases > Configuraciones sync MITRE
```

Crear una configuracion activa, por ejemplo:

- `interval_value`: `24`
- `interval_unit`: `hours`

Luego configurar el cron externo para invocar el comando de forma frecuente. Ejemplo cada hora:

```cron
0 * * * * cd /ruta/soc_usecases && docker compose run --rm web python manage.py sync_mitre_attack_scheduled
```

El comando no descarga nada si no vencio el intervalo guardado en DB.

Para probar manualmente:

```bash
docker compose run --rm web python manage.py sync_mitre_attack_scheduled --force
```

## LDAP

- Crear una configuracion en `LDAPSettings`.
- Usar `Probar conexion` antes de activarla.
- Usar `Activar` para dejarla como unica activa.
- Revisar `LDAPAuthLog` ante errores.

## PDF

- Configurar titulo, subtitulo, footer y logo en `DashboardReportSettings`.
- Probar `/dashboard/export/pdf/`.
- Mantener persistente `MEDIA_ROOT` si se suben logos.

## CI

El workflow `.github/workflows/django.yml` ejecuta:

```bash
docker compose run --rm web python manage.py test
docker compose run --rm web python manage.py makemigrations --check --dry-run
```
