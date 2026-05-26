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

## Datos demo

Para levantar un entorno de prueba completo despues de clonar:

```bash
docker compose run --rm web python manage.py seed_demo_data
```

El comando crea usuarios, casos, ATT&CK, D3FEND, revisiones lifecycle, overrides de cobertura y configuraciones demo.

Usuarios:

| Usuario | Rol | Password default |
| --- | --- | --- |
| `demo_admin` | Admin | `Demo12345!` |
| `demo_analyst` | Analyst | `Demo12345!` |
| `demo_owner` | Analyst/control owner | `Demo12345!` |
| `demo_readonly` | ReadOnly | `Demo12345!` |

Para regenerar solo datos demo:

```bash
docker compose run --rm web python manage.py seed_demo_data --reset
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

### Linux cron

Si no hay un contenedor `web` siempre corriendo, usar `run`:

```cron
0 * * * * cd /opt/soc_usecases && /usr/bin/docker compose run --rm web python manage.py sync_mitre_attack_scheduled >> /var/log/soc-usecases-mitre.log 2>&1
```

Si el servicio `web` ya esta corriendo de forma permanente, usar `exec` evita crear un contenedor nuevo:

```cron
0 * * * * cd /opt/soc_usecases && /usr/bin/docker compose exec -T web python manage.py sync_mitre_attack_scheduled >> /var/log/soc-usecases-mitre.log 2>&1
```

### Windows Task Scheduler

Crear una tarea programada con:

- Program/script: `powershell.exe`
- Add arguments:

```powershell
-NoProfile -ExecutionPolicy Bypass -Command "cd C:\ruta\soc_usecases; docker compose run --rm web python manage.py sync_mitre_attack_scheduled"
```

Para un servicio ya levantado:

```powershell
-NoProfile -ExecutionPolicy Bypass -Command "cd C:\ruta\soc_usecases; docker compose exec -T web python manage.py sync_mitre_attack_scheduled"
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
