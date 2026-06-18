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

## Importacion y exportacion Excel

Desde la UI:

- `Inventario > Importar Excel`: carga archivos `.xlsx` o `.xlsm`.
- `Inventario > Importar Excel > Descargar plantilla`: descarga columnas compatibles.
- `Inventario > Exportar Excel`: descarga la vista filtrada.

Desde consola:

```bash
docker compose run --rm web python manage.py import_usecases archivo.xlsx --update
```

La importacion usa `NOMBRE NETWITNESS` como clave de actualizacion cuando se marca `--update` o `Actualizar existentes por nombre` en la UI.
La columna D3FEND se ignora porque D3FEND se infiere automaticamente desde MITRE ATT&CK.

## Sincronizacion programada de frameworks

La programacion se guarda en Django Admin:

```text
Usecases > Sincronizaciones de frameworks
```

Crear una configuracion activa, por ejemplo:

- `interval_value`: `24`
- `interval_unit`: `hours`

Luego configurar el cron externo para invocar el comando completo de forma frecuente. Ejemplo cada hora:

```cron
0 * * * * cd /ruta/soc_usecases && docker compose run --rm web python manage.py sync_security_frameworks_scheduled
```

El comando no descarga nada si no vencio el intervalo guardado en DB.
Cuando corre, ejecuta:

1. MITRE ATT&CK Enterprise.
2. D3FEND.
3. Mappings D3FEND->ATT&CK.
4. Normalizacion de codigos D3FEND.
5. Recalculo de D3FEND inferido en casos de uso.

Para probar manualmente:

```bash
docker compose run --rm web python manage.py sync_security_frameworks_scheduled --force
```

El comando anterior reemplaza al cron viejo `sync_mitre_attack_scheduled` para ambientes donde se necesita mantener ATT&CK y D3FEND alineados. El comando viejo sigue disponible si solo se quiere actualizar ATT&CK.

El boton manual dentro de la configuracion se llama `Ejecutar sync completo ATT&CK + D3FEND` y dispara la misma cadena completa.

### Linux cron

Si no hay un contenedor `web` siempre corriendo, usar `run`:

```cron
0 * * * * cd /opt/soc_usecases && /usr/bin/docker compose run --rm web python manage.py sync_security_frameworks_scheduled >> /var/log/soc-usecases-frameworks.log 2>&1
```

Si el servicio `web` ya esta corriendo de forma permanente, usar `exec` evita crear un contenedor nuevo:

```cron
0 * * * * cd /opt/soc_usecases && /usr/bin/docker compose exec -T web python manage.py sync_security_frameworks_scheduled >> /var/log/soc-usecases-frameworks.log 2>&1
```

### Windows Task Scheduler

Crear una tarea programada con:

- Program/script: `powershell.exe`
- Add arguments:

```powershell
-NoProfile -ExecutionPolicy Bypass -Command "cd C:\ruta\soc_usecases; docker compose run --rm web python manage.py sync_security_frameworks_scheduled"
```

Para un servicio ya levantado:

```powershell
-NoProfile -ExecutionPolicy Bypass -Command "cd C:\ruta\soc_usecases; docker compose exec -T web python manage.py sync_security_frameworks_scheduled"
```

## LDAP

- Crear una configuracion en `LDAPSettings`.
- Usar `Probar conexion` antes de activarla.
- Usar `Activar` para dejarla como unica activa.
- Revisar `LDAPAuthLog` ante errores.
- Revisar `logs/auth.log` para eventos de login, logout, login fallido y pruebas LDAP.

## Logs operativos

Docker monta la carpeta del host `./logs` dentro del contenedor en `/logs`.

Archivos principales:

| Archivo | Contenido |
| --- | --- |
| `logs/auth.log` | Login exitoso, logout, login fallido y eventos LDAP. |
| `logs/mitre_sync.log` | Descarga, omisiones, errores y resultados de sincronizacion MITRE/frameworks. |
| `logs/app.log` | Warnings/errores HTTP de Django. |

Los archivos rotan automaticamente al llegar a 5 MB y conservan 5 backups.

Para verlos en Linux:

```bash
tail -f logs/auth.log
tail -f logs/mitre_sync.log
```

En Windows PowerShell:

```powershell
Get-Content .\logs\auth.log -Wait
Get-Content .\logs\mitre_sync.log -Wait
```

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
