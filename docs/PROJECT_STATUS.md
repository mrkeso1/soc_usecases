# Estado del Proyecto

Fecha de revision: 2026-06-29

## Resultado de Validacion

Comandos ejecutados:

```bash
docker compose exec web python manage.py test --keepdb
docker compose exec web python manage.py test apps.lifecycle apps.auditlog apps.usecases --keepdb
docker compose exec web python manage.py makemigrations --check --dry-run
```

Resultado:

- 108 tests OK.
- 32 tests focalizados OK para lifecycle, auditoria e inventario.
- Sin migraciones pendientes.
- `manage.py check` sin issues.

## Que Esta Bien

- La arquitectura modular esta funcionando: inventario en `usecases`, y dominios separados en `dashboard`, `lifecycle`, `mitre`, `sources`, `reports`, `sigma_tools`, `controls`, `auditlog`, `access_control`.
- Las rutas primarias ya estan fuera de `/usecases/` para MITRE y lifecycle.
- Las rutas legacy principales bajo `/usecases/` redirigen a las apps nuevas y se pueden apagar con `ENABLE_LEGACY_USECASE_REDIRECTS=0`.
- El inventario ya soporta regla completa, condiciones de regla y descripcion funcional.
- Los backups tecnicos ya pueden generarse desde la regla del inventario.
- Lifecycle ya genera metricas de deteccion por caso/periodo y transiciones auditables.
- Reportes tienen preview real y plantillas configurables.
- MITRE/D3FEND tienen scheduler Docker, admin de sync, logs y tests.
- Los registros de Django Admin ya viven en sus apps finales: `mitre`, `lifecycle`, `dashboard` y `usecases`.
- Los archivos activos visibles tienen guardrail de encoding para evitar mojibake nuevo.
- Fuentes de eventos ya tienen taxonomia, tipos y metodos de envio.
- Auditoria central concentra eventos de varias apps.
- CI existe y corre check, tests y migraciones.
- `soc-control-manager-django-master/` fue eliminado del workspace y agregado a `.gitignore`.
- Dashboard ejecutivo usa datos reales de calidad del inventario: fuentes, MITRE, regla/logica, documentacion y backup vigente.
- Hay smoke visual opcional con Playwright en `tools/visual_smoke_playwright.py`.

## Cosas Mal o Confusas

### 1. Encoding historico

Quedan strings con mojibake en migrations historicas. Los archivos activos de codigo, templates, static y docs se escanean con test de regresion para evitar que vuelva a entrar texto roto.

Impacto:

- No deberia aparecer en UI actual si los modelos activos estan correctos.
- Ensucia migrations antiguas, pero tocarlas puede generar ruido historico innecesario.

Recomendacion:

- Mantener el test de encoding activo.
- Evitar tocar migrations antiguas salvo que sea estrictamente necesario.
- Si se detecta mojibake visible, corregir el archivo activo y agregar cobertura si aplica.

### 2. Rutas legacy

Existen redirects bajo `/usecases/`:

- `/usecases/lifecycle/`
- `/usecases/attack-matrix/`
- `/usecases/d3fend-matrix/`
- `/usecases/coverage-admin/`

Impacto:

- Bueno para compatibilidad.
- Malo si se perpetua como API implicita.

- Mantener activas por defecto durante transicion.
- Apagarlas en staging con `ENABLE_LEGACY_USECASE_REDIRECTS=0`.
- Si no hay usuarios afectados, remover las rutas en una release posterior.

### 3. Tests visuales insuficientes

La suite funcional esta bien cubierta, pero no hay cobertura automatizada de:

- layout en claro/oscuro;
- PDF visual;
- matrices ATT&CK/D3FEND;
- report previews embebidos;
- formularios grandes de inventario/fuentes/lifecycle.

Recomendacion:

- Ejecutar el smoke Playwright antes de releases con UI.
- Priorizar dashboard, inventario edit, fuentes, lifecycle y report preview.

## Pendientes Recomendados

### Prioridad Alta

1. Probar manualmente en navegador:
   - alta/edicion inventario;
   - generar backup desde regla;
   - preview/download reportes;
   - sync MITRE manual desde admin;
   - fuentes con categoria/subcategoria dependiente.

### Prioridad Media

1. Ejecutar Playwright visual smoke y revisar screenshots.
2. Consolidar mas CSS inline de templates secundarios hacia archivos estaticos.
3. Agregar comandos de mantenimiento para limpiar snapshots/demo si hace falta.

### Prioridad Baja

1. Remover fisicamente rutas legacy despues de probar `ENABLE_LEGACY_USECASE_REDIRECTS=0` en staging.
2. No hacer squash de migrations ahora; reconsiderar solo si se confirma instalacion desde cero y sin DB historica.
3. Seguir mejorando textos de ayuda puntuales en formularios especializados.

## Checklist Antes de Commit/Deploy

```bash
docker compose exec web python manage.py check
docker compose exec web python manage.py test --keepdb
docker compose exec web python manage.py makemigrations --check --dry-run
```

Checklist manual:

- Dashboard ejecutivo.
- Dashboard MITRE.
- Inventario list/detail/edit.
- Fuentes list/new/admin catalog.
- Lifecycle revision.
- Reports preview/download.
- Sigma backups.
- Auditoria.
- Django Admin MITRE sync.
