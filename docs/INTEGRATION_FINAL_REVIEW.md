# Revision de Integracion con `soc-control-manager-django-master`

Fecha original: 2026-06-24  
Actualizacion: 2026-06-27

## Resumen

La integracion se hizo por absorcion selectiva, no copiando el proyecto nuevo tal cual. Esa decision sigue siendo correcta:

- Inventario maestro en `apps.usecases.UseCase`.
- Apps propias con migraciones normales.
- Sin `managed = False`.
- Sin inventarios paralelos.
- Auditoria central.
- MITRE ATT&CK/D3FEND como diferencial del proyecto actual.

El proyecto nuevo queda como referencia visual/funcional, no como codigo productivo directo.

## Funcionalidades Ya Absorbidas

| Funcion del proyecto nuevo | Estado actual |
| --- | --- |
| Shell visual mas profesional | Parcialmente incorporado en `base.html`, topbar y estilos comunes. |
| Fuentes de eventos | Implementado en `apps.sources`. |
| Taxonomia categoria/subcategoria | Implementado con `SourceCategory`. |
| Tipos de fuente | Implementado con `SourceType`. |
| Metodo de envio/ingesta | Implementado con `SourceDeliveryMethod`. |
| Lifecycle con modal de revision | Implementado en `apps.lifecycle`. |
| Ciclo anual/periodos | Implementado con `LifecycleCycle`, `LifecyclePeriod`, `LifecyclePeriodMember`. |
| Reportes configurables | Implementado con `ReportTemplateConfig`. |
| Preview de reportes | Implementado con preview real e iframe PDF. |
| Backups tecnicos | Implementado en `apps.sigma_tools.UseCaseTechnicalBackup`. |
| Backup desde regla de inventario | Implementado desde `UseCase.full_rule_text` y condiciones. |
| Controles | Implementado en `apps.controls`. |
| Administracion de accesos | Implementado en `apps.access_control`. |
| Conversion EPL/Sigma | Implementado en `apps.sigma_tools`. |

## Funcionalidades Que No Se Copiaron

No se copiaron modelos legacy del proyecto nuevo:

- `Alert`
- `AlertEventSource`
- `AlertVersion`
- `UseCaseInventoryChange`
- `UseCaseInventoryVersionState`
- `LegacyUser`
- `AccessRole`
- modelos `managed=False`

Motivo: duplicaban dominio o dependian de tablas externas. En este proyecto se usan modelos propios y relaciones Django reales.

## Rutas Finales

| Dominio | Ruta |
| --- | --- |
| Inventario | `/usecases/` |
| Fuentes | `/sources/` |
| Catalogos de fuentes | `/sources/admin/catalog/` |
| Lifecycle | `/lifecycle/` |
| Periodos lifecycle | `/lifecycle/periods/` |
| MITRE ATT&CK | `/mitre/attack-matrix/` |
| D3FEND | `/mitre/d3fend-matrix/` |
| Admin cobertura | `/mitre/coverage-admin/` |
| Reportes | `/reports/` |
| Plantillas PDF | `/reports/template/` |
| Sigma | `/sigma/epl-to-sigma/` y `/sigma/converter/` |
| Backups | `/sigma/backups/` |
| Controles | `/controls/` |
| Auditoria | `/audit/` |
| Accesos | `/access/admin/` |

Rutas legacy bajo `/usecases/` se mantienen como redirects temporales.

## Lo Que Sigue Pendiente

### 1. Limpieza de Encoding

Resuelto para archivos activos visibles: hay test de regresion de encoding sobre codigo, templates, static y docs. Pueden quedar mojibakes en migrations historicas.

### 2. Admin Classes en Apps Finales

Resuelto: los registros admin de MITRE, lifecycle y dashboard viven en sus apps finales:

- `apps.mitre.admin`
- `apps.lifecycle.admin`
- `apps.dashboard.admin`

### 3. Tests Visuales

La suite funcional esta verde, pero faltan pruebas visuales/browser para:

- dashboard ejecutivo;
- dashboard MITRE;
- matrices;
- fuentes;
- inventario edit/detail;
- lifecycle modal;
- report preview;
- modo claro/oscuro.

### 4. Limpieza del Directorio de Referencia

Resuelto: `soc-control-manager-django-master/` fue eliminado del workspace y agregado a `.gitignore`.

### 5. Consolidacion CSS

Parcialmente resuelto: el CSS grande del dashboard ejecutivo se movio a `app/static/css/dashboard-executive.css`. Todavia quedan templates secundarios con CSS inline que conviene ir moviendo por tandas.

## Decision Final

Mantener el modelo actual:

```text
usecases.UseCase
  -> sources
  -> lifecycle
  -> mitre
  -> dashboard
  -> reports
  -> sigma_tools/backups
  -> auditlog
```

No volver a un modelo monolitico ni copiar tablas legacy.
