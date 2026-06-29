# Arquitectura de Apps

## Principio

`usecases.UseCase` es el inventario maestro. Ninguna app debe crear otro inventario paralelo de casos de uso. Las apps de dominio referencian `UseCase` y guardan solamente datos propios.

Este criterio permite integrar otro sistema sin copiar modelos legacy ni usar `managed = False`.

## Mapa Actual

| App | Responsabilidad | Modelos principales |
| --- | --- | --- |
| `usecases` | Inventario, reglas, import/export, changelog. | `UseCase`, `UseCaseRuleCondition`, `UseCaseChangeLog` |
| `sources` | Fuentes de eventos y taxonomia. | `EventSource`, `SourceCategory`, `SourceType`, `SourceDeliveryMethod`, `UseCaseSource` |
| `mitre` | ATT&CK, D3FEND, coverage y sync. | `MitreAttack`, `D3Fend`, `CoverageOverride`, `MitreAttackSyncSettings` |
| `dashboard` | Dashboards, PDF del dashboard y snapshots. | `DashboardReportSettings`, `MitreCoverageSnapshot` |
| `lifecycle` | Ciclos, periodos, revisiones, metricas y transiciones. | `LifecycleSettings`, `LifecycleReview`, `DetectionMetric`, `LifecycleTransition`, `LifecycleCycle`, `LifecyclePeriod`, `LifecyclePeriodMember` |
| `reports` | Centro de reportes y plantillas. | `ReportDownload`, `ReportTemplateConfig` |
| `sigma_tools` | Conversiones y backups tecnicos. | `SigmaConversion`, `UseCaseTechnicalBackup` |
| `controls` | Controles y versionado. | `Control`, `ControlVersion`, `ControlInventoryChange` |
| `access_control` | Administracion delegada de permisos. | Usa `Group`, `Permission`, `User` |
| `auditlog` | Auditoria central. | `AuditLog` |
| `accounts` | Usuario custom, LDAP y roles. | `User`, `LDAPSettings`, `LDAPAuthLog` |
| `integrations` | Entrada de inventarios externos. | Sin tablas propias por ahora |

## Relaciones Principales

```text
usecases.UseCase
  -> sources.UseCaseSource[]
  -> lifecycle.LifecycleReview[]
  -> lifecycle.DetectionMetric[]
  -> lifecycle.LifecycleTransition[]
  -> lifecycle.LifecyclePeriodMember[]
  -> mitre.MitreAttack[] via M2M
  -> mitre.D3Fend[] cache inferido via M2M
  -> sigma_tools.UseCaseTechnicalBackup[]
  -> controls.Control[] indirecto por gobierno operativo
  -> reports.ReportDownload[] por eventos/exportaciones
  -> auditlog.AuditLog[] por eventos centralizados
```

## Ruteo

Rutas primarias:

- `/usecases/`
- `/sources/`
- `/mitre/`
- `/lifecycle/`
- `/reports/`
- `/sigma/`
- `/controls/`
- `/access/`
- `/audit/`
- `/dashboard/`

Rutas legacy bajo `/usecases/` se mantienen como redirects temporales. Se pueden apagar con `ENABLE_LEGACY_USECASE_REDIRECTS=0` para validar el retiro definitivo:

- `/usecases/lifecycle/`
- `/usecases/attack-matrix/`
- `/usecases/d3fend-matrix/`
- `/usecases/coverage-admin/`

## Compatibilidad de Base de Datos

Algunos modelos movidos conservan `db_table = "usecases_*"` para no romper instalaciones existentes:

- `dashboard.DashboardReportSettings`
- `lifecycle.LifecycleSettings`
- `lifecycle.LifecycleReview`
- `mitre.MitreAttack`
- `mitre.D3Fend`
- `mitre.CoverageOverride`
- `mitre.MitreAttackSyncSettings`

No renombrar esas tablas sin una migracion planificada.

## Deuda Arquitectonica

1. Quedan mojibakes en migrations historicas; los archivos activos visibles tienen test de regresion de encoding.
2. Si se vuelve a usar `soc-control-manager-django-master/` como referencia, mantenerlo fuera del deploy y del repo final.
3. Cuando no haya usuarios de rutas legacy y `ENABLE_LEGACY_USECASE_REDIRECTS=0` funcione en staging, eliminar redirects viejos bajo `/usecases/`.

## Regla Para Futuras Integraciones

Si llega otra app con inventario propio:

1. Mapear sus campos hacia `usecases.UseCase`.
2. Crear estructuras propias solo cuando agreguen dominio nuevo.
3. Usar migraciones normales Django.
4. Evitar modelos duplicados y `managed = False`.
5. Registrar eventos relevantes en `auditlog`.
