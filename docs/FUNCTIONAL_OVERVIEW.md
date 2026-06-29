# Mapa Funcional

## Cuentas y Acceso

- `accounts.User`: usuario custom con datos LDAP y area.
- `LDAPSettings`: configuracion activa/inactiva, modo LDAP, URI, filtros, DN y bind.
- `LDAPAuthLog`: trazabilidad de pruebas LDAP y autenticaciones.
- `seed_groups`: normaliza grupos `Admin`, `Analyst` y `ReadOnly`.
- `access_control`: consola funcional para asignar permisos sin entrar al Django Admin.

## Inventario

- `UseCase`: inventario maestro.
- `UseCaseRuleCondition`: condiciones de regla con tipo `Incluir` o `Excluir`, campo, operador, valor y orden.
- `full_rule_text`: regla completa pegada desde SIEM/EPL/Sigma/consulta original.
- `functional_description`: descripcion funcional para analistas y auditoria.
- `UseCaseChangeLog`: diffs relevantes al editar un caso.
- `bulk_updates.py`: actualizacion masiva con permisos por ownership.
- Importacion Excel `.xlsx`, exportacion Excel y CSV.

## Fuentes de Eventos

- `EventSource`: fuente normalizada con proteccion, tipo, categoria/subcategoria, metodo de envio, puerto, protocolo, host y cuenta de servicio.
- `SourceCategory`: categoria y subcategoria administrables.
- `SourceType`: tipos usados en el selector de alta.
- `SourceDeliveryMethod`: metodos de envio/ingesta.
- `UseCaseSource`: vinculo many-to-many controlado entre caso y fuente.

Regla de importacion:

- `DISPOSITIVO` queda como campo legacy del inventario.
- `FUENTES` alimenta `EventSource` y vinculos.
- Si una fuente en Excel no existe, se crea como activa y tipo `Otro`.
- Si `FUENTES` viene vacio, no se usa `DISPOSITIVO` como reemplazo.

## MITRE ATT&CK y D3FEND

- `MitreAttack`: tecnicas ATT&CK habilitables.
- `D3Fend`: tecnicas/controles D3FEND habilitables.
- `CoverageOverride`: cobertura manual por herramienta o exclusion/no aplica.
- `MitreAttackSyncSettings`: agenda y resultado de sincronizacion completa.
- `sync_security_frameworks_scheduled`: sync completo ATT&CK + D3FEND + mappings + recalculo de casos.
- `run_mitre_scheduler`: loop usado por el servicio Docker `mitre_scheduler`.

La pagina D3FEND DAO (`https://d3fend.mitre.org/dao/`) se usa como contexto conceptual. El sync automatico usa fuentes machine-readable oficiales y no scrapea `/dao/`.

## Dashboard

- `/dashboard/`: resumen ejecutivo.
- `/dashboard/mitre/`: cobertura MITRE/D3FEND.
- `dashboard.dashboard`: builders de metricas.
- `MitreCoverageSnapshot`: indice diario para timeline de cobertura.
- `capture_mitre_coverage_snapshot`: captura el estado diario.

El score MITRE pondera:

- ATT&CK tecnicas habilitadas cubiertas.
- ATT&CK tacticas habilitadas cubiertas al 100%.
- D3FEND Detect equivalente.
- D3FEND Detect cubierto al 100%.

## Ciclo de Vida

- `/lifecycle/`: bandeja y revision.
- `/lifecycle/periods/`: administracion de fechas de periodos.
- `LifecycleCycle`: ciclo anual.
- `LifecyclePeriod`: periodos configurables dentro del ciclo.
- `LifecyclePeriodMember`: casos incluidos por periodo.
- `LifecycleReview`: evidencia de revision.
- `DetectionMetric`: indicador por caso/periodo con alertas, incidentes reales, falsos positivos, precision, efectividad y estado.
- `LifecycleTransition`: log explicito de cambios de estado lifecycle, reasignaciones, resets de periodo y cierre/inicio de ciclo.

La revision registra logica funcional, fuentes activas, Event IDs vigentes, campos existentes, necesidad de ajuste, optimizacion o baja, alertas, falsos positivos e incidentes.

Al guardar una revision se actualizan en forma automatica:

- el estado de validacion del caso de uso;
- el registro `LifecycleReview`;
- una metrica `DetectionMetric` para el periodo;
- una transicion `LifecycleTransition` visible desde auditoria central.

## Reportes

- `/reports/`: centro de reportes.
- `/reports/template/`: configuracion de plantillas.
- Preview real en `/reports/<tipo>/preview/`.
- PDF inline en `/reports/<tipo>/preview/pdf/`.
- Descarga en `/reports/<tipo>/download/`.
- `ReportTemplateConfig`: logo, colores, footer, labels, secciones y visibilidad.
- `ReportDownload`: trazabilidad de descargas.

Tipos:

- Ejecutivo.
- MITRE/D3FEND.
- Inventario.
- Ciclo de vida.
- Controles.

## Sigma Tools y Backups

- `/sigma/epl-to-sigma/`: conversion EPL a Sigma.
- `/sigma/converter/`: conversion Sigma a destino SIEM.
- `/sigma/backups/`: backups tecnicos versionados.
- `UseCaseTechnicalBackup`: version, tipo, logica, Sigma, checksum, vigente y notas.

El backup tecnico puede generarse desde:

1. Conversion Sigma Tools.
2. Formulario manual.
3. Regla cargada en inventario (`full_rule_text`).
4. Condiciones de regla si no hay regla completa.

## Auditoria

- `AuditRequestMiddleware`: registra POST/PUT/PATCH/DELETE exitosos.
- `auditlog.service.audit`: eventos explicitos de negocio.
- `/audit/`: vista central con filtros.
- Export CSV/XLSX desde auditoria.
- Eventos de ciclo de vida incluyen revisiones, metricas de deteccion y transiciones de periodo/ciclo.

Los historiales locales viejos redirigen o deben quedar ocultos a favor de auditoria central.

## Controles

- Inventario de controles.
- Versionado de controles.
- Historial centralizable por auditoria.
- Reporte de controles desde `reports`.

## Integraciones

- `apps.integrations.inventory.sync_inventory_records`: normaliza records externos y hace upsert sobre `UseCase`.
- `import_external_inventory`: comando para JSON/CSV.
- No crea inventario paralelo.
