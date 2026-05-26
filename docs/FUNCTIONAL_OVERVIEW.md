# Funciones del sistema

Este mapa sirve como punto de partida para entender que hace cada parte del proyecto.

## Cuentas y acceso

- `apps.accounts.models.User`: usuario custom con `display_name`, `ldap_dn` y `area`.
- `LDAPSettings`: configuracion LDAP activa/inactiva, modo de login y parametros de busqueda.
- `LDAPAuthLog`: auditoria de pruebas LDAP y autenticaciones.
- `roles.py`: reglas de rol `Admin`, `Analyst` y `ReadOnly`.
- `seed_groups`: normaliza grupos y permisos base.

## Catalogos

- `MitreAttack`: tecnicas ATT&CK con ID externo, nombre, tactica y estado habilitado.
- `D3Fend`: controles D3FEND con codigo, categoria, descripcion y relacion con ATT&CK.
- `CoverageOverride`: capa manual para marcar cobertura por herramienta externa o excluir elementos que no aplican.

## Sincronizacion MITRE

- `mitre_sync.fetch_mitre_attack_enterprise`: descarga el dataset Enterprise ATT&CK.
- `mitre_sync.load_mitre_attack_data`: transforma STIX en registros `MitreAttack`.
- `mitre_sync.run_scheduled_mitre_attack_sync`: valida intervalo DB, ejecuta la carga y actualiza auditoria.
- `load_mitre_attack`: comando manual historico, siempre descarga y actualiza.
- `sync_mitre_attack_scheduled`: comando pensado para cron; respeta `MitreAttackSyncSettings`.

## Casos de uso

- `UseCase`: inventario operativo, estado, severidad, owner, lifecycle, ATT&CK y D3FEND.
- `UseCase.sync_d3fends_from_attacks`: infiere D3FEND desde ATT&CK relacionado.
- `UseCaseChangeLog`: registra diffs relevantes cuando se edita un caso.
- `bulk_updates.py`: aplica cambios masivos con validacion y permisos por ownership.

## Dashboard y cobertura

- `dashboard.py`: calcula KPIs de cobertura para UI y PDF.
- `attack_matrix.py`: matriz ATT&CK por tactica/tecnica.
- `d3fend_matrix.py`: matriz D3FEND con cobertura inferida.
- `coverage_admin.py`: arma filas, filtros y contadores del administrador de cobertura.
- `coverage_overrides.py`: resuelve estados manuales, busqueda normalizada y actualizacion de overrides.

## Lifecycle

- `LifecycleSettings`: intervalo activo para proxima revision.
- `LifecycleReview`: evidencia historica de controles finalizados.
- `lifecycle.py`: construye vista de gestion, finalizacion y reasignacion de responsables.

## Reportes

- `DashboardReportSettings`: branding del PDF.
- `reports.py`: genera PDF con ReportLab usando el mismo contexto del dashboard.
- `export_usecases_csv`: exporta inventario productivo filtrado.

## Vistas HTTP

- `views.py` mantiene las funciones request/response.
- La logica de negocio mas pesada se fue moviendo a modulos dedicados para que las vistas deleguen.
- Los permisos se centralizan en `permissions.py`.
