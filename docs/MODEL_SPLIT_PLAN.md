# Plan para mover modelos por app

## Estado actual

Los modelos de dominio ya se movieron a sus apps correspondientes conservando las tablas fisicas existentes con `db_table`.

Separacion aplicada:

- `dashboard`: `DashboardReportSettings`, views, builders, reportes y tests.
- `lifecycle`: `LifecycleSettings`, `LifecycleReview`, servicios, views y tests.
- `mitre`: `MitreAttack`, `D3Fend`, `CoverageOverride`, `MitreAttackSyncSettings`, matrices, coverage, sync, comandos y tests.
- `integrations`: adaptador de entrada para inventario externo.

`usecases` conserva el inventario maestro:

- `UseCase`
- `UseCaseChangeLog`

## Riesgo controlado

Mover un modelo Django de app cambia su `app_label`. Aunque se mantenga la misma tabla con `db_table`, Django tambien cambia:

- content types
- permisos
- nombres de rutas admin
- dependencias de migraciones
- referencias historicas en migraciones anteriores

Por eso se uso `SeparateDatabaseAndState`: las tablas no se dropean ni se crean de nuevo; solo cambia el estado de Django.

## Estrategia segura

1. Crear modelos destino con el mismo `db_table`. Hecho.
2. Usar migraciones `SeparateDatabaseAndState` para cambiar estado Django sin tocar tablas fisicas. Hecho.
3. Migrar content types y permisos. Hecho en `usecases.0026_split_domain_model_state`.
4. Actualizar imports por etapas. Hecho.
5. Probar admin, permisos, comandos y reportes. Hecho en tests automatizados.

## Migraciones relevantes

- `dashboard.0001_initial`
- `lifecycle.0001_initial`
- `mitre.0001_initial`
- `usecases.0026_split_domain_model_state`

## Recomendacion

Mantener futuras apps externas consumiendo `usecases.UseCase` como inventario maestro. Si agregan modelos propios, deben referenciar `UseCase` con `ForeignKey` o `OneToOneField` segun corresponda.
