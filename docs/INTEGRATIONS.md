# Integraciones externas

## Objetivo

La app `integrations` es la capa de entrada para conectar otro sistema sin duplicar inventarios.

El inventario maestro sigue siendo `usecases.UseCase`. Las integraciones deben normalizar datos externos y crear/actualizar casos en esa tabla.

## Adaptador de inventario

Modulo principal:

```python
from apps.integrations.inventory import sync_inventory_records
```

Uso basico:

```python
result = sync_inventory_records([
    {
        "name": "External brute force",
        "status": "Produccion",
        "production_date": "2026-01-02",
        "mitre_attack_ids": ["T1110"],
        "severity": "High",
    }
])
```

El adaptador acepta alias comunes:

- `name`, `nombre`, `nombre_netwitness`, `usecase`, `use_case`
- `device`, `dispositivo`, `platform`, `fuente`
- `status`, `estado`, `lifecycle_status`
- `production_date`, `fecha_produccion`
- `mitre_attack_ids`, `mitre_attacks`, `attack_ids`, `attack`
- `is_enabled`, `habilitado`, `enabled`

## Reglas

- Si el caso no existe, se crea.
- Si existe y `update_existing=True`, se actualiza.
- Si existe y `update_existing=False`, se omite.
- El match inicial se hace por `name`.
- Los ATT&CK deben existir previamente en el catalogo MITRE para asociarse.
- Si un caso entra en produccion, se validan las reglas del inventario, incluida la relacion ATT&CK.
- No se crean tablas nuevas para integracion en esta fase.

## Resultado

`sync_inventory_records` devuelve:

- `created`
- `updated`
- `skipped`
- `errors`
- `ok`

## Proximo paso para una app externa real

Cuando se defina el origen, agregar un cliente especifico:

- API HTTP: `apps.integrations.clients.<nombre>.py`
- archivo Excel/CSV externo: comando de management que lea el archivo y llame al adaptador
- DB externa: job que consulte la DB origen y llame al adaptador

La regla es mantener el cliente separado del adaptador. El cliente trae datos; el adaptador decide como entran al inventario.

## Importar archivo externo

Comando disponible:

```bash
docker compose run --rm web python manage.py import_external_inventory /app/ruta/inventory.json
```

Formatos soportados:

- `.json`: lista de objetos o un objeto con `records`, `items`, `usecases` o `use_cases`.
- `.csv`: encabezados con alias soportados por el adaptador.

Opciones:

```bash
docker compose run --rm web python manage.py import_external_inventory /app/ruta/inventory.csv --dry-run
docker compose run --rm web python manage.py import_external_inventory /app/ruta/inventory.csv --no-update
```

- `--dry-run`: valida y calcula creados/actualizados sin guardar.
- `--no-update`: omite casos existentes y solo crea nuevos.
