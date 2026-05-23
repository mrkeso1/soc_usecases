# Migraciones

El historial actual de `apps.usecases` contiene migraciones intermedias donde
algunos campos de `MitreAttack` se agregaron, quitaron y volvieron a agregar
antes de estabilizarse en `0021`.

No se deben editar ni borrar migraciones ya publicadas si pueden estar aplicadas
en ambientes existentes. El estado final fue validado con:

```bash
docker compose run --rm web python manage.py makemigrations --check --dry-run
```

Resultado esperado:

```text
No changes detected
```

Si el proyecto necesita reducir deuda histórica de migraciones, hacerlo con un
squash planificado en una release controlada:

```bash
docker compose run --rm web python manage.py squashmigrations usecases 0023
```

Antes de reemplazar migraciones antiguas, validar backups, ambientes desplegados
y el plan de rollback. Mientras haya instalaciones que dependan del historial
actual, mantener las migraciones existentes intactas.
