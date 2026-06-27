# Migraciones

El historial de `apps.usecases` conserva migraciones historicas previas al split de apps. Algunas tablas movidas a `dashboard`, `lifecycle` y `mitre` mantienen `db_table = "usecases_*"` para no romper bases existentes.

No editar ni borrar migraciones ya publicadas si pueden estar aplicadas en ambientes existentes.

Estado validado:

```bash
docker compose exec web python manage.py makemigrations --check --dry-run
```

Resultado esperado:

```text
No changes detected
```

Migraciones relevantes recientes:

- `0026_split_domain_model_state`: separa estado de modelos movidos.
- `0027_alter_usecase_blocking_type_and_more`: ajustes posteriores del inventario.
- `0028_usecase_full_rule_text_and_more`: agrega regla completa, descripcion funcional y condiciones de regla por caso.

Si se necesita reducir deuda historica, hacerlo con un squash planificado en una release controlada y solo si se confirma que no hay instalaciones dependientes del historial actual.

Ejemplo orientativo:

```bash
docker compose exec web python manage.py squashmigrations usecases 0028
```

Antes de reemplazar migraciones antiguas:

1. Confirmar backup de DB.
2. Validar ambientes desplegados.
3. Definir rollback.
4. Ejecutar suite completa.
5. Verificar `makemigrations --check --dry-run`.
