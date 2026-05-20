# Requisitos técnicos

Este documento resume los requisitos técnicos mínimos y recomendados para operar SOC Use Cases Manager.

## Plataforma

- Python 3.12+.
- Django 6.0.5.
- PostgreSQL accesible desde la aplicación.
- Sistema operativo Linux recomendado para despliegue.
- Gunicorn como servidor WSGI en producción.

## Dependencias de sistema

- Compiladores/librerías necesarias para instalar wheels Python si no se usan wheels binarios.
- Conectividad TCP hacia PostgreSQL.
- Conectividad TCP hacia LDAP/LDAPS si se habilita autenticación LDAP.
- Volumen persistente para `MEDIA_ROOT` cuando se suban logos de reportes.

## Dependencias Python

Instalar desde la raíz del repositorio:

```bash
python -m pip install -r requirements.txt
```

Dependencias fijadas:

| Paquete | Uso |
| --- | --- |
| Django | Framework web. |
| psycopg[binary] | Driver PostgreSQL. |
| gunicorn | WSGI en producción. |
| python-dotenv | Variables de entorno. |
| openpyxl | Importación Excel. |
| requests | Integraciones HTTP/cargas auxiliares. |
| ldap3 | LDAP. |
| Pillow | Imágenes para logos. |
| reportlab | PDF. |

## Variables obligatorias en producción

- `SECRET_KEY`: valor secreto y único.
- `DEBUG=0`.
- `ALLOWED_HOSTS`: dominios/hosts válidos.
- `POSTGRES_DB`.
- `POSTGRES_USER`.
- `POSTGRES_PASSWORD`.
- `POSTGRES_HOST`.
- `POSTGRES_PORT`.

## Puertos y rutas

- Aplicación Django/Gunicorn: definido por el despliegue, usualmente `8000` interno.
- PostgreSQL: default `5432`.
- LDAP: usualmente `389` para LDAP o `636` para LDAPS.

## Comandos de validación

```bash
python app/manage.py check
python app/manage.py migrate --plan
python app/manage.py test
```

## Consideraciones de seguridad

- No usar el `SECRET_KEY` default en producción.
- Mantener `DEBUG=0` en producción.
- Usar HTTPS delante de Django.
- Restringir acceso a `/admin/`.
- Validar certificados si se usa LDAPS.
- Hacer backup de PostgreSQL y de `MEDIA_ROOT`.
