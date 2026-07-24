from django.db import migrations, models


def seed_generic_rules(apps, schema_editor):
    Rule = apps.get_model("server_heatmap", "ServerNamingRule")
    rules = [
        (10, "Sistema operativo Linux", r"(^|[-_])(LIN|LNX|RHEL|UBU|CENTOS)([0-9]|[-_]|$)", "linux", ""),
        (11, "Sistema operativo Windows", r"(^|[-_])(WIN|W2K|W[0-9]{2})([0-9]|[-_]|$)", "windows", ""),
        (20, "Active Directory", r"(^|[-_])(AD|DC)([0-9]|[-_]|$)", "", "ad"),
        (21, "Base de datos", r"(^|[-_])(DB|SQL|ORA|PG)([0-9]|[-_]|$)", "", "database"),
        (22, "File server", r"(^|[-_])(FS|FILE)([0-9]|[-_]|$)", "", "fileserver"),
        (23, "Aplicaciones", r"(^|[-_])(APP|AP)([0-9]|[-_]|$)", "", "application"),
        (24, "Web", r"(^|[-_])(WEB|WWW|IIS)([0-9]|[-_]|$)", "", "web"),
        (25, "Correo", r"(^|[-_])(MAIL|SMTP|EXCH)([0-9]|[-_]|$)", "", "mail"),
    ]
    for priority, name, pattern, os_family, server_type in rules:
        Rule.objects.get_or_create(
            name=name,
            defaults={"priority": priority, "pattern": pattern, "os_family": os_family, "server_type": server_type},
        )


class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [
        migrations.CreateModel(
            name="ServerAsset",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("hostname", models.CharField(max_length=255, unique=True, verbose_name="Hostname")),
                ("display_name", models.CharField(blank=True, max_length=255, verbose_name="Nombre visible")),
                ("domain", models.CharField(blank=True, max_length=180, verbose_name="Dominio")),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True, verbose_name="Dirección IP")),
                ("os_family", models.CharField(choices=[("windows", "Windows"), ("linux", "Linux"), ("unix", "Unix"), ("other", "Otro"), ("unknown", "Sin identificar")], default="unknown", max_length=20, verbose_name="Sistema operativo")),
                ("server_type", models.CharField(choices=[("ad", "Active Directory"), ("application", "Aplicaciones"), ("database", "Base de datos"), ("fileserver", "File server"), ("web", "Web"), ("mail", "Correo"), ("security", "Seguridad"), ("network", "Red / infraestructura"), ("other", "Otro"), ("unknown", "Sin identificar")], default="unknown", max_length=30, verbose_name="Tipo de servidor")),
                ("application_name", models.CharField(blank=True, max_length=180, verbose_name="Aplicación interna")),
                ("environment", models.CharField(blank=True, max_length=80, verbose_name="Ambiente")),
                ("in_active_directory", models.BooleanField(default=False, verbose_name="Presente en AD")),
                ("in_siem", models.BooleanField(default=False, verbose_name="Con ingesta en SIEM")),
                ("is_enabled", models.BooleanField(default=True, verbose_name="Habilitado")),
                ("classification_source", models.CharField(choices=[("auto", "Automática por nomenclatura"), ("manual", "Manual")], default="auto", max_length=20, verbose_name="Origen de clasificación")),
                ("notes", models.TextField(blank=True, verbose_name="Notas")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"verbose_name": "Servidor", "verbose_name_plural": "Servidores", "ordering": ["hostname"]},
        ),
        migrations.CreateModel(
            name="ServerNamingRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=120, unique=True, verbose_name="Nombre")),
                ("pattern", models.CharField(help_text="Se evalúa sin distinguir mayúsculas. Ejemplo: (^|[-_])DB([0-9]|[-_]|$)", max_length=255, verbose_name="Expresión regular")),
                ("os_family", models.CharField(blank=True, choices=[("windows", "Windows"), ("linux", "Linux"), ("unix", "Unix"), ("other", "Otro"), ("unknown", "Sin identificar")], max_length=20, verbose_name="Sistema operativo sugerido")),
                ("server_type", models.CharField(blank=True, choices=[("ad", "Active Directory"), ("application", "Aplicaciones"), ("database", "Base de datos"), ("fileserver", "File server"), ("web", "Web"), ("mail", "Correo"), ("security", "Seguridad"), ("network", "Red / infraestructura"), ("other", "Otro"), ("unknown", "Sin identificar")], max_length=30, verbose_name="Tipo sugerido")),
                ("priority", models.PositiveIntegerField(default=100, help_text="Las reglas con menor número se evalúan primero.", verbose_name="Prioridad")),
                ("is_active", models.BooleanField(default=True, verbose_name="Activa")),
                ("notes", models.TextField(blank=True, verbose_name="Notas")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"verbose_name": "Regla de nomenclatura", "verbose_name_plural": "Reglas de nomenclatura", "ordering": ["priority", "name"]},
        ),
        migrations.RunPython(seed_generic_rules, migrations.RunPython.noop),
    ]
