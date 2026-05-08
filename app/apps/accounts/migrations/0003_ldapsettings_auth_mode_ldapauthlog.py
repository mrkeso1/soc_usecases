# Generated manually for LDAP operational settings and logging.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0002_ldapsettings"),
    ]

    operations = [
        migrations.AddField(
            model_name="ldapsettings",
            name="auth_mode",
            field=models.CharField(
                choices=[
                    ("ldap_with_fallback", "LDAP + fallback local"),
                    ("ldap_only", "Solo LDAP (superusers locales permitidos)"),
                    ("local_only", "Solo local"),
                ],
                default="ldap_with_fallback",
                max_length=32,
                verbose_name="Modo autenticación",
            ),
        ),
        migrations.CreateModel(
            name="LDAPAuthLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("event_type", models.CharField(choices=[("auth", "Autenticación"), ("test", "Prueba conexión")], default="auth", max_length=20)),
                ("username", models.CharField(blank=True, max_length=150)),
                ("server_uri", models.CharField(blank=True, max_length=255)),
                ("success", models.BooleanField(default=False)),
                ("message", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "verbose_name": "Log LDAP",
                "verbose_name_plural": "Logs LDAP",
                "ordering": ["-created_at"],
            },
        ),
    ]
