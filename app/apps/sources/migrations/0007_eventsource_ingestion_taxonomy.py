import django.db.models.deletion
from django.db import migrations, models


def seed_delivery_methods(apps, schema_editor):
    SourceDeliveryMethod = apps.get_model("sources", "SourceDeliveryMethod")
    SourceCategory = apps.get_model("sources", "SourceCategory")
    SourceType = apps.get_model("sources", "SourceType")
    defaults = [
        ("syslog", "Syslog"),
        ("api", "API"),
        ("agent", "Agente"),
        ("collector", "Collector"),
        ("forwarder", "Forwarder"),
        ("webhook", "Webhook"),
        ("manual", "Manual"),
    ]
    for code, name in defaults:
        SourceDeliveryMethod.objects.get_or_create(code=code, defaults={"name": name})

    source_types = [
        ("siem", "SIEM"),
        ("edr", "EDR"),
        ("firewall", "Firewall"),
        ("identity", "Identidad"),
        ("cloud", "Cloud"),
        ("network", "Red"),
        ("application", "Aplicacion"),
        ("other", "Otro"),
    ]
    for code, name in source_types:
        SourceType.objects.get_or_create(code=code, defaults={"name": name})

    taxonomy = {
        "Aplicacion": ["Linux / Unix", "Windows", "Base de datos", "Web"],
        "Cloud": ["AWS", "Azure", "GCP", "SaaS"],
        "Identidad": ["Active Directory", "Entra ID", "PAM", "IAM"],
        "SIEM": ["Collector", "Parser", "Correlacion"],
        "Endpoint": ["EDR", "Antivirus", "Sistema operativo"],
        "Network": ["Firewall", "Proxy", "VPN", "IDS / IPS"],
        "Email": ["Gateway", "Exchange", "M365"],
    }
    for category_name, subcategories in taxonomy.items():
        category, _created = SourceCategory.objects.get_or_create(name=category_name, parent=None)
        for subcategory_name in subcategories:
            SourceCategory.objects.get_or_create(name=subcategory_name, parent=category)


class Migration(migrations.Migration):

    dependencies = [
        ("sources", "0006_alter_sourcecategory_options_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="SourceDeliveryMethod",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("code", models.SlugField(max_length=40, unique=True, verbose_name="Codigo")),
                ("name", models.CharField(max_length=80, unique=True, verbose_name="Nombre")),
                ("description", models.TextField(blank=True, verbose_name="Descripcion")),
                ("is_active", models.BooleanField(default=True, verbose_name="Activo")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Metodo de envio",
                "verbose_name_plural": "Metodos de envio",
                "ordering": ["name"],
            },
        ),
        migrations.AddField(
            model_name="eventsource",
            name="protection",
            field=models.CharField(
                choices=[
                    ("internal", "Interna"),
                    ("external", "Externa"),
                    ("mixed", "Mixta"),
                    ("third_party", "Tercero"),
                ],
                default="internal",
                max_length=24,
                verbose_name="Proteccion",
            ),
        ),
        migrations.AddField(
            model_name="eventsource",
            name="delivery_method",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="sources",
                to="sources.sourcedeliverymethod",
                verbose_name="Metodo de envio",
            ),
        ),
        migrations.AddField(
            model_name="eventsource",
            name="service_account",
            field=models.CharField(blank=True, max_length=160, verbose_name="Cuenta de servicio"),
        ),
        migrations.CreateModel(
            name="SourceAlias",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("alias", models.CharField(max_length=180, unique=True, verbose_name="Alias")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "source",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="aliases",
                        to="sources.eventsource",
                        verbose_name="Fuente",
                    ),
                ),
            ],
            options={
                "verbose_name": "Alias de fuente",
                "verbose_name_plural": "Aliases de fuentes",
                "ordering": ["alias"],
            },
        ),
        migrations.RunPython(seed_delivery_methods, migrations.RunPython.noop),
    ]
