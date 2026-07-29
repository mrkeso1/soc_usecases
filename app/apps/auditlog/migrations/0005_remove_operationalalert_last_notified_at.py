from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("auditlog", "0004_actionratelimit"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="operationalalert",
            name="last_notified_at",
        ),
    ]
