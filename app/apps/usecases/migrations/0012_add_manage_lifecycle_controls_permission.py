# Generated manually to make lifecycle-wide edit access explicit.

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("usecases", "0011_lifecyclereview_unique_active_settings"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="usecase",
            options={
                "ordering": ["name"],
                "permissions": [
                    ("approve_usecase", "Can approve use case"),
                    ("promote_usecase", "Can promote use case to production"),
                    ("review_usecase", "Can review use case"),
                    ("manage_lifecycle_controls", "Can manage all lifecycle controls"),
                    ("retire_usecase", "Can retire use case"),
                ],
            },
        ),
    ]
