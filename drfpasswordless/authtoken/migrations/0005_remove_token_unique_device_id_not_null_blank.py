# Generated by Django 3.2.18 on 2024-10-17 05:42

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authtoken', '0004_auto_20240927_1224'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='token',
            name='unique_device_id_not_null_blank',
        ),
    ]

