# Generated by Django 5.1.7 on 2025-03-27 07:27

import dplapp.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dplapp', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='tokensmodel',
            name='can_reset_password',
            field=models.BooleanField(default=dplapp.models.ReturnFalse),
        ),
    ]
