# Generated by Django 5.1.4 on 2024-12-28 09:52

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_remove_customuser_avatar_customuser_selected_avatar_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='username',
            field=models.CharField(max_length=255, validators=[django.core.validators.RegexValidator(regex='^[\\w.@+\\-_\\s]+$')]),
        ),
    ]
