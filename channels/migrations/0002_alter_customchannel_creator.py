# Generated by Django 5.1.4 on 2025-01-17 13:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('channels', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customchannel',
            name='creator',
            field=models.CharField(max_length=255),
        ),
    ]
