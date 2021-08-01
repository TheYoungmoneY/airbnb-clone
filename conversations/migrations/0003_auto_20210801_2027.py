# Generated by Django 2.2.5 on 2021-08-01 11:27

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('conversations', '0002_auto_20210416_2131'),
    ]

    operations = [
        migrations.AlterField(
            model_name='conversation',
            name='participants',
            field=models.ManyToManyField(blank=True, related_name='converstation', to=settings.AUTH_USER_MODEL),
        ),
    ]