# Generated by Django 2.2.5 on 2021-09-07 05:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_auto_20210907_1404'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='email_secret',
            field=models.CharField(blank=True, default='', max_length=12),
        ),
    ]
