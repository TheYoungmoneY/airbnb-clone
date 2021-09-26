from django.db import models
from core import managers as core_managers

# Create your models here.
class TimeStampedModel(models.Model):

    """ Time Stamped Model """

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    objects = core_managers.CustomModelManager()
    
    class Meta:
        abstract = True