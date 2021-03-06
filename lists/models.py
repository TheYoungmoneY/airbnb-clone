from django.db import models
from core import models as core_models

# Create your models here.
class List(core_models.TimeStampedModel):
    """List Model Definition"""

    name = models.CharField(max_length=80)
    user = models.ForeignKey(
        "users.User", on_delete=models.CASCADE, related_name="lists"
    )
    room = models.ManyToManyField("rooms.Room", related_name="lists", blank=True)

    def __str__(self):
        return self.name

    def count_rooms(self):
        return self.room.count()
    count_rooms.short_description = "Number of Rooms"