from django.db import models
from django.utils import timezone
from django.utils.dateparse import parse_date
from core import models as core_models

# Create your models here.
class Reservation(core_models.TimeStampedModel):
    """Reservation Model Definition"""

    STATUS_PENDING = "pending"
    STATUS_CONFIRMED = "confirmed"
    STAUTS_CANCELED = "canceled"

    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_CONFIRMED, "Confirmed"),
        (STAUTS_CANCELED, "Canceled"),
    )
    status = models.CharField(
        max_length=12, choices=STATUS_CHOICES, default=STATUS_PENDING
    )
    check_in = models.DateField()
    check_out = models.DateField()
    guest = models.ForeignKey(
        "users.User", on_delete=models.CASCADE, related_name="reservations"
    )
    room = models.ForeignKey(
        "rooms.Room", on_delete=models.CASCADE, related_name="reservations"
    )

    def __str__(self):
        return f"{self.room} - {self.check_in}"

    def in_progress(self):
        now = timezone.localtime()
        now = parse_date(timezone.localtime().strftime("%Y-%m-%d"))
        return now > self.check_in and now < self.check_out
    in_progress.boolean = True

    def is_finished(self):
        now = timezone.localtime()
        now = parse_date(timezone.localtime().strftime("%Y-%m-%d"))
        return now > self.check_out
    is_finished.boolean = True