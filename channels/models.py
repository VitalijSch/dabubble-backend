from django.db import models
from accounts.models import CustomUser


class CustomChannel(models.Model):
    name = models.CharField(max_length=255)
    description = models.CharField(max_length=255, blank=True, null=True)
    creator = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="created_channels")
    members = models.ManyToManyField(
        CustomUser, related_name="channels", blank=True)

    def __str__(self):
        return self.name
