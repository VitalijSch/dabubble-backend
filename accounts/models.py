import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator


class CustomUser(AbstractUser):
    username = models.CharField(max_length=255, unique=False, validators=[
                                RegexValidator(regex=r'^[\w.@+\-_\s]+$')])
    email = models.EmailField(unique=True)
    uploaded_avatar = models.ImageField(
        upload_to='avatars/', blank=True, null=True)
    selected_avatar = models.CharField(max_length=255, blank=True, null=True)
    is_terms_accepted = models.BooleanField(default=True)
    is_online = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email


class PasswordResetToken(models.Model):
    email = models.CharField(max_length=255)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    def __str__(self):
        return self.email
