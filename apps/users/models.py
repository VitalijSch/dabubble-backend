import uuid
from pathlib import PurePath
from typing import Any, ClassVar

from django.contrib.auth.models import AbstractUser, UserManager
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator
from django.db import models

AVATAR_EXTENSIONS = ["jpg", "jpeg", "png", "webp"]


class DefaultAvatar(models.TextChoices):
    """Built-in avatars a user can pick instead of uploading one. The frontend has the images."""

    AVATAR_1 = "avatar_1", "Avatar 1"
    AVATAR_2 = "avatar_2", "Avatar 2"
    AVATAR_3 = "avatar_3", "Avatar 3"
    AVATAR_4 = "avatar_4", "Avatar 4"
    AVATAR_5 = "avatar_5", "Avatar 5"
    AVATAR_6 = "avatar_6", "Avatar 6"


def avatar_upload_to(instance: User, filename: str) -> str:
    """Store uploads under a random name; never trust the client's file name."""
    return f"avatars/{uuid.uuid4().hex}{PurePath(filename).suffix.lower()}"


class EmailUserManager(UserManager["User"]):
    """User manager that uses the email address instead of a username."""

    use_in_migrations = True

    def _create_email_user(self, email: str, password: str | None, **extra_fields: Any) -> User:
        if not email:
            raise ValueError("Users must have an email address.")
        if not extra_fields.get("avatar"):
            # Users created outside the API (createsuperuser, shell) get a built-in avatar.
            extra_fields.setdefault("default_avatar", DefaultAvatar.AVATAR_1)
        user = self.model(email=self.normalize_email(email).lower(), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(  # type: ignore[override]
        self, email: str, password: str | None = None, **extra_fields: Any
    ) -> User:
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_email_user(email, password, **extra_fields)

    def create_superuser(  # type: ignore[override]
        self, email: str, password: str | None = None, **extra_fields: Any
    ) -> User:
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self._create_email_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom user model that logs in with email.

    Add fields here instead of creating a separate profile table.
    """

    username = None  # type: ignore[assignment]  # email replaces the username
    first_name = None  # type: ignore[assignment]  # replaced by full_name
    last_name = None  # type: ignore[assignment]  # replaced by full_name

    email = models.EmailField("email address", unique=True)
    full_name = models.CharField("full name", max_length=150)
    # Exactly one of these two is set (see the constraint below).
    avatar = models.ImageField(
        upload_to=avatar_upload_to,
        blank=True,
        validators=[FileExtensionValidator(AVATAR_EXTENSIONS)],
    )
    default_avatar = models.CharField(max_length=20, choices=DefaultAvatar.choices, blank=True)
    # Set when the user opens the link in the confirmation email.
    email_verified_at = models.DateTimeField("email verified at", null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = ["full_name"]

    objects: ClassVar[EmailUserManager] = EmailUserManager()

    class Meta(AbstractUser.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=(models.Q(avatar="") & ~models.Q(default_avatar=""))
                | (~models.Q(avatar="") & models.Q(default_avatar="")),
                name="users_user_exactly_one_avatar",
                violation_error_message="Upload an avatar or choose a default one, not both.",
            ),
        ]

    def clean(self) -> None:
        super().clean()
        if bool(self.avatar) == bool(self.default_avatar):
            raise ValidationError(
                {"default_avatar": "Upload an avatar or choose a default one, not both."}
            )

    def __str__(self) -> str:
        return self.email
