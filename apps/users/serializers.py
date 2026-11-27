from typing import Any

from django.conf import settings
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.files.uploadedfile import UploadedFile
from django.core.validators import FileExtensionValidator
from rest_framework import serializers

from .models import AVATAR_EXTENSIONS, DefaultAvatar, User


class UserSerializer(serializers.ModelSerializer[User]):
    # Declared so the schema says what the API really sends: "" when the user uploaded an avatar.
    default_avatar = serializers.ChoiceField(
        choices=DefaultAvatar.choices, allow_blank=True, read_only=True
    )

    class Meta:
        model = User
        fields = ("id", "email", "full_name", "avatar", "default_avatar", "date_joined")
        read_only_fields = ("id", "email", "avatar", "default_avatar", "date_joined")


class RegisterDetailsSerializer(serializers.Serializer[dict[str, Any]]):
    """The first sign-up step: name, email, password and privacy policy. No avatar yet.

    Used on its own to check the first step before the user picks an avatar, and as the base of
    `RegisterSerializer`, so both steps follow exactly the same rules.
    """

    full_name = serializers.CharField(max_length=150)
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(
        write_only=True, trim_whitespace=False, style={"input_type": "password"}
    )
    accept_privacy_policy = serializers.BooleanField(
        write_only=True, help_text="Must be `true`: the user has read the privacy policy."
    )

    def validate_email(self, value: str) -> str:
        email = value.strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError("Diese E-Mail-Adresse wird bereits verwendet.")
        return email

    def validate_accept_privacy_policy(self, value: bool) -> bool:
        if value is not True:
            raise serializers.ValidationError(
                "Bitte bestätige, dass du die Datenschutzerklärung gelesen hast."
            )
        return value

    def validate_password(self, value: str) -> str:
        """Run Django's password validators, including "too similar to name/email".

        This is a field check (not part of `validate`), so its errors come back together with the
        other field errors instead of only after they are fixed. Name and email are therefore
        taken as typed, before their own validation; that's fine for a similarity check.
        """
        raw = self.initial_data
        unsaved_user = User(
            email=raw.get("email") if isinstance(raw.get("email"), str) else "",
            full_name=raw.get("full_name") if isinstance(raw.get("full_name"), str) else "",
        )
        try:
            password_validation.validate_password(value, user=unsaved_user)
        except DjangoValidationError as error:
            raise serializers.ValidationError(list(error.messages)) from error
        return value


class RegisterSerializer(RegisterDetailsSerializer):
    """Sign-up data. Send `avatar` (an image file) or `default_avatar`, not both."""

    avatar = serializers.ImageField(
        required=False, validators=[FileExtensionValidator(AVATAR_EXTENSIONS)]
    )
    default_avatar = serializers.ChoiceField(choices=DefaultAvatar.choices, required=False)

    def validate_avatar(self, value: UploadedFile[bytes]) -> UploadedFile[bytes]:
        max_size: int = settings.AVATAR_MAX_UPLOAD_SIZE
        if value.size is not None and value.size > max_size:
            raise serializers.ValidationError(
                f"Das Bild ist zu groß (max. {max_size // (1024 * 1024)} MB)."
            )
        return value

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if bool(attrs.get("avatar")) == bool(attrs.get("default_avatar")):
            raise serializers.ValidationError(
                {"avatar": "Lade ein eigenes Profilbild hoch oder wähle einen Standard-Avatar."}
            )
        return attrs


class VerifyEmailSerializer(serializers.Serializer[dict[str, str]]):
    uid = serializers.CharField(max_length=64)
    token = serializers.CharField(max_length=128)
