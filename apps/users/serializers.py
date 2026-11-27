from typing import Any

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.files.uploadedfile import UploadedFile
from django.core.validators import FileExtensionValidator
from rest_framework import serializers

from .models import AVATAR_EXTENSIONS, DefaultAvatar, User


class UserSerializer(serializers.ModelSerializer[User]):
    class Meta:
        model = User
        fields = ("id", "email", "full_name", "avatar", "default_avatar", "date_joined")
        read_only_fields = ("id", "email", "avatar", "default_avatar", "date_joined")


class RegisterSerializer(serializers.Serializer[dict[str, Any]]):
    """Sign-up data. Send `avatar` (an image file) or `default_avatar`, not both."""

    full_name = serializers.CharField(max_length=150)
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(
        write_only=True, trim_whitespace=False, style={"input_type": "password"}
    )
    avatar = serializers.ImageField(
        required=False, validators=[FileExtensionValidator(AVATAR_EXTENSIONS)]
    )
    default_avatar = serializers.ChoiceField(choices=DefaultAvatar.choices, required=False)
    accept_privacy_policy = serializers.BooleanField(
        write_only=True, help_text="Must be `true`: the user has read the privacy policy."
    )

    def validate_email(self, value: str) -> str:
        email = value.strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return email

    def validate_avatar(self, value: UploadedFile[bytes]) -> UploadedFile[bytes]:
        max_size: int = settings.AVATAR_MAX_UPLOAD_SIZE
        if value.size is not None and value.size > max_size:
            raise serializers.ValidationError(
                f"The image is too large (max {max_size // (1024 * 1024)} MB)."
            )
        return value

    def validate_accept_privacy_policy(self, value: bool) -> bool:
        if value is not True:
            raise serializers.ValidationError("You must accept the privacy policy.")
        return value

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if bool(attrs.get("avatar")) == bool(attrs.get("default_avatar")):
            raise serializers.ValidationError(
                {"avatar": "Upload an avatar or choose a default one, not both."}
            )
        # Run Django's password validators, including "too similar to name/email".
        unsaved_user = User(email=attrs["email"], full_name=attrs["full_name"])
        try:
            validate_password(attrs["password"], user=unsaved_user)
        except DjangoValidationError as error:
            raise serializers.ValidationError({"password": list(error.messages)}) from error
        return attrs


class VerifyEmailSerializer(serializers.Serializer[dict[str, str]]):
    uid = serializers.CharField(max_length=64)
    token = serializers.CharField(max_length=128)
