import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError

from apps.users.models import DefaultAvatar, User

from .factories import DEFAULT_PASSWORD, UserFactory

pytestmark = pytest.mark.django_db


def test_custom_user_model_is_active() -> None:
    assert get_user_model() is User


def test_create_user_with_email() -> None:
    user = User.objects.create_user(email="Ada@Example.com", password="s3cret-pass")
    assert user.email == "ada@example.com"
    assert user.check_password("s3cret-pass")
    assert not user.is_staff
    assert str(user) == "ada@example.com"


def test_create_user_requires_email() -> None:
    with pytest.raises(ValueError, match="email"):
        User.objects.create_user(email="", password="x")


def test_create_superuser() -> None:
    admin = User.objects.create_superuser(email="admin@example.com", password="s3cret-pass")
    assert admin.is_staff
    assert admin.is_superuser


def test_email_is_unique() -> None:
    UserFactory.create(email="taken@example.com")
    with pytest.raises(IntegrityError):
        UserFactory.create(email="taken@example.com")


def test_factory_creates_user_with_password() -> None:
    user = UserFactory.create()
    assert user.pk is not None
    assert user.check_password(DEFAULT_PASSWORD)


def test_user_needs_exactly_one_avatar() -> None:
    with pytest.raises(IntegrityError):
        UserFactory.create(default_avatar="")


def test_user_cannot_have_two_avatars() -> None:
    with pytest.raises(IntegrityError):
        UserFactory.create(avatar="avatars/x.png", default_avatar=DefaultAvatar.AVATAR_1)


def test_clean_reports_missing_avatar() -> None:
    user = UserFactory.build(default_avatar="")
    with pytest.raises(ValidationError) as exc_info:
        user.clean()
    assert "default_avatar" in exc_info.value.message_dict


def test_create_superuser_gets_default_avatar() -> None:
    admin = User.objects.create_superuser(email="root@example.com", password="s3cret-pass")
    assert admin.default_avatar == DefaultAvatar.AVATAR_0


def test_create_user_without_avatar_gets_placeholder_avatar() -> None:
    user = User.objects.create_user(email="ada@example.com", password="s3cret-pass")
    assert user.default_avatar == "avatar_0"
