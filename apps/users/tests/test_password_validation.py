import pytest
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from django.utils import translation

from apps.users.models import User


def similarity_errors(password: str) -> list[str]:
    user = User(email="ada@example.com", full_name="Lovelace Augusta")
    with pytest.raises(ValidationError) as error:
        password_validation.validate_password(password, user=user)
    return list(error.value.messages)


def test_similar_to_email_message_is_proper_german() -> None:
    assert "Das Passwort ist deiner E-Mail-Adresse zu ähnlich." in similarity_errors("adaexample")


def test_similar_to_name_message_is_proper_german() -> None:
    assert "Das Passwort ist deinem Namen zu ähnlich." in similarity_errors("lovelaceaugusta")


def test_similarity_message_stays_english_in_english() -> None:
    # The admin runs in English (EnglishAdminMiddleware) and keeps Django's own wording.
    with translation.override("en"):
        errors = similarity_errors("adaexample")

    assert "The password is too similar to the email address." in errors
