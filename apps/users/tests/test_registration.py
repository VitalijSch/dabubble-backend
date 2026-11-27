import io
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils import timezone
from PIL import Image
from rest_framework.test import APIClient
from rest_framework.throttling import ScopedRateThrottle

from apps.users.models import DefaultAvatar, User

from .factories import UserFactory

pytestmark = pytest.mark.django_db

STRONG_PASSWORD = "c0rrect-horse-battery"

CaptureOnCommit = Callable[..., AbstractContextManager[list[Callable[[], Any]]]]


def png_file(name: str = "me.png") -> SimpleUploadedFile:
    buffer = io.BytesIO()
    Image.new("RGB", (8, 8), "red").save(buffer, format="PNG")
    return SimpleUploadedFile(name, buffer.getvalue(), content_type="image/png")


def payload(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "full_name": "Ada Lovelace",
        "email": "ada@example.com",
        "password": STRONG_PASSWORD,
        "default_avatar": DefaultAvatar.AVATAR_3,
        "accept_privacy_policy": True,
    }
    data.update(overrides)
    return {key: value for key, value in data.items() if value is not None}


def register(capture: CaptureOnCommit, data: dict[str, Any], fmt: str = "multipart") -> Any:
    with capture(execute=True):
        return APIClient().post(reverse("users:register"), data, format=fmt)


def verification_params() -> dict[str, str]:
    """Pull uid and token out of the link in the last email sent."""
    body = str(mail.outbox[-1].body)
    link = next(word for word in body.split() if "/verify-email?" in word)
    query = parse_qs(urlsplit(link).query)
    return {"uid": query["uid"][0], "token": query["token"][0]}


# --- Registration -------------------------------------------------------------------------------


def test_register_with_default_avatar(django_capture_on_commit_callbacks: CaptureOnCommit) -> None:
    response = register(django_capture_on_commit_callbacks, payload(), fmt="json")

    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["email"] == "ada@example.com"
    assert body["full_name"] == "Ada Lovelace"
    assert body["default_avatar"] == "avatar_3"
    assert body["avatar"] is None
    assert "password" not in body

    user = User.objects.get(email="ada@example.com")
    assert not user.is_active  # can't log in before confirming the email
    assert user.email_verified_at is None
    assert user.password != STRONG_PASSWORD
    assert user.check_password(STRONG_PASSWORD)


def test_register_with_uploaded_avatar(django_capture_on_commit_callbacks: CaptureOnCommit) -> None:
    data = payload(default_avatar=None, avatar=png_file())

    response = register(django_capture_on_commit_callbacks, data)

    assert response.status_code == 201, response.json()
    user = User.objects.get(email="ada@example.com")
    name = str(user.avatar.name)
    assert name.startswith("avatars/")
    assert name.endswith(".png")
    assert "me" not in name  # the client's file name is not used
    assert user.default_avatar == ""
    assert response.json()["avatar"].endswith(".png")


def test_register_sends_verification_email(
    django_capture_on_commit_callbacks: CaptureOnCommit, settings: Any
) -> None:
    settings.FRONTEND_URL = "https://app.example.com"

    register(django_capture_on_commit_callbacks, payload())

    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == ["ada@example.com"]
    assert mail.outbox[0].subject == "Bestätige deine E-Mail-Adresse für DABubble"
    body = str(mail.outbox[0].body)
    assert body.startswith("Hallo Ada Lovelace,")
    assert "https://app.example.com/verify-email?uid=" in body


def test_register_normalises_email(django_capture_on_commit_callbacks: CaptureOnCommit) -> None:
    response = register(django_capture_on_commit_callbacks, payload(email="Ada@Example.COM"))

    assert response.status_code == 201
    assert User.objects.filter(email="ada@example.com").exists()


@pytest.mark.parametrize("missing", ["full_name", "email", "password"])
def test_register_requires_field(
    django_capture_on_commit_callbacks: CaptureOnCommit, missing: str
) -> None:
    response = register(django_capture_on_commit_callbacks, payload(**{missing: None}))

    assert response.status_code == 400
    # Built-in DRF message, so this also proves LANGUAGE_CODE is German.
    assert response.json()[missing] == ["Dieses Feld ist zwingend erforderlich."]
    assert not User.objects.exists()
    assert mail.outbox == []


def test_register_requires_an_avatar(django_capture_on_commit_callbacks: CaptureOnCommit) -> None:
    response = register(django_capture_on_commit_callbacks, payload(default_avatar=None))

    assert response.status_code == 400
    assert "avatar" in response.json()
    assert not User.objects.exists()


def test_register_rejects_two_avatars(django_capture_on_commit_callbacks: CaptureOnCommit) -> None:
    response = register(django_capture_on_commit_callbacks, payload(avatar=png_file()))

    assert response.status_code == 400
    assert "avatar" in response.json()


def test_register_rejects_blank_full_name(
    django_capture_on_commit_callbacks: CaptureOnCommit,
) -> None:
    response = register(django_capture_on_commit_callbacks, payload(full_name="   "))

    assert response.status_code == 400
    assert "full_name" in response.json()


def test_register_rejects_unknown_default_avatar(
    django_capture_on_commit_callbacks: CaptureOnCommit,
) -> None:
    response = register(django_capture_on_commit_callbacks, payload(default_avatar="nope"))

    assert response.status_code == 400
    assert "default_avatar" in response.json()


def test_register_rejects_file_that_is_not_an_image(
    django_capture_on_commit_callbacks: CaptureOnCommit,
) -> None:
    fake = SimpleUploadedFile("me.png", b"not an image", content_type="image/png")

    response = register(
        django_capture_on_commit_callbacks, payload(default_avatar=None, avatar=fake)
    )

    assert response.status_code == 400
    assert "avatar" in response.json()


def test_register_rejects_too_large_avatar(
    django_capture_on_commit_callbacks: CaptureOnCommit, settings: Any
) -> None:
    settings.AVATAR_MAX_UPLOAD_SIZE = 10  # bytes

    response = register(
        django_capture_on_commit_callbacks, payload(default_avatar=None, avatar=png_file())
    )

    assert response.status_code == 400
    assert "avatar" in response.json()


def test_register_rejects_taken_email(django_capture_on_commit_callbacks: CaptureOnCommit) -> None:
    UserFactory.create(email="ada@example.com")

    response = register(django_capture_on_commit_callbacks, payload(email="ADA@example.com"))

    assert response.status_code == 400
    assert "email" in response.json()
    assert User.objects.count() == 1


def test_register_rejects_weak_password(
    django_capture_on_commit_callbacks: CaptureOnCommit,
) -> None:
    response = register(django_capture_on_commit_callbacks, payload(password="12345678"))

    assert response.status_code == 400
    assert "password" in response.json()


def test_register_reports_password_error_together_with_other_errors(
    django_capture_on_commit_callbacks: CaptureOnCommit,
) -> None:
    UserFactory.create(email="ada@example.com")

    response = register(django_capture_on_commit_callbacks, payload(password="12345678"))

    assert response.status_code == 400
    assert {"email", "password"} <= response.json().keys()


def test_register_rejects_password_similar_to_name(
    django_capture_on_commit_callbacks: CaptureOnCommit,
) -> None:
    response = register(
        django_capture_on_commit_callbacks,
        payload(full_name="Lovelace Augusta", password="lovelaceaugusta"),
    )

    assert response.status_code == 400
    assert "password" in response.json()


@pytest.mark.parametrize("fmt", ["json", "multipart"])
@pytest.mark.parametrize("value", [None, False])
def test_register_requires_privacy_policy_acceptance(
    django_capture_on_commit_callbacks: CaptureOnCommit, fmt: str, value: bool | None
) -> None:
    response = register(
        django_capture_on_commit_callbacks, payload(accept_privacy_policy=value), fmt=fmt
    )

    assert response.status_code == 400
    assert "accept_privacy_policy" in response.json()
    assert not User.objects.exists()
    assert mail.outbox == []


def test_register_explains_privacy_policy_error_in_german(
    django_capture_on_commit_callbacks: CaptureOnCommit,
) -> None:
    response = register(django_capture_on_commit_callbacks, payload(accept_privacy_policy=False))

    assert response.json()["accept_privacy_policy"] == [
        "Bitte bestätige, dass du die Datenschutzerklärung gelesen hast."
    ]


def test_register_records_privacy_policy_acceptance(
    django_capture_on_commit_callbacks: CaptureOnCommit, settings: Any
) -> None:
    settings.PRIVACY_POLICY_VERSION = "2026-11-27"
    before = timezone.now()

    response = register(django_capture_on_commit_callbacks, payload())

    assert response.status_code == 201, response.json()
    assert "accept_privacy_policy" not in response.json()
    user = User.objects.get(email="ada@example.com")
    assert user.privacy_policy_version == "2026-11-27"
    assert user.privacy_policy_accepted_at is not None
    assert before <= user.privacy_policy_accepted_at <= timezone.now()


# --- Step 1 validation (before the avatar step) -------------------------------------------------


def details(**overrides: Any) -> dict[str, Any]:
    """The fields of the first sign-up step: everything except the avatar."""
    data = payload(**overrides)
    data.pop("default_avatar", None)
    return data


def validate_details(data: dict[str, Any]) -> Any:
    return APIClient().post(reverse("users:register-validate"), data, format="json")


def test_validate_accepts_valid_details_without_creating_a_user() -> None:
    response = validate_details(details())

    assert response.status_code == 204
    assert not User.objects.exists()
    assert mail.outbox == []


def test_validate_rejects_taken_email_in_german() -> None:
    UserFactory.create(email="ada@example.com")

    response = validate_details(details(email="ADA@example.com"))

    assert response.status_code == 400
    assert response.json()["email"] == ["Diese E-Mail-Adresse wird bereits verwendet."]


def test_validate_rejects_weak_password() -> None:
    response = validate_details(details(password="12345678"))

    assert response.status_code == 400
    assert "password" in response.json()


def test_validate_rejects_password_similar_to_name() -> None:
    response = validate_details(details(full_name="Lovelace Augusta", password="lovelaceaugusta"))

    assert response.status_code == 400
    assert "Das Passwort ist deinem Namen zu ähnlich." in response.json()["password"]


def test_validate_rejects_password_similar_to_email_in_german() -> None:
    response = validate_details(details(email="ada@example.com", password="adaexample"))

    assert response.status_code == 400
    assert "Das Passwort ist deiner E-Mail-Adresse zu ähnlich." in response.json()["password"]


@pytest.mark.parametrize("value", [None, False])
def test_validate_requires_privacy_policy_acceptance(value: bool | None) -> None:
    response = validate_details(details(accept_privacy_policy=value))

    assert response.status_code == 400
    assert "accept_privacy_policy" in response.json()


@pytest.mark.parametrize("field", ["full_name", "email", "password"])
def test_validate_requires_field(field: str) -> None:
    response = validate_details(details(**{field: None}))

    assert response.status_code == 400
    assert field in response.json()


def test_validate_reports_all_field_errors_at_once() -> None:
    UserFactory.create(email="ada@example.com")

    response = validate_details(details(password="12345678", accept_privacy_policy=False))

    assert response.status_code == 400
    assert {"email", "password", "accept_privacy_policy"} <= response.json().keys()


def test_validate_checks_password_even_when_name_is_missing() -> None:
    response = validate_details(details(full_name=None, password="12345678"))

    assert response.status_code == 400
    assert {"full_name", "password"} <= response.json().keys()


def test_validate_checks_password_similarity_against_raw_input() -> None:
    """The name is compared as typed, even when another field (here the email) is invalid."""
    response = validate_details(
        details(email="not-an-email", full_name="Lovelace Augusta", password="lovelaceaugusta")
    )

    assert response.status_code == 400
    assert {"email", "password"} <= response.json().keys()


def test_validate_is_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ScopedRateThrottle, "THROTTLE_RATES", {"register_validate": "2/hour"})

    statuses = [validate_details(details()).status_code for _ in range(3)]

    assert statuses == [204, 204, 429]


# --- Email verification -------------------------------------------------------------------------


def test_verify_email_activates_user(django_capture_on_commit_callbacks: CaptureOnCommit) -> None:
    register(django_capture_on_commit_callbacks, payload())

    response = APIClient().post(reverse("users:verify-email"), verification_params(), format="json")

    assert response.status_code == 204
    user = User.objects.get(email="ada@example.com")
    assert user.is_active
    assert user.email_verified_at is not None


def test_verify_email_link_works_only_once(
    django_capture_on_commit_callbacks: CaptureOnCommit,
) -> None:
    register(django_capture_on_commit_callbacks, payload())
    params = verification_params()
    APIClient().post(reverse("users:verify-email"), params, format="json")

    response = APIClient().post(reverse("users:verify-email"), params, format="json")

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Dieser Link ist ungültig, abgelaufen oder wurde bereits verwendet."
    }


def test_verify_email_link_stops_working_after_deactivation(
    django_capture_on_commit_callbacks: CaptureOnCommit,
) -> None:
    register(django_capture_on_commit_callbacks, payload())
    params = verification_params()
    APIClient().post(reverse("users:verify-email"), params, format="json")
    User.objects.filter(email="ada@example.com").update(is_active=False)  # e.g. banned by admin

    response = APIClient().post(reverse("users:verify-email"), params, format="json")

    assert response.status_code == 400
    assert not User.objects.get(email="ada@example.com").is_active


@pytest.mark.parametrize(
    "params",
    [
        {"uid": "MQ", "token": "wrong-token"},
        {"uid": "not-base64!", "token": "wrong-token"},
        {"uid": "OTk5OTk", "token": "wrong-token"},  # user 99999 does not exist
        {},
    ],
)
def test_verify_email_rejects_bad_link(
    django_capture_on_commit_callbacks: CaptureOnCommit, params: dict[str, str]
) -> None:
    register(django_capture_on_commit_callbacks, payload())

    response = APIClient().post(reverse("users:verify-email"), params, format="json")

    assert response.status_code == 400
    assert not User.objects.get(email="ada@example.com").is_active
