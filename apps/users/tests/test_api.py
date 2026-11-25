import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from .factories import UserFactory

pytestmark = pytest.mark.django_db


def test_me_requires_login() -> None:
    response = APIClient().get(reverse("users:me"))
    assert response.status_code == 403


def test_me_returns_current_user() -> None:
    user = UserFactory.create(email="me@example.com", first_name="Ada")
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.get(reverse("users:me"))

    assert response.status_code == 200
    assert response.json()["email"] == "me@example.com"
    assert response.json()["first_name"] == "Ada"


def test_openapi_schema_is_served() -> None:
    response = APIClient().get(reverse("schema"))
    assert response.status_code == 200
