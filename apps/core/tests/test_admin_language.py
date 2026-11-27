import pytest
from django.test import Client
from django.urls import reverse
from django.utils import translation

pytestmark = pytest.mark.django_db


def test_admin_is_english() -> None:
    response = Client().get(reverse("admin:login"))

    assert response.status_code == 200
    assert 'lang="en"' in response.text
    assert "Log in" in response.text


def test_api_stays_german_after_an_admin_request() -> None:
    client = Client()
    client.get(reverse("admin:login"))

    response = client.post(reverse("users:register"), {}, content_type="application/json")

    assert response.json()["email"] == ["Dieses Feld ist zwingend erforderlich."]
    assert translation.get_language() == "de"  # English did not leak into later code
