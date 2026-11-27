"""The OpenAPI schema is the contract with the frontend: it must be complete and committed."""

import io
from pathlib import Path
from typing import Any

import pytest
import yaml
from django.conf import settings
from django.core.management import call_command
from django.urls import reverse
from rest_framework.test import APIClient

from apps.users.tests.factories import UserFactory

SCHEMA_FILE = Path(settings.BASE_DIR) / "openapi.yaml"


def generate_schema() -> str:
    out = io.StringIO()
    call_command("spectacular", "--validate", "--fail-on-warn", stdout=out)
    return out.getvalue()


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(generate_schema())
    return loaded


def component(schema: dict[str, Any], name: str) -> dict[str, Any]:
    found: dict[str, Any] = schema["components"]["schemas"][name]
    return found


def response_schema(schema: dict[str, Any], path: str, status: str) -> dict[str, Any]:
    response: dict[str, Any] = schema["paths"][path]["post"]["responses"][status]
    ref: str = response["content"]["application/json"]["schema"]["$ref"]
    return component(schema, ref.rsplit("/", 1)[-1])


def test_committed_schema_is_up_to_date() -> None:
    assert SCHEMA_FILE.read_text() == generate_schema(), (
        "openapi.yaml is out of date. Run `make schema` and commit the file."
    )


def test_uploaded_avatar_is_a_binary_file_in_the_request(schema: dict[str, Any]) -> None:
    avatar = component(schema, "RegisterRequest")["properties"]["avatar"]

    assert avatar["format"] == "binary"


@pytest.mark.django_db
def test_user_default_avatar_may_be_blank(schema: dict[str, Any]) -> None:
    """A user with an uploaded avatar has `default_avatar: ""`; the schema must allow that."""
    user = UserFactory.create(avatar="avatars/me.png", default_avatar="")
    client = APIClient()
    client.force_authenticate(user)

    assert client.get(reverse("users:me")).json()["default_avatar"] == ""
    options = component(schema, "User")["properties"]["default_avatar"]["oneOf"]
    assert {"$ref": "#/components/schemas/BlankEnum"} in options


@pytest.mark.parametrize(
    ("path", "component_name", "fields"),
    [
        (
            "/api/v1/auth/register/",
            "RegisterValidationError",
            {"full_name", "email", "password", "accept_privacy_policy", "avatar"},
        ),
        (
            "/api/v1/auth/register/validate/",
            "RegisterDetailsValidationError",
            {"full_name", "email", "password", "accept_privacy_policy"},
        ),
    ],
)
def test_field_errors_are_documented(
    schema: dict[str, Any], path: str, component_name: str, fields: set[str]
) -> None:
    errors = response_schema(schema, path, "400")
    expected = component(schema, component_name)

    assert errors == expected
    assert fields | {"non_field_errors"} <= errors["properties"].keys()
    assert errors["properties"]["email" if "email" in fields else "full_name"] == {
        "type": "array",
        "items": {"type": "string"},
    }


@pytest.mark.parametrize(
    "path",
    ["/api/v1/auth/register/", "/api/v1/auth/register/validate/", "/api/v1/auth/verify-email/"],
)
def test_rate_limit_is_documented(schema: dict[str, Any], path: str) -> None:
    assert response_schema(schema, path, "429") == component(schema, "ErrorDetail")


def test_verify_email_documents_both_error_shapes(schema: dict[str, Any]) -> None:
    response = schema["paths"]["/api/v1/auth/verify-email/"]["post"]["responses"]["400"]
    ref = response["content"]["application/json"]["schema"]["$ref"]
    options = component(schema, ref.rsplit("/", 1)[-1])["oneOf"]

    assert {"$ref": "#/components/schemas/ErrorDetail"} in options
    assert {"$ref": "#/components/schemas/VerifyEmailValidationError"} in options


def test_me_documents_missing_login(schema: dict[str, Any]) -> None:
    response = schema["paths"]["/api/v1/me/"]["get"]["responses"]["403"]

    assert response["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorDetail"
    }


def test_endpoints_are_grouped_by_feature(schema: dict[str, Any]) -> None:
    operation = schema["paths"]["/api/v1/auth/register/"]["post"]

    assert operation["tags"] == ["auth"]
    assert operation["operationId"] == "auth_register_create"
