"""Building blocks for describing API responses in the OpenAPI schema (drf-spectacular).

The schema is the contract with the frontend, which generates its TypeScript types from it.
DRF's error bodies aren't described automatically, so endpoints add them with these helpers.
"""

from functools import cache
from typing import Any

from drf_spectacular.utils import OpenApiResponse, PolymorphicProxySerializer
from rest_framework import serializers


class ErrorDetailSerializer(serializers.Serializer[dict[str, str]]):
    """A single error message, e.g. "not logged in" or "too many requests"."""

    detail = serializers.CharField()


def _messages() -> serializers.ListField:
    return serializers.ListField(child=serializers.CharField(), required=False)


@cache
def validation_error_serializer(
    serializer_class: type[serializers.Serializer[Any]],
) -> type[serializers.Serializer[dict[str, list[str]]]]:
    """The 400 body DRF returns when `serializer_class` is invalid: messages per field.

    Built from the serializer's writable fields, so it stays in sync when fields change.
    `non_field_errors` holds errors that don't belong to a single field.
    """
    name = serializer_class.__name__.removesuffix("Serializer")
    writable = [
        field_name for field_name, field in serializer_class().fields.items() if not field.read_only
    ]
    attrs: dict[str, object] = {field_name: _messages() for field_name in writable}
    attrs["non_field_errors"] = _messages()
    attrs["__doc__"] = f"Field errors: one or more German messages per invalid field ({name})."
    return type(f"{name}ValidationErrorSerializer", (serializers.Serializer,), attrs)


def validation_error_response(
    serializer_class: type[serializers.Serializer[Any]],
) -> OpenApiResponse:
    return OpenApiResponse(
        response=validation_error_serializer(serializer_class),
        description="The data is invalid. Messages per field, ready to show under the inputs.",
    )


def error_response(description: str) -> OpenApiResponse:
    return OpenApiResponse(response=ErrorDetailSerializer, description=description)


def validation_or_detail_error_response(
    serializer_class: type[serializers.Serializer[Any]], *, component_name: str, description: str
) -> OpenApiResponse:
    """A 400 that is either field errors or a single `detail` message."""
    return OpenApiResponse(
        response=PolymorphicProxySerializer(
            component_name=component_name,
            serializers=[validation_error_serializer(serializer_class), ErrorDetailSerializer],
            resource_type_field_name=None,
        ),
        description=description,
    )


RATE_LIMITED = error_response("Too many requests. Try again later.")
NOT_LOGGED_IN = error_response("Not logged in.")
