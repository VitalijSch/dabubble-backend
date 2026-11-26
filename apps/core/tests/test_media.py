import importlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from django.test import Client
from django.urls import clear_url_caches

import config.urls


def reload_urls() -> None:
    importlib.reload(config.urls)
    clear_url_caches()


@pytest.fixture
def media_file(settings: Any, tmp_path: Path) -> str:
    """A file in a temporary MEDIA_ROOT; returns the URL path it should be served at."""
    settings.MEDIA_ROOT = tmp_path
    (tmp_path / "avatars").mkdir()
    (tmp_path / "avatars" / "x.png").write_bytes(b"png-bytes")
    return "/media/avatars/x.png"


@pytest.fixture(autouse=True)
def _restore_urls() -> Iterator[None]:
    """Autouse, so it tears down last: after `settings` is restored, rebuild the normal URLs."""
    yield
    reload_urls()


def test_dev_server_serves_uploaded_files(settings: Any, media_file: str) -> None:
    settings.DEBUG = True
    reload_urls()

    response = Client().get(media_file)

    assert response.status_code == 200
    assert b"".join(response.streaming_content) == b"png-bytes"  # type: ignore[attr-defined]


def test_uploaded_files_are_not_served_without_debug(settings: Any, media_file: str) -> None:
    settings.DEBUG = False
    reload_urls()

    response = Client().get(media_file)

    assert response.status_code == 404
