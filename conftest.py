from collections.abc import Iterator

import pytest
from django.core.cache import cache


@pytest.fixture(autouse=True)
def _clear_cache() -> Iterator[None]:
    """Start every test with an empty cache, so API throttle counters don't leak between tests."""
    cache.clear()
    yield
    cache.clear()
