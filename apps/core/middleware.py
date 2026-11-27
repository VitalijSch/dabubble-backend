from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.utils import translation


class EnglishAdminMiddleware:
    """Show the Django admin in English.

    Users see German (`LANGUAGE_CODE = "de"`), but the admin is a staff tool and stays English.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        self.admin_prefix = "/" + settings.ADMIN_URL.lstrip("/")

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if not request.path.startswith(self.admin_prefix):
            return self.get_response(request)
        # `override` restores the previous language afterwards, so English can't leak into
        # the next request handled by this thread.
        with translation.override("en"):
            request.LANGUAGE_CODE = "en"
            return self.get_response(request)
