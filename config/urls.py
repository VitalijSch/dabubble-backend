from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import URLPattern, URLResolver, include, path

from apps.core.views import health

urlpatterns: list[URLPattern | URLResolver] = [
    path(settings.ADMIN_URL, admin.site.urls),
    path("health/", health, name="health"),
    path("api/v1/", include("apps.users.urls")),
]

if settings.API_DOCS_ENABLED:
    from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

    urlpatterns += [
        path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
        path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="api-docs"),
    ]

if settings.DEBUG:
    # Serve uploaded files (./media, e.g. avatars) from the dev server.
    # Production stores them in Supabase Storage and returns signed URLs instead.
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG and "debug_toolbar" in settings.INSTALLED_APPS:
    from debug_toolbar.toolbar import debug_toolbar_urls

    urlpatterns += debug_toolbar_urls()
