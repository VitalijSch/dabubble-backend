from django.urls import path

from .views import MeView, RegisterView, VerifyEmailView

app_name = "users"

urlpatterns = [
    path("me/", MeView.as_view(), name="me"),
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/verify-email/", VerifyEmailView.as_view(), name="verify-email"),
]
