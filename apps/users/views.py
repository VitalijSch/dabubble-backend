from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import generics, permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from . import services
from .models import User
from .serializers import (
    RegisterDetailsSerializer,
    RegisterSerializer,
    UserSerializer,
    VerifyEmailSerializer,
)


class MeView(generics.RetrieveAPIView[User]):
    """The currently logged-in user."""

    serializer_class = UserSerializer

    def get_object(self) -> User:
        user = self.request.user
        assert isinstance(user, User)  # IsAuthenticated guarantees a real user  # noqa: S101
        return user


class RegisterView(APIView):
    """Create an account. The user must confirm their email before they can log in."""

    authentication_classes = ()
    permission_classes = (permissions.AllowAny,)
    throttle_classes = (ScopedRateThrottle,)
    throttle_scope = "register"

    @extend_schema(request=RegisterSerializer, responses={201: UserSerializer})
    def post(self, request: Request) -> Response:
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = services.register_user(**serializer.validated_data)
        return Response(
            UserSerializer(user, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )


class RegisterValidateView(APIView):
    """Check the first sign-up step (name, email, password, privacy policy) without saving.

    The frontend calls this on "Weiter", before the avatar step, so the user sees problems like
    "email already in use" right away. `register` checks everything again: this is only a preview.
    """

    authentication_classes = ()
    permission_classes = (permissions.AllowAny,)
    throttle_classes = (ScopedRateThrottle,)
    throttle_scope = "register_validate"

    @extend_schema(
        request=RegisterDetailsSerializer,
        responses={
            204: OpenApiResponse(description="The details are valid; continue to the avatar step."),
            400: OpenApiResponse(description="Field errors, in the same format as `register`."),
        },
    )
    def post(self, request: Request) -> Response:
        RegisterDetailsSerializer(data=request.data).is_valid(raise_exception=True)
        return Response(status=status.HTTP_204_NO_CONTENT)


class VerifyEmailView(APIView):
    """Confirm the email address with the `uid` and `token` from the email link."""

    authentication_classes = ()
    permission_classes = (permissions.AllowAny,)
    throttle_classes = (ScopedRateThrottle,)
    throttle_scope = "verify_email"

    @extend_schema(
        request=VerifyEmailSerializer,
        responses={
            204: OpenApiResponse(description="Email confirmed; the account is active."),
            400: OpenApiResponse(description="The link is invalid, expired or already used."),
        },
    )
    def post(self, request: Request) -> Response:
        serializer = VerifyEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if services.verify_email(**serializer.validated_data) is None:
            return Response(
                {"detail": "Dieser Link ist ungültig, abgelaufen oder wurde bereits verwendet."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(status=status.HTTP_204_NO_CONTENT)
