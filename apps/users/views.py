from rest_framework import generics

from .models import User
from .serializers import UserSerializer


class MeView(generics.RetrieveAPIView[User]):
    """The currently logged-in user."""

    serializer_class = UserSerializer

    def get_object(self) -> User:
        user = self.request.user
        assert isinstance(user, User)  # IsAuthenticated guarantees a real user  # noqa: S101
        return user
