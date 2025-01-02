from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from ..serializers import UserSerializer


class GuestLoginService:

    @staticmethod
    def create_guest_user():
        guest_user_data = {
            'id': None,
            'username': 'Guest',
            'email': 'guest@example.com',
        }
        return User(**guest_user_data)

    @staticmethod
    def generate_refresh_token(user):
        return RefreshToken.for_user(user)

    @staticmethod
    def get_serialized_guest_data(user):
        serializer = UserSerializer(user)
        return serializer.data
