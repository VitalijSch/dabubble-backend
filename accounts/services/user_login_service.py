from django.contrib.auth.hashers import check_password
from ..models import CustomUser
from ..serializers import UserSerializer
from rest_framework_simplejwt.tokens import RefreshToken


class UserLoginService:

    @staticmethod
    def authenticate_user(email, password):
        try:
            user = CustomUser.objects.get(email=email)
            if check_password(password, user.password):
                return user
        except CustomUser.DoesNotExist:
            return None
        return None

    @staticmethod
    def generate_tokens(user):
        refresh = RefreshToken.for_user(user)
        return {
            'access': str(refresh.access_token),
            'refresh': str(refresh)
        }

    @staticmethod
    def get_serialized_user_data(user):
        serializer = UserSerializer(user)
        return serializer.data
