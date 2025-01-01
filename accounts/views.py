from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser, PasswordResetToken
from .serializers import UserSerializer, SendPasswordResetEmailSerializer
from django.core.mail import send_mail
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from .services.email_service import email_exists


class CreateUserView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer


class CheckEmailExistsView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')

        if not email:
            return self.error_response('The email parameter is missing.', status.HTTP_400_BAD_REQUEST)

        exists = email_exists(email)
        return Response({'exists': exists}, status=status.HTTP_200_OK)

    def error_response(self, message, status_code):
        return Response({'error': message}, status=status_code)


class SendPasswordResetEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        user_email = request.data.get('email')

        if not user_email:
            return self.error_response('The email parameter is missing.', status.HTTP_400_BAD_REQUEST)

        serializer = self.validate_email(user_email)
        if not serializer:
            return self.error_response('Invalid email.', status.HTTP_400_BAD_REQUEST)

        reset_token = self.create_reset_token(serializer)
        self.send_reset_email(user_email, serializer.data['token'])

        return Response({'message': 'Email sent successfully!', 'token': reset_token.token}, status=status.HTTP_200_OK)

    def validate_email(self, email):
        serializer = SendPasswordResetEmailSerializer(data={'email': email})
        if serializer.is_valid():
            return serializer
        return None

    def create_reset_token(self, serializer):
        return serializer.save()

    def send_reset_email(self, email, token):
        reset_url = f'http://localhost:4200/auth/reset-password/{token}'
        message = (
            f'Hallo,\n\n'
            f'Wir haben eine Anfrage zum Zurücksetzen deines Passworts erhalten. '
            f'Klicke hier, um dein Passwort zurückzusetzen:\n{reset_url}\n\n'
            f'Ignoriere diese E-Mail, falls du die Anfrage nicht gestellt hast.\n\n'
            f'Beste Grüße,\nDein DABubble Team!'
        )
        send_mail(
            subject='Passwort zurücksetzen',
            message=message,
            from_email='mail@vitalij-schwab.com',
            recipient_list=[email],
        )

    def error_response(self, message, status_code):
        return Response({'error': message}, status=status_code)


class DeletePasswordResetEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email_token = request.data.get('token')

        if not email_token:
            return self.error_response('Token is missing.', status.HTTP_400_BAD_REQUEST)

        email = self.get_email_by_token(email_token)
        if not email:
            return self.error_response('Token not found.', status.HTTP_404_NOT_FOUND)

        self.delete_token(email)

        return Response({'message': 'Token deleted successfully'}, status=status.HTTP_200_OK)

    def get_email_by_token(self, token):
        try:
            return PasswordResetToken.objects.get(token=token)
        except PasswordResetToken.DoesNotExist:
            return None

    def delete_token(self, email):
        email.delete()

    def error_response(self, message, status_code):
        return Response({'error': message}, status=status_code)


class GetPasswordResetEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        token = request.query_params.get('token')

        if not token:
            return self.error_response('Token is missing.', status.HTTP_400_BAD_REQUEST)

        email = self.get_email_by_token(token)
        if not email:
            return self.error_response('Token not found.', status.HTTP_404_NOT_FOUND)

        return Response({'email': email.email})

    def get_email_by_token(self, token):
        try:
            return PasswordResetToken.objects.get(token=token)
        except PasswordResetToken.DoesNotExist:
            return None

    def error_response(self, message, status_code):
        return Response({'error': message}, status=status_code)


class ChangePasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        new_password = request.data.get('newPassword')
        user_email = request.data.get('email')

        if not new_password or not user_email:
            return self.error_response('New Password or email is missing.', status.HTTP_400_BAD_REQUEST)

        user = self.get_user_by_email(user_email)
        if not user:
            return self.error_response('User with this email does not exist.', status.HTTP_404_NOT_FOUND)

        self.update_user_password(user, new_password)

        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)

    def get_user_by_email(self, email):
        try:
            return CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return None

    def update_user_password(self, user, new_password):
        user.set_password(new_password)
        user.save()

    def error_response(self, message, status_code):
        return Response({'error': message}, status=status_code)


class UserLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return self.error_response('E-Mail oder Passwort fehlt.', status.HTTP_400_BAD_REQUEST)

        user = self.authenticate_user(email, password)
        if user is None:
            return self.error_response('Ungültige E-Mail oder Passwort.', status.HTTP_401_UNAUTHORIZED)

        tokens = self.generate_tokens(user)

        user_data = self.get_serialized_user_data(user)

        return Response({
            'access': tokens['access'],
            'refresh': tokens['refresh'],
            'user': user_data,
        }, status=status.HTTP_200_OK)

    def authenticate_user(self, email, password):
        try:
            user = CustomUser.objects.get(email=email)
            if check_password(password, user.password):
                return user
        except CustomUser.DoesNotExist:
            pass
        return None

    def generate_tokens(self, user):
        refresh = RefreshToken.for_user(user)
        return {
            'access': str(refresh.access_token),
            'refresh': str(refresh)
        }

    def get_serialized_user_data(self, user):
        serializer = UserSerializer(user)
        return serializer.data

    def error_response(self, message, status_code):
        return Response({'error': message}, status=status_code)


class GuestLoginView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        guest_user = self.create_guest_user()
        refresh = self.generate_refresh_token(guest_user)
        guest_data = self.get_serialized_guest_data(guest_user)

        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': guest_data,
        }, status=status.HTTP_200_OK)

    def create_guest_user(self):
        guest_user_data = {
            'id': None,
            'username': 'Guest',
            'email': 'guest@example.com',
        }
        return User(**guest_user_data)

    def generate_refresh_token(self, user):
        return RefreshToken.for_user(user)

    def get_serialized_guest_data(self, user):
        serializer = UserSerializer(user)
        return serializer.data
