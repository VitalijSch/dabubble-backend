from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser, PasswordResetToken
from .serializers import UserSerializer, SendPasswordResetEmailSerializer
from django.core.mail import send_mail
from django.contrib.auth.hashers import check_password


class CreateUserView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer


class CheckEmailExistsView(APIView):
    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'The email parameter is missing.'}, status=status.HTTP_400_BAD_REQUEST)

        exists = CustomUser.objects.filter(email=email).exists()
        return Response({'exists': exists}, status=status.HTTP_200_OK)


class SendPasswordResetEmailView(APIView):
    def post(self, request):
        user_email = request.data.get('email')

        if not user_email:
            return Response({'email': 'The email parameter is missing.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = SendPasswordResetEmailSerializer(
            data={'email': user_email})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        reset_token = serializer.save()
        reset_url = f'http://localhost:4200/auth/reset-password/{
            serializer.data['token']}'
        message = (
            f'Hallo,\n\n'
            f'Wir haben eine Anfrage zum Zurücksetzen deines Passworts erhalten. '
            f'Klicke hier, um dein Passwort zurückzusetzen:\n{reset_url}\n\n'
            f'Ignoriere diese E-Mail, falls du die Anfrage nicht gestellt hast.\n\n'
            f'Beste Grüße,\nDein DABubble Team!'
        )

        send_mail(
            subject='Passwort zurücksetzten',
            message=message,
            from_email='mail@vitalij-schwab.com',
            recipient_list=[user_email],
        )

        return Response({'message': 'Email sent successfully!', 'token': reset_token.token}, status=status.HTTP_200_OK)


class DeletePasswordResetEmailView(APIView):
    def post(self, request):
        email_token = request.data.get('token')

        if not email_token:
            return Response({'error': 'Token is missing.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            email = PasswordResetToken.objects.get(token=email_token)
        except PasswordResetToken.DoesNotExist:
            return Response({'error': 'Token not found.'}, status=status.HTTP_404_NOT_FOUND)

        email.delete()

        return Response({'message': 'Token deleted successfully'}, status=status.HTTP_200_OK)


class GetPasswordResetEmailView(APIView):
    def get(self, request):
        token = request.query_params.get('token')

        if not token:
            return Response({'error': 'Token is missing.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            email = PasswordResetToken.objects.get(token=token)
        except PasswordResetToken.DoesNotExist:
            return Response({'error': 'Token not found.'}, status=status.HTTP_404_NOT_FOUND)

        return Response({'email': email.email})


class ChangePasswordView(APIView):
    def post(self, request):
        new_password = request.data.get('newPassword')
        user_email = request.data.get('email')

        if not new_password or not user_email:
            return Response({'error': 'New Password or email is missing.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=user_email)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)


class UserLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({'error': 'E-Mail oder Passwort fehlt.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)

            if check_password(password, user.password):
                refresh = RefreshToken.for_user(user)
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                }, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Ungültiges Passwort.'}, status=status.HTTP_401_UNAUTHORIZED)

        except CustomUser.DoesNotExist:
            return Response({'error': 'Benutzer mit dieser E-Mail existiert nicht.'}, status=status.HTTP_404_NOT_FOUND)
