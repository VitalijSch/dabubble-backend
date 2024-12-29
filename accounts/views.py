from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from .models import CustomUser
from .serializers import UserSerializer, SendPasswordResetEmailSerializer
from django.core.mail import send_mail


class CreateUserView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer


class CheckEmailExistsView(APIView):
    def get(self, request):
        email = request.query_params.get('email')
        if not email:
            return Response({'error': 'The email parameter is missing.'}, status=status.HTTP_400_BAD_REQUEST)

        exists = CustomUser.objects.filter(email=email).exists()
        return Response({'exists': exists}, status=status.HTTP_200_OK)


class SendPasswordResetEmailView(APIView):
    def post(self, request):
        user_email = request.data.get('email')
        if not user_email:
            return Response({'email': 'The email parameter is missing.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = SendPasswordResetEmailSerializer(data={'email': user_email})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        reset_token = serializer.save()
        reset_url = f'http://localhost:4200/auth/reset-password/{serializer.data['token']}'
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
