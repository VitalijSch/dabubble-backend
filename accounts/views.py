from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser
from .serializers import UserSerializer, SendPasswordResetEmailSerializer, PasswordResetToken
from django.forms import ValidationError
from django.core.mail import EmailMessage


class UserCreateView(APIView):

    def post(self, request):
        serializer = UserSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            serializer.save()
            return Response({'message': 'User created successfully!'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CheckEmailExistsView(APIView):

    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'Email parameter is missing'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            is_email_exist = CustomUser.objects.filter(email=email).exists()
            return Response({'isEmailExist': is_email_exist}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SendPasswordResetEmailView(APIView):

    def post(self, request):
        email_object = request.data

        if not email_object:
            return Response({'error': 'Email parameter is missing'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            self.process_password_reset(email_object)
            return Response({'message': 'Email sent successfully!'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def process_password_reset(self, email_object):
        token = self.create_token(email_object)
        self.send_reset_email(email_object, token)

    @staticmethod
    def create_token(email_object):
        serializer = SendPasswordResetEmailSerializer(data=email_object)
        if not serializer.is_valid():
            raise ValidationError(serializer.errors)
        serializer.save()
        return serializer.data['token']

    @staticmethod
    def send_reset_email(email_object, token):
        subject = 'Passwort zurücksetzen'
        body = (
            f'Hallo,\n\n'
            f'Wir haben eine Anfrage zum Zurücksetzen deines Passworts erhalten. '
            f'Klicke hier, um dein Passwort zurückzusetzen:\nhttp://localhost:4200/auth/reset-password/{
                token}\n\n'
            f'Ignoriere diese E-Mail, falls du die Anfrage nicht gestellt hast.\n\n'
            f'Beste Grüße,\nDein DABubble Team!'
        )
        from_email = 'mail@vitalij-schwab.com'

        email_message = EmailMessage(
            subject=subject,
            body=body,
            from_email=from_email,
            to=[email_object['email']]
        )

        email_message.send()


class DeletePasswordResetEmailView(APIView):

    def post(self, request):
        token_object = request.data

        if not token_object:
            return Response({'error': 'Token parameter is missing'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            self.process_delete_password_reset(token_object)
            return Response({'message': 'Token deleted successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def process_delete_password_reset(self, token_object):
        token = self.get_token(token_object)
        self.delete_token(token)

    @staticmethod
    def get_token(token_object):
        return PasswordResetToken.objects.get(token=token_object['token'])

    @staticmethod
    def delete_token(token):
        token.delete()


class GetPasswordResetEmailView(APIView):

    def get(self, request):
        token = request.query_params.get('token')

        if not token:
            return Response({'error': 'Token parameter is missing'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            email = self.get_token(token)
            return Response({'email': email.email})
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def get_token(token):
        return PasswordResetToken.objects.get(token=token)


class ChangePasswordView(APIView):

    def post(self, request):
        user_data = request.data
        if not user_data:
            return Response({'error': 'New Password or email is missing.'}, status.HTTP_400_BAD_REQUEST)

        try:
            self.change_user_password(user_data)
            return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def change_user_password(self, user_data):
        user = self.get_user_by_email(user_data['email'])
        if not user:
            raise ValueError('User with this email does not exist.')
        self.update_user_password(user, user_data['newPassword'])

    @staticmethod
    def get_user_by_email(email):
        return CustomUser.objects.get(email=email)

    @staticmethod
    def update_user_password(user, new_password):
        user.set_password(new_password)
        user.save()


class GuestLoginView(APIView):
    pass


class CustomTokenObtainPairView(TokenObtainPairView):

    def post(self, request):
        tokens = self.generate_tokens(request)

        try:
            return self.handle_request(request, tokens)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def generate_tokens(self, request):
        response = super().post(request)
        return response.data

    def handle_request(self, request, tokens):
        user = self.get_user_by_email(request.data.get('email'))
        self.update_user_status(user, is_online=True)
        response_with_cookies = self.add_tokens_to_response_cookies(
            user, tokens)
        return self.prepare_response(user, response_with_cookies)

    @staticmethod
    def get_user_by_email(email):
        return CustomUser.objects.get(email=email)

    @staticmethod
    def update_user_status(user, is_online):
        user.is_online = is_online
        user.save()

    @staticmethod
    def add_tokens_to_response_cookies(user, tokens):
        response = Response()
        response.set_cookie(
            key=f'access_{user.id}',
            value=tokens['access'],
            httponly=True,
            secure=True,
            samesite='None',
        )
        response.set_cookie(
            key=f'refresh_{user.id}',
            value=tokens['refresh'],
            httponly=True,
            secure=True,
            samesite='None',
        )
        return response

    @staticmethod
    def prepare_response(user, response_with_cookies):
        serialized_user = UserSerializer(user)
        response_with_cookies.data = {'user': serialized_user.data}
        return response_with_cookies


class CustomTokenRefreshView(TokenRefreshView):

    def post(self, request):
        try:
            refresh_token = self.get_refresh_token_from_cookies(request)
            new_access_token = self.create_new_access_token(refresh_token)
            user = self.get_user_from_token(new_access_token)
            return self.prepare_response(user, new_access_token)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def get_refresh_token_from_cookies(request):
        user_id = request.data.get('id')
        refresh_token = request.COOKIES.get(f'refresh_{user_id}')
        return refresh_token

    @staticmethod
    def create_new_access_token(refresh_token):
        token = RefreshToken(refresh_token)
        return str(token.access_token)

    @staticmethod
    def get_user_from_token(access_token):
        decoded_token = AccessToken(access_token)
        user_id = decoded_token['user_id']
        return CustomUser.objects.get(id=user_id)

    def prepare_response(self, user, access_token):
        serialized_user = UserSerializer(user)
        response = Response({'user': serialized_user.data},
                            status=status.HTTP_200_OK)
        self.set_access_cookie(response, user.id, access_token)
        return response

    @staticmethod
    def set_access_cookie(response, user_id, access_token):
        response.set_cookie(
            key=f'access_{user_id}',
            value=access_token,
            httponly=True,
            secure=True,
            samesite='None',
        )


class UserUpdateView(APIView):

    def put(self, request):
        try:
            user = self.get_user_by_id(request.data.get('id'))
            serializer = self.get_serializer(user, request.data)
            self.update_user_if_valid(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def get_user_by_id(user_id):
        if not user_id:
            raise ValueError('User ID is required.')
        return CustomUser.objects.get(id=user_id)

    @staticmethod
    def get_serializer(user, data):
        print(data)
        return UserSerializer(user, data=data, partial=True)

    @staticmethod
    def update_user_if_valid(serializer):
        if not serializer.is_valid():
            raise ValueError(serializer.errors)
        serializer.save()


class UserListView(APIView):

    def get(self, request):
        users = self.get_non_superusers()
        serialized_users = self.serialize_users(users)
        return Response({'users': serialized_users}, status=status.HTTP_200_OK)

    @staticmethod
    def get_non_superusers():
        return CustomUser.objects.filter(is_superuser=False)

    @staticmethod
    def serialize_users(users):
        return UserSerializer(users, many=True).data


class UserLogoutView(APIView):

    def post(self, request, *args, **kwargs):
        try:
            user = self.get_user_by_id(request.data.get('id'))
            self.logout_user(user)
            response = self.create_success_response(user.id)
            return response
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def get_user_by_id(user_id):
        if not user_id:
            raise ValueError('User ID is required.')
        return CustomUser.objects.get(id=user_id)

    @staticmethod
    def logout_user(user):
        user.is_online = False
        user.save()

    @staticmethod
    def create_success_response(user_id):
        response = Response({'message': 'Logout successfully'})
        response.delete_cookie(f'access_{user_id}', samesite='None')
        response.delete_cookie(f'refresh_{user_id}', samesite='None')
        return response
