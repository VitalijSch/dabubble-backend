from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework_simplejwt.tokens import AccessToken
from .models import CustomUser
from .serializers import UserSerializer
from django.forms import ValidationError
from .services.email_service import EmailService
from .services.password_reset_service import PasswordResetService
from .services.password_reset_token_service import PasswordResetTokenService
from .services.password_change_service import PasswordChangeService
from .services.user_login_service import UserLoginService
from .services.guest_login_service import GuestLoginService


class CreateUserView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer


class CheckEmailExistsView(APIView):

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return self.error_response('The email parameter is missing.', status.HTTP_400_BAD_REQUEST)

        try:
            is_email_exist = EmailService.email_exists(email)
            return Response({'isEmailExist': is_email_exist}, status=status.HTTP_200_OK)
        except ValidationError as e:
            return self.error_response(str(e), status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return self.error_response('An error occurred while processing the request.', status.HTTP_500_INTERNAL_SERVER_ERROR)

    def error_response(self, message, status_code):
        return Response({'error': message}, status=status_code)


class SendPasswordResetEmailView(APIView):

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return self.error_response('The email parameter is missing.', status.HTTP_400_BAD_REQUEST)

        try:
            PasswordResetService().process_password_reset(email)
            return Response({'message': 'Email sent successfully!'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            return self.error_response(str(e), status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return self.error_response('An error occurred while processing the request.', status.HTTP_500_INTERNAL_SERVER_ERROR)

    def error_response(self, message, status_code):
        return Response({'error': message}, status=status_code)


class DeletePasswordResetEmailView(APIView):

    def post(self, request):
        email_token = request.data.get('token')
        if not email_token:
            return self.error_response('Token is missing.', status.HTTP_400_BAD_REQUEST)

        try:
            token_object = PasswordResetTokenService.get_token(email_token)
            PasswordResetTokenService.delete_token(token_object)
            return Response({'message': 'Token deleted successfully'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            return self.error_response(str(e), status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return self.error_response('An error occurred while processing the request.', status.HTTP_500_INTERNAL_SERVER_ERROR)

    def error_response(self, message, status_code):
        return Response({'error': message}, status=status_code)


class GetPasswordResetEmailView(APIView):

    def get(self, request):
        token = request.query_params.get('token')
        if not token:
            return self.error_response('Token is missing.', status.HTTP_400_BAD_REQUEST)

        try:
            email = PasswordResetTokenService.get_token(token)
            return Response({'email': email.email})
        except ValidationError as e:
            return self.error_response(str(e), status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return self.error_response('An error occurred while processing the request.', status.HTTP_500_INTERNAL_SERVER_ERROR)

    def error_response(self, message, status_code):
        return Response({'error': message}, status=status_code)


class ChangePasswordView(APIView):

    def post(self, request):
        new_password = request.data.get('newPassword')
        user_email = request.data.get('email')
        if not new_password or not user_email:
            return self.error_response('New Password or email is missing.', status.HTTP_400_BAD_REQUEST)

        try:
            PasswordChangeService.change_user_password(user_email, new_password)
            return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        except ValueError as e:
            return self.error_response(str(e), status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return self.error_response('An error occurred while processing the request.', status.HTTP_500_INTERNAL_SERVER_ERROR)

    def error_response(self, message, status_code):
        return Response({'error': message}, status=status_code)


class UserLoginView(APIView):

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        if not email or not password:
            return self.error_response('E-Mail oder Passwort fehlt.', status.HTTP_400_BAD_REQUEST)

        try:
            user = UserLoginService.authenticate_user(email, password)
            if user is None:
                raise ValueError('Ungültige E-Mail oder Passwort.')

            user.is_online = True
            user.save()

            tokens = UserLoginService.generate_tokens(user)
            user_data = UserLoginService.get_serialized_user_data(user)

            response = Response({
                'access': tokens['access'],
                'refresh': tokens['refresh'],
                'user': user_data,
            }, status=status.HTTP_200_OK)

            response.set_cookie(
                key='access',
                value=tokens['access'],
                httponly=True,
                secure=True,
                samesite='None',
            )

            return response
        except ValueError as e:
            return self.error_response(str(e), status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return self.error_response('An error occurred while processing the request.', status.HTTP_500_INTERNAL_SERVER_ERROR)

    def error_response(self, message, status_code):
        return Response({'error': message}, status=status_code)


class UserCheckView(APIView):

    def get(self, request):
        token = request.COOKIES.get('access')
        if not token:
            return Response({'authenticated': False}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            decoded_token = AccessToken(token)
            user_id = decoded_token['user_id']
            user = CustomUser.objects.get(id=user_id)
            user_data = UserLoginService.get_serialized_user_data(user)
            return Response({'authenticated': True, 'user': user_data}, status=status.HTTP_200_OK)
        except Exception:
            return Response({'authenticated': False}, status=status.HTTP_401_UNAUTHORIZED)


class UserLogoutView(APIView):

    def post(self, request):
        token = request.COOKIES.get('access')
        if not token:
            return Response({'authenticated': False}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            decoded_token = AccessToken(token)
            user_id = decoded_token['user_id']
            user = CustomUser.objects.get(id=user_id)
            user.is_online = False
            user.save()

            response = Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)
            response.delete_cookie('access', samesite='None')
            return response
        except Exception as e:
            return Response({'authenticated': False, 'error': str(e)}, status=status.HTTP_401_UNAUTHORIZED)


class GuestLoginView(APIView):

    def get(self, request):
        guest_user = GuestLoginService.create_guest_user()
        refresh = GuestLoginService.generate_refresh_token(guest_user)
        guest_data = GuestLoginService.get_serialized_guest_data(guest_user)

        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': guest_data,
        }, status=status.HTTP_200_OK)
