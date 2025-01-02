from django.forms import ValidationError
from ..serializers import SendPasswordResetEmailSerializer, PasswordResetToken


class PasswordResetTokenService:

    @staticmethod
    def create_token(email):
        serializer = SendPasswordResetEmailSerializer(data={'email': email})
        if not serializer.is_valid():
            raise ValidationError('Invalid email address.')
        serializer.save()
        return serializer.data['token']

    @staticmethod
    def get_token(token):
        try:
            return PasswordResetToken.objects.get(token=token)
        except PasswordResetToken.DoesNotExist:
            return None

    @staticmethod
    def delete_token(token_object):
        token_object.delete()
