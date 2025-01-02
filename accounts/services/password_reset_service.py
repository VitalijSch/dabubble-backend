from django.core.mail import EmailMessage
from rest_framework.exceptions import ValidationError
from ..serializers import SendPasswordResetEmailSerializer


class PasswordResetService:

    def process_password_reset(self, email):
        token = self._create_reset_token(email)
        reset_url = self._generate_reset_url(token)
        self._send_reset_email(email, reset_url)

    def _create_reset_token(self, email):
        serializer = SendPasswordResetEmailSerializer(data={'email': email})
        if not serializer.is_valid():
            raise ValidationError('Invalid email address.')
        serializer.save()
        return serializer.data['token']

    def _generate_reset_url(self, token):
        base_url = 'http://localhost:4200/auth/reset-password/'
        return f'{base_url}{token}'

    def _send_reset_email(self, email, reset_url):
        subject = 'Passwort zurücksetzen'
        body = (
            f'Hallo,\n\n'
            f'Wir haben eine Anfrage zum Zurücksetzen deines Passworts erhalten. '
            f'Klicke hier, um dein Passwort zurückzusetzen:\n{reset_url}\n\n'
            f'Ignoriere diese E-Mail, falls du die Anfrage nicht gestellt hast.\n\n'
            f'Beste Grüße,\nDein DABubble Team!'
        )
        from_email = 'mail@vitalij-schwab.com'

        try:
            email_message = EmailMessage(
                subject=subject,
                body=body,
                from_email=from_email,
                to=[email]
            )
            email_message.send()
        except Exception as e:
            raise ValueError(f"Error sending email: {str(e)}")
