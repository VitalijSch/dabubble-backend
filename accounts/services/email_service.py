from django.core.mail import EmailMessage
from ..models import CustomUser


class EmailService:

    @staticmethod
    def email_exists(email):
        return CustomUser.objects.filter(email=email).exists()

    @staticmethod
    def send_reset_email(email, reset_url):
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
