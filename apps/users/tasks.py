from urllib.parse import urlencode

from django.conf import settings
from django.core.mail import send_mail
from django.tasks import task
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .models import User
from .tokens import email_verification_token


@task()
def send_welcome_email(user_id: int) -> None:
    """Send the welcome email in the background. Enqueue with `send_welcome_email.enqueue(id)`."""
    user = User.objects.get(pk=user_id)
    send_mail(
        subject="Welcome to DABubble",
        message=render_to_string("email/welcome.txt", {"user": user}),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
    )


@task()
def send_verification_email(user_id: int) -> None:
    """Email the link that confirms the address and activates the account."""
    user = User.objects.get(pk=user_id)
    query = urlencode(
        {
            "uid": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": email_verification_token.make_token(user),
        }
    )
    verify_url = f"{settings.FRONTEND_URL.rstrip('/')}/verify-email?{query}"
    send_mail(
        subject="Confirm your DABubble email address",
        message=render_to_string(
            "email/verify_email.txt",
            {
                "user": user,
                "verify_url": verify_url,
                "valid_days": settings.PASSWORD_RESET_TIMEOUT // (60 * 60 * 24),
            },
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
    )
