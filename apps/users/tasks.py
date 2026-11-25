from django.conf import settings
from django.core.mail import send_mail
from django.tasks import task
from django.template.loader import render_to_string

from .models import User


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
