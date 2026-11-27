from django.conf import settings
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction
from django.utils import timezone
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

from .models import User
from .tasks import send_verification_email
from .tokens import email_verification_token


def register_user(
    *,
    full_name: str,
    email: str,
    password: str,
    accept_privacy_policy: bool,
    avatar: UploadedFile[bytes] | None = None,
    default_avatar: str = "",
) -> User:
    """Create an inactive user and email them a confirmation link.

    The user can't log in until they confirm their email with `verify_email`. We record when they
    accepted the privacy policy and which version, so we can prove it later.
    """
    if accept_privacy_policy is not True:
        raise ValueError("The privacy policy must be accepted to register.")
    extra: dict[str, object] = {"avatar": avatar} if avatar else {"default_avatar": default_avatar}
    with transaction.atomic():
        user = User.objects.create_user(
            email=email,
            password=password,
            full_name=full_name,
            is_active=False,
            privacy_policy_accepted_at=timezone.now(),
            privacy_policy_version=settings.PRIVACY_POLICY_VERSION,
            **extra,
        )
        # Send only once the user is really in the database.
        transaction.on_commit(lambda: send_verification_email.enqueue(user.pk))
    return user


def verify_email(*, uid: str, token: str) -> User | None:
    """Activate the user the link belongs to. Returns None if the link is invalid or used."""
    try:
        user = User.objects.get(pk=int(force_str(urlsafe_base64_decode(uid))))
    except ValueError, OverflowError, User.DoesNotExist:
        return None
    if user.email_verified_at is not None or not email_verification_token.check_token(user, token):
        return None

    user.is_active = True
    user.email_verified_at = timezone.now()
    user.save(update_fields=["is_active", "email_verified_at"])
    return user
