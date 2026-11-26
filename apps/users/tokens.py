from datetime import datetime
from typing import Any

from django.contrib.auth.tokens import PasswordResetTokenGenerator


class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    """Tokens for the link in the confirmation email.

    A token stops working once the email is verified (``email_verified_at`` is part of the hash)
    and after ``PASSWORD_RESET_TIMEOUT`` (3 days by default).
    """

    key_salt = "apps.users.tokens.EmailVerificationTokenGenerator"

    def _make_hash_value(self, user: Any, timestamp: int) -> str:
        verified_at: datetime | None = user.email_verified_at
        verified = "" if verified_at is None else verified_at.replace(microsecond=0, tzinfo=None)
        return f"{user.pk}{user.email}{user.is_active}{verified}{timestamp}"


email_verification_token = EmailVerificationTokenGenerator()
