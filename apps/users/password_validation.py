from typing import Any

from django.contrib.auth.password_validation import UserAttributeSimilarityValidator
from django.core.exceptions import ValidationError
from django.utils import translation

# German has to decline the noun ("deiner E-Mail-Adresse", "deinem Namen"), so Django's
# "Das Passwort ist zu ähnlich zu %(verbose_name)s." can't be filled with a field name.
GERMAN_MESSAGES = {
    "email": "Das Passwort ist deiner E-Mail-Adresse zu ähnlich.",
    "full_name": "Das Passwort ist deinem Namen zu ähnlich.",
}


class GermanUserAttributeSimilarityValidator(UserAttributeSimilarityValidator):
    """Django's similarity check with a grammatically correct German message per attribute.

    Outside German (the admin runs in English) it keeps Django's own message.
    """

    def validate(self, password: str, user: Any = None) -> None:
        if not (translation.get_language() or "").startswith("de"):
            super().validate(password, user)
            return
        # Check one attribute at a time so we know which one the password is similar to.
        for attribute in self.user_attributes:
            single = UserAttributeSimilarityValidator((attribute,), self.max_similarity)
            try:
                single.validate(password, user)
            except ValidationError as error:
                if attribute not in GERMAN_MESSAGES:
                    raise
                raise ValidationError(
                    GERMAN_MESSAGES[attribute], code="password_too_similar"
                ) from error
