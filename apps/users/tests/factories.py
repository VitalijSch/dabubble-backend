from django.utils import timezone
from factory.declarations import LazyFunction, Sequence
from factory.django import DjangoModelFactory, Password
from factory.faker import Faker

from apps.users.models import DefaultAvatar, User

DEFAULT_PASSWORD = "test-password"


class UserFactory(DjangoModelFactory[User]):
    """Create users in tests: `UserFactory.create(email=...)`. Users are active and verified."""

    class Meta:
        model = User

    email = Sequence(lambda n: f"user{n}@example.com")
    full_name = Faker("name")
    default_avatar = DefaultAvatar.AVATAR_1
    email_verified_at = LazyFunction(timezone.now)
    password = Password(DEFAULT_PASSWORD)
