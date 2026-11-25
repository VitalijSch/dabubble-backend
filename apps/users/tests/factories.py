from factory.declarations import Sequence
from factory.django import DjangoModelFactory, Password
from factory.faker import Faker

from apps.users.models import User

DEFAULT_PASSWORD = "test-password"


class UserFactory(DjangoModelFactory[User]):
    """Create users in tests: `UserFactory.create(email=...)`."""

    class Meta:
        model = User

    email = Sequence(lambda n: f"user{n}@example.com")
    first_name = Faker("first_name")
    last_name = Faker("last_name")
    password = Password(DEFAULT_PASSWORD)
