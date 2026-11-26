import pytest
from django.core import mail

from apps.users.tasks import send_welcome_email

from .factories import UserFactory

pytestmark = pytest.mark.django_db


def test_send_welcome_email() -> None:
    user = UserFactory.create(email="new@example.com", full_name="Ada Lovelace")

    send_welcome_email.enqueue(user.pk)  # runs immediately with the test task backend

    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == ["new@example.com"]
    assert "Hi Ada Lovelace" in str(mail.outbox[0].body)
