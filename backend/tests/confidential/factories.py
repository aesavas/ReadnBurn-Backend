from datetime import timedelta

import factory
from confidential.models import Secret
from core.encryption import encrypt_message
from django.utils import timezone
from factory.django import DjangoModelFactory
from tests.accounts.factories import UserFactory

from backend.settings_test import TEST_ENCRYPTION_KEY


class SecretFactory(DjangoModelFactory[Secret]):
    class Meta:
        model = Secret

    class Params:
        plain_content = factory.Faker("text")

    id = factory.Faker("uuid4")
    creator = factory.SubFactory(UserFactory)

    encrypted_content = factory.LazyAttribute(
        lambda o: encrypt_message(
            plaintext=o.plain_content,
            key=TEST_ENCRYPTION_KEY.encode(),
        )
    )

    max_views = 1
    view_count = 0
    expires_at = factory.LazyFunction(lambda: timezone.now() + timedelta(hours=1))
    viewed_at = None
    is_deleted = False
    deleted_at = None
