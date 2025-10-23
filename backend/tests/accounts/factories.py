import uuid

import factory
from accounts.models import User
from factory.django import DjangoModelFactory


class UserFactory(DjangoModelFactory):
    class Meta:
        model = User

    id = factory.Faker("uuid4")
    email = factory.LazyFunction(lambda: f"{uuid.uuid4()}@readnburn.com")
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    is_staff = False
    is_superuser = False
    email_verified = True
