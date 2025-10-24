import uuid
from typing import Any
from typing import Type
from typing import cast

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
    is_active = True
    email_verified = True
    password = "default_password!"

    @classmethod
    def _create(cls, model_class: Type[User], *args: Any, **kwargs: Any) -> User:
        """Override the default .create() to use our custom manager."""
        manager = cls._get_manager(model_class)
        # Pop the required arguments for our manager
        email = kwargs.pop("email")
        password = kwargs.pop("password")
        # The remaining kwargs are the extra_fields
        return cast(User, manager.create_user(email, password, **kwargs))
