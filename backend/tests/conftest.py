from typing import Callable

import pytest
from accounts.models import User
from confidential.models import Secret
from confidential.models import SecretViewLog
from pytest_factoryboy import register
from rest_framework.test import APIClient
from tests.accounts.factories import UserFactory
from tests.confidential.factories import SecretFactory
from tests.confidential.factories import SecretViewLogFactory

register(UserFactory)
register(SecretFactory)
register(SecretViewLogFactory)

UserFactoryCallable = Callable[..., User]
SecretFactoryCallable = Callable[..., Secret]
SecretViewLogFactoryCallable = Callable[..., SecretViewLog]


@pytest.fixture
def api_client() -> APIClient:
    return APIClient()


@pytest.fixture
def user_account(user_factory: UserFactoryCallable) -> User:
    return user_factory()


@pytest.fixture
def admin_account(user_factory: UserFactoryCallable) -> User:
    return user_factory(is_staff=True, is_superuser=True)


@pytest.fixture
def auth_user_api_client(api_client: APIClient, user_account: User) -> APIClient:
    api_client.force_authenticate(user=user_account)
    return api_client


@pytest.fixture
def auth_admin_api_client(api_client: APIClient, admin_account: User) -> APIClient:
    api_client.force_authenticate(user=admin_account)
    return api_client
