from typing import Callable

import pytest
from accounts.models import User
from pytest_factoryboy import register
from rest_framework.test import APIClient
from tests.accounts.factories import UserFactory

register(UserFactory)

UserFactoryCallable = Callable[..., User]


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
