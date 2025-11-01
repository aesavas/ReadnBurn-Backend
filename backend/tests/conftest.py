from typing import Callable
from typing import Generator

import pytest
from accounts.models import User
from confidential.models import Secret
from confidential.models import SecretViewLog
from pytest import MonkeyPatch
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


@pytest.fixture(autouse=True)
def patch_encryption_functions(monkeypatch: MonkeyPatch) -> Generator[None, None, None]:
    """Patch encryption functions to always use test key."""
    from cryptography.fernet import Fernet

    from backend.settings_test import TEST_ENCRYPTION_KEY

    def test_encrypt_message(plaintext: str, key: bytes) -> str:
        """Always encrypt with test key regardless of what key is passed."""
        f = Fernet(TEST_ENCRYPTION_KEY.encode())
        encrypted_message = f.encrypt(plaintext.encode("utf-8"))
        return encrypted_message.decode("utf-8")

    def test_decrypt_message(encrypted_text: str, key: bytes) -> str:
        """Always decrypt with test key regardless of what key is passed."""
        f = Fernet(TEST_ENCRYPTION_KEY.encode())
        decrypted_message = f.decrypt(encrypted_text.encode("utf-8"))
        return decrypted_message.decode("utf-8")

    # Patch the decrypt function to always use test key
    monkeypatch.setattr("core.encryption.decrypt_message", test_decrypt_message)
    monkeypatch.setattr("confidential.services.decrypt_message", test_decrypt_message)
    monkeypatch.setattr("core.encryption.encrypt_message", test_encrypt_message)
    monkeypatch.setattr("confidential.services.encrypt_message", test_encrypt_message)

    yield
