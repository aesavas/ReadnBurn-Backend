import uuid
from datetime import timedelta

import pytest
from accounts.models import User
from confidential.exceptions import SecretAlreadyDeletedError
from confidential.exceptions import SecretAlreadyViewedError
from confidential.exceptions import SecretDoesNotExistError
from confidential.exceptions import SecretExpiredError
from confidential.models import Secret
from confidential.models import SecretViewLog
from confidential.services import SecretService
from core.encryption import decrypt_message
from django.utils import timezone
from freezegun import freeze_time
from tests.conftest import SecretFactoryCallable

from backend.settings_test import TEST_ENCRYPTION_KEY


@pytest.mark.django_db
def test_create_secret_with_default_expiration_and_max_views(
    user_account: User,
) -> None:
    """Tests the creation of a secret with default expiration and max views."""
    content = "test content"

    secret = SecretService.create_secret(
        user=user_account,
        content=content,
        key=TEST_ENCRYPTION_KEY.encode(),
    )
    assert secret.creator == user_account
    assert secret.encrypted_content != content
    assert (
        decrypt_message(secret.encrypted_content, TEST_ENCRYPTION_KEY.encode())
        == content
    )
    assert secret.view_count == 0
    assert secret.viewed_at is None
    assert secret.is_deleted is False
    assert secret.deleted_at is None


@pytest.mark.django_db
def test_create_secret_with_custom_expiration_and_max_views(
    user_account: User,
) -> None:
    """Tests the creation of a secret with custom expiration and max views."""
    content = "test content"
    expires_at = timezone.now() + timedelta(hours=5)
    max_views = 2

    secret = SecretService.create_secret(
        user=user_account,
        content=content,
        expires_at=expires_at,
        max_views=max_views,
        key=TEST_ENCRYPTION_KEY.encode(),
    )
    assert secret.creator == user_account
    assert secret.encrypted_content != content
    assert (
        decrypt_message(secret.encrypted_content, TEST_ENCRYPTION_KEY.encode())
        == content
    )
    assert secret.view_count == 0
    assert secret.viewed_at is None
    assert secret.is_deleted is False
    assert secret.deleted_at is None


@pytest.mark.django_db
def test_retrieve_and_destroy_secret(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Tests the retrieval and destruction of a secret."""
    secret_content = "ReadnBurn"
    secret = secret_factory(creator=user_account, plain_content=secret_content)
    assert secret.view_count == 0
    assert secret.viewed_at is None
    assert secret.is_deleted is False
    assert secret.deleted_at is None
    assert secret.encrypted_content != secret_content

    retrieved_secret = SecretService.retrieve_and_destroy_secret(
        secret.id, "127.0.0.1", "Mozilla/5.0", key=TEST_ENCRYPTION_KEY.encode()
    )
    secret.refresh_from_db()
    assert retrieved_secret == secret_content

    assert secret.view_count == 1
    assert secret.viewed_at is not None
    assert secret.is_deleted is True  # type: ignore [unreachable]
    assert secret.deleted_at is not None
    assert Secret.objects.filter(id=secret.id).exists() is True
    assert SecretViewLog.objects.filter(secret=secret).exists()


@pytest.mark.django_db
def test_retrieve_and_destroy_secret_multiple_views(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Tests the retrieval and destruction of a secret multiple views."""
    secret_content = "ReadnBurn"
    secret = secret_factory(
        creator=user_account, plain_content=secret_content, max_views=2
    )
    assert secret.view_count == 0
    assert secret.viewed_at is None
    assert secret.is_deleted is False
    assert secret.deleted_at is None
    assert secret.encrypted_content != secret_content

    retrieved_secret = SecretService.retrieve_and_destroy_secret(
        secret.id, "127.0.0.1", "Mozilla/5.0", key=TEST_ENCRYPTION_KEY.encode()
    )
    secret.refresh_from_db()
    assert retrieved_secret == secret_content

    assert secret.view_count == 1
    assert secret.viewed_at is not None
    assert secret.is_deleted is False  # type: ignore [unreachable]
    assert secret.deleted_at is None
    assert Secret.objects.filter(id=secret.id).exists() is True
    assert SecretViewLog.objects.filter(secret=secret).exists()

    retrieved_secret = SecretService.retrieve_and_destroy_secret(
        secret.id, "127.0.0.1", "Mozilla/5.0", key=TEST_ENCRYPTION_KEY.encode()
    )
    secret.refresh_from_db()
    assert retrieved_secret == secret_content

    assert secret.view_count == 2
    assert secret.viewed_at is not None
    assert secret.is_deleted is True
    assert secret.deleted_at is not None
    assert Secret.objects.filter(id=secret.id).exists() is True
    assert SecretViewLog.objects.filter(secret=secret).count() == 2


@pytest.mark.django_db
def test_retrieve_and_destroy_secret_with_does_not_exist_error() -> None:
    """Tests the retrieval and destruction of a secret with does not exist error."""
    with pytest.raises(SecretDoesNotExistError):
        SecretService.retrieve_and_destroy_secret(
            uuid.uuid4(), "127.0.0.1", "Mozilla/5.0", key=TEST_ENCRYPTION_KEY.encode()
        )


@pytest.mark.django_db
@freeze_time("2025-01-01 00:00:00")
def test_retrieve_and_destroy_secret_with_expired_error(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Tests the retrieval and destruction of a secret with expired error."""
    secret_content = "ReadnBurn"
    secret = secret_factory(creator=user_account, plain_content=secret_content)
    assert secret.view_count == 0
    assert secret.viewed_at is None
    assert secret.is_deleted is False
    assert secret.deleted_at is None
    assert secret.encrypted_content != secret_content

    with freeze_time("2025-01-02 00:00:00"):
        with pytest.raises(SecretExpiredError):
            SecretService.retrieve_and_destroy_secret(
                secret.id, "127.0.0.1", "Mozilla/5.0", key=TEST_ENCRYPTION_KEY.encode()
            )

    assert (
        SecretViewLog.objects.get(secret=secret).failure_reason
        == SecretViewLog.FailureReason.EXPIRED.value
    )


@pytest.mark.django_db
def test_retrieve_and_destroy_secret_with_already_deleted_error(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Tests the retrieval and destruction of a secret with already deleted error."""
    secret_content = "ReadnBurn"
    secret = secret_factory(creator=user_account, plain_content=secret_content)
    secret.soft_delete()

    secret.refresh_from_db()

    assert secret.is_deleted is True
    assert secret.deleted_at is not None

    with pytest.raises(SecretAlreadyDeletedError):
        SecretService.retrieve_and_destroy_secret(
            secret.id, "127.0.0.1", "Mozilla/5.0", key=TEST_ENCRYPTION_KEY.encode()
        )

    assert (
        SecretViewLog.objects.get(secret=secret).failure_reason
        == SecretViewLog.FailureReason.DELETED.value
    )


@pytest.mark.django_db
def test_retrieve_and_destroy_secret_with_already_viewed_error(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Tests the retrieval and destruction of a secret with already viewed error."""
    secret_content = "ReadnBurn"
    secret = secret_factory(creator=user_account, plain_content=secret_content)
    secret.view_count = 1
    secret.viewed_at = timezone.now()
    secret.save()

    secret.refresh_from_db()

    assert secret.view_count == 1
    assert secret.viewed_at is not None

    with pytest.raises(SecretAlreadyViewedError):
        SecretService.retrieve_and_destroy_secret(
            secret.id, "127.0.0.1", "Mozilla/5.0", key=TEST_ENCRYPTION_KEY.encode()
        )

    assert (
        SecretViewLog.objects.get(secret=secret).failure_reason
        == SecretViewLog.FailureReason.ALREADY_VIEWED.value
    )
