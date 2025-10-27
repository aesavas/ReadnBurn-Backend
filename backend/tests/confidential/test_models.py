import pytest
from accounts.models import User
from confidential.exceptions import SecretNotAvailableError
from confidential.models import SecretViewLog
from core.encryption import decrypt_message
from freezegun import freeze_time
from tests.conftest import SecretFactoryCallable
from tests.conftest import SecretViewLogFactoryCallable

from backend.settings_test import TEST_ENCRYPTION_KEY


@pytest.mark.django_db
def test_secret_creation(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Test secret creation."""
    secret = secret_factory(creator=user_account)
    assert isinstance(secret.creator, User)
    assert secret.creator.first_name == user_account.first_name
    assert secret.is_available
    assert not secret.is_expired
    assert not secret.is_deleted


@pytest.mark.django_db
def test_secret_encryption_and_decryption(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    my_secret = "ReadnBurn"
    secret = secret_factory(creator=user_account, plain_content=my_secret)
    assert secret.encrypted_content != my_secret

    decrypted_secret = decrypt_message(
        secret.encrypted_content, TEST_ENCRYPTION_KEY.encode()
    )
    assert decrypted_secret == my_secret


@pytest.mark.django_db
@freeze_time("2025-01-01 00:00:00")
def test_secret_message_expired_without_viewing(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Test secret message expired without viewing."""
    secret = secret_factory(creator=user_account)
    assert not secret.is_expired
    assert secret.is_available

    with freeze_time("2025-01-02 00:00:00"):
        assert secret.is_expired
        assert not secret.is_available  # type: ignore [unreachable]


@pytest.mark.django_db
@freeze_time("2025-01-01 00:00:00")
def test_secret_message_view_expired(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Test secret message view expired."""
    secret = secret_factory(creator=user_account)
    assert not secret.is_expired
    assert secret.is_available

    with freeze_time("2025-01-02 00:00:00"):
        with pytest.raises(
            SecretNotAvailableError, match="Secret is not available to be viewed."
        ):
            secret.mark_as_viewed()
        assert secret.is_expired
        assert not secret.is_available  # type: ignore [unreachable]


@pytest.mark.django_db
def test_secret_message_expired_with_viewing(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Test secret message expired with viewing."""
    secret = secret_factory(creator=user_account)
    assert not secret.is_expired
    assert secret.is_available
    assert secret.view_count == 0
    assert not secret.is_deleted

    secret.mark_as_viewed()
    assert not secret.is_expired
    assert not secret.is_available
    assert secret.view_count == 1  # type: ignore [unreachable]
    assert secret.is_deleted


@pytest.mark.django_db
def test_secret_message_soft_deleted(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Test secret message soft deleted."""
    secret = secret_factory(creator=user_account)
    assert not secret.is_deleted
    assert secret.deleted_at is None
    assert secret.view_count == 0
    assert not secret.is_expired
    assert secret.is_available

    secret.soft_delete()
    assert secret.is_deleted
    assert secret.deleted_at is not None
    assert secret.view_count == 0  # type: ignore [unreachable]
    assert not secret.is_expired
    assert not secret.is_available


@pytest.mark.django_db
def test_secret_message_viewing_soft_deleted(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Test secret message viewing soft deleted."""
    secret = secret_factory(creator=user_account)
    assert not secret.is_deleted
    assert secret.deleted_at is None
    assert secret.view_count == 0
    assert not secret.is_expired
    assert secret.is_available

    secret.soft_delete()
    assert secret.is_deleted
    assert secret.deleted_at is not None
    assert secret.view_count == 0  # type: ignore [unreachable]
    assert not secret.is_expired
    assert not secret.is_available

    with pytest.raises(SecretNotAvailableError):
        secret.mark_as_viewed()


@pytest.mark.django_db
def test_secret_message_soft_delete_twice(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Test secret message soft delete twice."""
    secret = secret_factory(creator=user_account)
    assert not secret.is_deleted
    assert secret.deleted_at is None
    assert secret.view_count == 0
    assert not secret.is_expired
    assert secret.is_available

    secret.soft_delete()
    assert secret.is_deleted
    assert secret.deleted_at is not None
    assert secret.view_count == 0  # type: ignore [unreachable]
    assert not secret.is_expired
    assert not secret.is_available

    # Second soft delete should raise an error
    with pytest.raises(SecretNotAvailableError, match="Secret is already deleted."):
        secret.soft_delete()


@pytest.mark.django_db
def test_secret_message_allow_multiple_views(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Test secret message allow multiple views."""
    secret = secret_factory(creator=user_account, max_views=2)
    assert not secret.is_expired
    assert secret.is_available
    assert secret.view_count == 0
    assert not secret.is_deleted

    secret.mark_as_viewed()
    assert not secret.is_expired
    assert secret.is_available
    assert secret.view_count == 1
    assert not secret.is_deleted

    secret.mark_as_viewed()
    assert not secret.is_expired
    assert not secret.is_available
    assert secret.view_count == 2  # type: ignore [unreachable]
    assert secret.is_deleted


@pytest.mark.django_db
def test_secret_get_shareable_url(
    user_account: User, secret_factory: SecretFactoryCallable
) -> None:
    """Test secret get shareable url."""
    secret = secret_factory(creator=user_account)
    assert secret.get_shareable_url() == f"/secret/view/{secret.id}"


@pytest.mark.django_db
def test_secret_view_log(
    user_account: User,
    secret_factory: SecretFactoryCallable,
    secret_view_log_factory: SecretViewLogFactoryCallable,
) -> None:
    """Test secret view log."""
    secret = secret_factory(creator=user_account)
    secret_view_log_factory(secret=secret)
    secret.mark_as_viewed()
    assert SecretViewLog.objects.count() == 1
    svl = SecretViewLog.objects.first()
    assert svl is not None
    assert str(svl.secret.id) == secret.id
    assert svl.viewed_at is not None
    assert not svl.secret.is_available
    assert svl.secret.view_count == 1


@pytest.mark.django_db
def test_secret_view_log_with_multiple_views(
    user_account: User,
    secret_factory: SecretFactoryCallable,
    secret_view_log_factory: SecretViewLogFactoryCallable,
) -> None:
    """Test secret view log with multiple views."""
    secret = secret_factory(creator=user_account, max_views=2)
    secret_view_log_factory(secret=secret)
    secret.mark_as_viewed()
    assert SecretViewLog.objects.count() == 1
    svl = SecretViewLog.objects.first()
    assert svl is not None
    assert str(svl.secret.id) == secret.id
    assert svl.viewed_at is not None
    assert svl.secret.is_available
    assert svl.secret.view_count == 1

    secret.mark_as_viewed()
    secret_view_log_factory(secret=secret)
    assert SecretViewLog.objects.count() == 2
    svl = SecretViewLog.objects.last()
    assert svl is not None
    assert str(svl.secret.id) == secret.id
    assert svl.viewed_at is not None
    assert not svl.secret.is_available
    assert svl.secret.view_count == 2

    assert SecretViewLog.objects.filter(secret=secret).count() == 2
