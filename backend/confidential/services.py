from datetime import datetime
from datetime import timedelta
from typing import Type
from typing import cast
from uuid import UUID

from accounts.models import User
from confidential.exceptions import SecretAlreadyDeletedError
from confidential.exceptions import SecretAlreadyViewedError
from confidential.exceptions import SecretDoesNotExistError
from confidential.exceptions import SecretExpiredError
from confidential.models import Secret
from confidential.models import SecretViewLog
from core.encryption import decrypt_message
from core.encryption import encrypt_message
from django.db import OperationalError
from django.db import transaction
from django.utils import timezone

from backend.settings import ENCRYPTION_KEY

DEFAULT_MAX_VIEWS = 1
DEFAULT_EXPIRES_AT = timezone.now() + timedelta(hours=1)


class SecretService:
    """Service class for secret management."""

    @staticmethod
    def create_secret(
        user: User,
        content: str,
        expires_at: datetime = DEFAULT_EXPIRES_AT,
        max_views: int = DEFAULT_MAX_VIEWS,
        key: bytes = ENCRYPTION_KEY.encode(),
    ) -> Secret:
        """Create a new secret."""
        return cast(
            Secret,
            Secret.objects.create(
                creator=user,
                encrypted_content=encrypt_message(content, key),
                expires_at=expires_at,
                max_views=max_views,
            ),
        )

    @staticmethod
    def retrieve_and_destroy_secret(
        uuid: UUID,
        ip_address: str,
        user_agent: str,
        key: bytes = ENCRYPTION_KEY.encode(),
    ) -> str:
        """Retrieve and destroy a secret."""
        try:
            with transaction.atomic():
                secret = Secret.objects.select_for_update(nowait=True).get(id=uuid)
                secret.mark_as_viewed()
                SecretService._create_secret_view_log(
                    secret=secret,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=True,
                )
                return decrypt_message(secret.encrypted_content, key)
        except OperationalError:
            # This occurs if the select_for_update() call hits a lock from a concurrent request.
            # We can treat this as if the secret has already been viewed.
            raise SecretAlreadyViewedError("Secret is being viewed by another request.")
        except Secret.DoesNotExist:
            raise SecretDoesNotExistError("Secret does not exist.")
        except (
            SecretExpiredError,
            SecretAlreadyDeletedError,
            SecretAlreadyViewedError,
        ) as e:
            failure_map: dict[Type[Exception], str] = {
                SecretExpiredError: SecretViewLog.FailureReason.EXPIRED.value,  # type: ignore
                SecretAlreadyDeletedError: SecretViewLog.FailureReason.DELETED.value,  # type: ignore
                SecretAlreadyViewedError: SecretViewLog.FailureReason.ALREADY_VIEWED.value,  # type: ignore
            }
            SecretService._create_secret_view_log(
                secret=secret,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                failure_reason=failure_map[type(e)],
            )
            raise e

    @staticmethod
    def _create_secret_view_log(
        secret: Secret,
        ip_address: str,
        user_agent: str,
        success: bool = True,
        failure_reason: str = "",
    ) -> SecretViewLog:
        return cast(
            SecretViewLog,
            SecretViewLog.objects.create(
                secret=secret,
                secret_uuid=secret.id,
                creator=secret.creator,
                viewed_at=timezone.now(),
                ip_address=ip_address,
                user_agent=user_agent,
                success=success,
                failure_reason=failure_reason,
            ),
        )
