# mypy: ignore-errors
import uuid

from accounts.models import User
from confidential.exceptions import SecretNotAvailableError
from core.models import TimeStampedModel
from django.db import models
from django.utils import timezone


class Secret(TimeStampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    creator = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_content = models.TextField()
    max_views = models.PositiveIntegerField(default=1, blank=False)
    view_count = models.PositiveIntegerField(default=0, blank=False)
    expires_at = models.DateTimeField(null=True, blank=True)
    viewed_at = models.DateTimeField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)  # Soft delete
    deleted_at = models.DateTimeField(null=True, blank=True)

    @property
    def is_expired(self) -> bool:
        """Return True if the secret has expired."""
        return self.expires_at and self.expires_at < timezone.now()

    @property
    def is_available(self) -> bool:
        """Return True if the secret is available."""
        return (
            not self.is_expired
            and not self.is_deleted
            and self.view_count < self.max_views
        )

    def mark_as_viewed(self) -> None:
        """Mark Secret as viewed"""
        if self.is_available:
            self.view_count += 1
            self.viewed_at = timezone.now()
            if self.view_count >= self.max_views:
                self.soft_delete()
            self.save()
        else:
            raise SecretNotAvailableError("Secret is not available to be viewed.")

    def soft_delete(self) -> None:
        """Soft delete the secret"""
        if self.is_deleted:
            raise SecretNotAvailableError("Secret is already deleted.")
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()

    def get_shareable_url(self) -> str:
        """Return the shareable URL for the secret."""
        return f"/secret/view/{self.id}"

    class Meta:
        indexes = [
            models.Index(fields=["creator", "expires_at"]),
        ]


class SecretViewLog(TimeStampedModel):
    class FailureReason(models.TextChoices):
        ALREADY_VIEWED = "already_viewed", "Already Viewed"
        EXPIRED = "expired", "Expired"
        NOT_FOUND = "not_found", "Not Found"
        DELETED = "deleted", "Secret Deleted"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    secret = models.ForeignKey(Secret, on_delete=models.SET_NULL, null=True)
    secret_uuid = models.UUIDField(
        db_index=True, help_text="UUID of the secret (kept even after secret deletion)"
    )
    creator = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="secret_view_logs",
    )
    viewed_at = models.DateTimeField()
    ip_address = models.GenericIPAddressField(help_text="IP address of the viewer")
    user_agent = models.TextField(blank=True, null=True)
    # Maybe add later.
    # viewer_identifier = models.CharField(max_length=255, blank=True, null=True)

    # Success tracking
    success = models.BooleanField(
        default=True, db_index=True, help_text="Whether the view was successful"
    )

    failure_reason = models.CharField(
        max_length=50,
        blank=True,
        default="",
        choices=FailureReason.choices,
    )

    class Meta:
        ordering = ["-viewed_at"]
        indexes = [
            models.Index(fields=["creator", "-viewed_at"]),
            models.Index(fields=["secret_uuid", "-viewed_at"]),
            models.Index(fields=["success", "-viewed_at"]),
        ]

    def __str__(self):
        status = "successful" if self.success else "failed"
        return f"{status} view of {self.secret_uuid} at {self.viewed_at}"
