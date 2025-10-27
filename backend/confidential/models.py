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
