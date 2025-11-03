from typing import Dict

from accounts.models import User
from confidential.models import Secret
from django.db.models import F
from django.db.models import Q
from django.utils import timezone


class AnalyticsService:
    """Service class for analytics management."""

    @staticmethod
    def get_user_stats(user: User) -> Dict[str, int]:
        """Get user stats."""
        secrets = Secret.objects.filter(creator=user)
        return {
            "total_secrets": secrets.count(),
            "active_secrets": secrets.filter(
                Q(expires_at__gt=timezone.now())
                & Q(view_count__lt=F("max_views"))
                & Q(is_deleted=False)
            ).count(),
            "viewed_secrets": secrets.filter(view_count__gt=0).count(),
            "pending_secrets": secrets.filter(
                Q(view_count=0) & Q(expires_at__gt=timezone.now()) & Q(is_deleted=False)
            ).count(),
            "expired_secrets": secrets.filter(
                Q(expires_at__lt=timezone.now()) & Q(is_deleted=False)
            ).count(),
            "never_viewed_secrets": secrets.filter(
                Q(view_count=0) & Q(expires_at__lt=timezone.now())
            ).count(),
        }
