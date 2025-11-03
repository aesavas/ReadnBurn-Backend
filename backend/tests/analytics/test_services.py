from datetime import timedelta

import pytest
from analytics.services import AnalyticsService
from confidential.models import User
from django.utils import timezone
from tests.confidential.factories import SecretFactory


@pytest.mark.django_db
def test_get_user_stats(user_account: User) -> None:
    # 10 never viewed secrets (A)
    SecretFactory.create_batch(
        size=10,
        creator=user_account,
        view_count=0,
        expires_at=timezone.now() - timedelta(days=1),
    )
    # 10 expired secrets and viewed (B)
    SecretFactory.create_batch(
        size=10,
        creator=user_account,
        view_count=1,
        max_views=2,
        expires_at=timezone.now() - timedelta(days=1),
    )
    # 10 pending secrets (also known as active secrets) (C)
    SecretFactory.create_batch(
        size=10,
        creator=user_account,
        view_count=0,
        expires_at=timezone.now() + timedelta(days=1),
    )
    # 10 viewed and active secrets (D)
    SecretFactory.create_batch(
        size=10,
        creator=user_account,
        view_count=1,
        max_views=2,
    )

    stats = AnalyticsService.get_user_stats(user_account)
    # Total secrets 40 (A + B + C + D)
    assert stats["total_secrets"] == 40
    # Active secrets: 10 (C + D)
    assert stats["active_secrets"] == 20
    # Viewed secrets 20 (B + D)
    assert stats["viewed_secrets"] == 20
    # Pending secrets 10
    assert stats["pending_secrets"] == 10
    # Expired secrets 20 (A + B)
    assert stats["expired_secrets"] == 20
    # Never viewed secrets 10
    assert stats["never_viewed_secrets"] == 10
