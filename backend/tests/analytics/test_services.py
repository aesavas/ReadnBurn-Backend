from datetime import timedelta
from typing import Any
from typing import Callable
from typing import ContextManager

import pytest
from analytics.services import AnalyticsService
from confidential.models import User
from django.core.cache import cache
from django.test.utils import override_settings
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


@pytest.mark.django_db
@override_settings(
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    }
)
def test_cache_hit_miss_behavior(
    user_account: User,
    django_assert_num_queries: Callable[[int], ContextManager[Any]],
) -> None:
    """Test that cache is used for stats queries."""
    # Clear any existing cache
    cache.clear()

    SecretFactory.create_batch(size=5, creator=user_account)

    # First call - cache miss (should execute DB queries)
    with django_assert_num_queries(6):
        stats1 = AnalyticsService.get_user_stats(user_account)

    # Verify data is cached
    cache_key = f"user_stats_{user_account.id}"
    assert cache.get(cache_key) is not None

    # Second call - cache hit (should not execute DB queries)
    with django_assert_num_queries(0):
        stats2 = AnalyticsService.get_user_stats(user_account)

    # Both calls should return same data
    assert stats1 == stats2
    assert stats1["total_secrets"] == 5

    # Clear cache and verify miss behavior
    cache.delete(cache_key)

    # Third call - cache miss again
    with django_assert_num_queries(6):
        stats3 = AnalyticsService.get_user_stats(user_account)

    assert stats3 == stats1
