from datetime import timedelta

import pytest
from accounts.models import User
from django.utils import timezone
from rest_framework.test import APIClient
from tests.confidential.factories import SecretFactory


@pytest.mark.django_db
def test_dashboard_stats(api_client: APIClient, user_account: User) -> None:
    api_client.force_authenticate(user=user_account)

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

    response = api_client.get("/api/analytics/stats/")

    assert response.status_code == 200

    response_json = response.json()

    assert response_json["status"] == "success"
    assert response_json["message"] == "Dashboard stats retrieved successfully"
    assert response_json["data"]["total_secrets"] == 40
    assert response_json["data"]["active_secrets"] == 20
    assert response_json["data"]["viewed_secrets"] == 20
    assert response_json["data"]["pending_secrets"] == 10
    assert response_json["data"]["expired_secrets"] == 20
    assert response_json["data"]["never_viewed_secrets"] == 10
