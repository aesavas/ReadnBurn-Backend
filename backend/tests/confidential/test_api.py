import uuid
from datetime import datetime
from datetime import timedelta
from typing import cast

import pytest
from accounts.models import User
from confidential.models import Secret
from confidential.models import SecretViewLog
from django.utils import timezone
from freezegun import freeze_time
from rest_framework.test import APIClient
from tests.confidential.factories import SecretFactory
from tests.confidential.factories import UserFactory
from tests.conftest import SecretFactoryCallable


@pytest.mark.django_db
def test_secret_create_api(auth_user_api_client: APIClient) -> None:
    """Test secret creation API."""
    payload = {
        "content": "Secret content",
        "expires_at": timezone.now() + timedelta(days=1),
        "max_views": 10,
    }
    response = auth_user_api_client.post("/api/secrets/create/", payload)

    response_json = response.json()

    assert response.status_code == 201
    assert response_json["status"] == "success"
    assert response_json["message"] == "Secret created successfully"
    assert response_json["data"]["expires_at"] == cast(
        datetime, payload["expires_at"]
    ).isoformat().replace("+00:00", "Z")
    assert response_json["data"]["max_views"] == payload["max_views"]


@pytest.mark.django_db
def test_secret_create_api_invalid_content(auth_user_api_client: APIClient) -> None:
    """Test secret creation API with invalid content."""
    payload = {
        "content": "",
        "expires_at": timezone.now() + timedelta(days=1),
        "max_views": 10,
    }
    response = auth_user_api_client.post("/api/secrets/create/", payload)

    response_json = response.json()

    assert response.status_code == 400
    assert response_json["status"] == "error"
    assert response_json["message"] == "Secret creation failed"
    assert "content" in response_json["errors"]


@pytest.mark.django_db
def test_secret_create_api_missing_content(auth_user_api_client: APIClient) -> None:
    """Test secret creation API with missing content."""
    payload = {
        "expires_at": timezone.now() + timedelta(days=1),
        "max_views": 10,
    }
    response = auth_user_api_client.post("/api/secrets/create/", payload)

    response_json = response.json()

    assert response.status_code == 400
    assert response_json["status"] == "error"
    assert response_json["message"] == "Secret creation failed"
    assert "content" in response_json["errors"]


@pytest.mark.django_db
def test_secret_create_api_invalid_expires_at(auth_user_api_client: APIClient) -> None:
    """Test secret creation API with invalid expires at."""
    payload = {
        "content": "Secret content",
        "expires_at": timezone.now() - timedelta(days=1),
        "max_views": 10,
    }
    response = auth_user_api_client.post("/api/secrets/create/", payload)

    response_json = response.json()

    assert response.status_code == 400
    assert response_json["status"] == "error"
    assert response_json["message"] == "Secret creation failed"
    assert "expires_at" in response_json["errors"]


@pytest.mark.django_db
def test_secret_create_api_missing_max_views(auth_user_api_client: APIClient) -> None:
    """Test secret creation API with missing max views."""
    payload = {
        "content": "Secret content",
        "expires_at": timezone.now() + timedelta(days=1),
    }
    response = auth_user_api_client.post("/api/secrets/create/", payload)

    response_json = response.json()

    assert response.status_code == 201
    assert response_json["status"] == "success"
    assert response_json["message"] == "Secret created successfully"
    assert response_json["data"]["max_views"] == 1  # default 1


@pytest.mark.django_db
def test_secret_create_api_unauthorized(api_client: APIClient) -> None:
    """Test secret creation API with unauthorized user."""
    payload = {
        "content": "Secret content",
        "expires_at": timezone.now() + timedelta(days=1),
        "max_views": 10,
    }
    response = api_client.post("/api/secrets/create/", payload)

    assert response.status_code == 401


@pytest.mark.django_db
def test_secret_retrieve_api(
    auth_user_api_client: APIClient,
    secret_factory: SecretFactoryCallable,
) -> None:
    """Test secret retrieve API."""
    my_secret = "ReadnBurn"
    secret = secret_factory(plain_content=my_secret)
    secret.refresh_from_db()

    assert Secret.objects.get(id=secret.id).view_count == 0

    response = auth_user_api_client.get(f"/api/secrets/retrieve/{secret.id}")

    assert response.status_code == 200
    response_json = response.json()

    assert response_json["status"] == "success"
    assert response_json["message"] == "Secret retrieved successfully"
    assert response_json["data"]["content"] == my_secret

    assert Secret.objects.get(id=secret.id).view_count == 1
    assert SecretViewLog.objects.filter(secret=secret).all().count() == 1


@pytest.mark.django_db
def test_secret_retrieve_api_secret_does_not_exist(
    auth_user_api_client: APIClient,
) -> None:
    """Test secret retrieve API with secret does not exist."""
    response = auth_user_api_client.get(f"/api/secrets/retrieve/{uuid.uuid4()}")

    assert response.status_code == 404
    response_json = response.json()

    assert response_json["status"] == "error"
    assert response_json["message"] == "Secret not found"


@pytest.mark.django_db
@freeze_time("2025-01-01 00:00:00")
def test_secret_retrieve_api_secret_expired(
    auth_user_api_client: APIClient,
    secret_factory: SecretFactoryCallable,
) -> None:
    """Test secret retrieve API with secret expired."""
    my_secret = "ReadnBurn"
    secret = secret_factory(
        plain_content=my_secret, expires_at=timezone.now() - timedelta(days=1)
    )
    secret.refresh_from_db()

    assert Secret.objects.get(id=secret.id).view_count == 0

    with freeze_time("2025-01-03 00:00:00"):
        response = auth_user_api_client.get(f"/api/secrets/retrieve/{secret.id}")

        assert response.status_code == 410
        response_json = response.json()

        assert response_json["status"] == "error"
        assert response_json["message"] == "Secret has expired"


@pytest.mark.django_db
def test_secret_retrieve_api_secret_already_viewed(
    auth_user_api_client: APIClient,
    secret_factory: SecretFactoryCallable,
) -> None:
    """Test secret retrieve API with secret already viewed. (With calling twice)"""
    my_secret = "ReadnBurn"
    secret = secret_factory(plain_content=my_secret)
    secret.refresh_from_db()

    assert Secret.objects.get(id=secret.id).view_count == 0

    response_1 = auth_user_api_client.get(f"/api/secrets/retrieve/{secret.id}")

    assert response_1.status_code == 200
    response_json1 = response_1.json()

    assert response_json1["status"] == "success"
    assert response_json1["message"] == "Secret retrieved successfully"
    assert response_json1["data"]["content"] == my_secret

    response_2 = auth_user_api_client.get(f"/api/secrets/retrieve/{secret.id}")

    assert response_2.status_code == 410
    response_json2 = response_2.json()

    assert response_json2["status"] == "error"
    assert response_json2["message"] == "Secret has already been viewed or deleted"

    # Because we are calling twice, it should be 2
    assert SecretViewLog.objects.filter(secret=secret).all().count() == 2


@pytest.mark.django_db
def test_secret_retrieve_api_secret_deleted(
    auth_user_api_client: APIClient,
    secret_factory: SecretFactoryCallable,
) -> None:
    """Test secret retrieve API with secret deleted."""
    my_secret = "ReadnBurn"
    secret = secret_factory(plain_content=my_secret)
    secret.refresh_from_db()

    secret.soft_delete()  # Soft delete the secret
    secret.refresh_from_db()

    assert secret.is_deleted
    assert secret.deleted_at is not None

    response = auth_user_api_client.get(f"/api/secrets/retrieve/{secret.id}")

    assert response.status_code == 410
    response_json = response.json()

    assert response_json["status"] == "error"
    assert response_json["message"] == "Secret has already been viewed or deleted"


@pytest.mark.django_db
def test_secret_detail_api(
    auth_user_api_client: APIClient,
    secret_factory: SecretFactoryCallable,
) -> None:
    """Test secret detail API."""
    my_secret = "ReadnBurn"
    secret = secret_factory(plain_content=my_secret)
    secret.refresh_from_db()

    response = auth_user_api_client.get(f"/api/secrets/detail/{secret.id}")

    assert response.status_code == 200
    response_json = response.json()

    assert response_json["status"] == "success"
    assert response_json["message"] == "Secret retrieved successfully"
    assert response_json["data"]["id"] == str(secret.id)
    assert response_json["data"]["max_views"] == secret.max_views
    assert response_json["data"]["view_count"] == secret.view_count
    assert response_json["data"]["expires_at"] == cast(
        datetime, secret.expires_at
    ).isoformat().replace("+00:00", "Z")
    assert response_json["data"]["get_shareable_url"] == secret.get_shareable_url()


@pytest.mark.django_db
def test_secret_detail_api_secret_does_not_exist(
    auth_user_api_client: APIClient,
) -> None:
    """Test secret detail API with secret does not exist."""
    response = auth_user_api_client.get(f"/api/secrets/detail/{uuid.uuid4()}")

    assert response.status_code == 404
    response_json = response.json()

    assert response_json["status"] == "error"
    assert response_json["message"] == "Secret not found"


@pytest.mark.django_db
def test_secret_detail_api_secret_deleted(
    auth_user_api_client: APIClient,
    secret_factory: SecretFactoryCallable,
) -> None:
    """Test secret detail API with secret deleted."""
    my_secret = "ReadnBurn"
    secret = secret_factory(plain_content=my_secret)
    secret.refresh_from_db()

    secret.soft_delete()  # Soft delete the secret
    secret.refresh_from_db()

    assert secret.is_deleted
    assert secret.deleted_at is not None

    response = auth_user_api_client.get(f"/api/secrets/detail/{secret.id}")

    assert response.status_code == 410
    response_json = response.json()

    assert response_json["status"] == "error"
    assert response_json["message"] == "Secret has already been deleted"


@pytest.mark.django_db
def test_secret_delete_api(
    api_client: APIClient,
    user_account: User,
    secret_factory: SecretFactoryCallable,
) -> None:
    """Test secret delete API."""
    api_client.force_authenticate(user=user_account)
    my_secret = "ReadnBurn"
    secret = secret_factory(plain_content=my_secret, creator=user_account)
    secret.refresh_from_db()

    response = api_client.delete(f"/api/secrets/delete/{secret.id}")
    secret.refresh_from_db()

    assert response.status_code == 200
    response_json = response.json()

    assert response_json["status"] == "success"
    assert response_json["message"] == "Secret deleted successfully"
    assert secret.is_deleted
    assert secret.deleted_at is not None
    assert Secret.objects.filter(id=secret.id).exists() is True  # proof of soft delete


@pytest.mark.django_db
def test_secret_delete_api_secret_does_not_exist(
    api_client: APIClient,
    user_account: User,
) -> None:
    api_client.force_authenticate(user=user_account)
    response = api_client.delete(f"/api/secrets/delete/{uuid.uuid4()}")

    assert response.status_code == 404
    response_json = response.json()

    assert response_json["status"] == "error"
    assert response_json["message"] == "Secret not found"


@pytest.mark.django_db
def test_secret_delete_api_secret_already_deleted(
    api_client: APIClient,
    user_account: User,
    secret_factory: SecretFactoryCallable,
) -> None:
    api_client.force_authenticate(user=user_account)
    my_secret = "ReadnBurn"
    secret = secret_factory(plain_content=my_secret, creator=user_account)
    secret.refresh_from_db()

    secret.soft_delete()  # Soft delete the secret
    secret.refresh_from_db()

    assert secret.is_deleted
    assert secret.deleted_at is not None

    response = api_client.delete(f"/api/secrets/delete/{secret.id}")
    secret.refresh_from_db()

    assert response.status_code == 410
    response_json = response.json()

    assert response_json["status"] == "error"
    assert response_json["message"] == "Secret has already been deleted"


@pytest.mark.django_db
def test_secret_delete_api_secret_not_owner(
    api_client: APIClient,
    user_account: User,
    secret_factory: SecretFactoryCallable,
) -> None:
    api_client.force_authenticate(user=user_account)
    my_secret = "ReadnBurn"
    secret = secret_factory(plain_content=my_secret)
    secret.refresh_from_db()

    response = api_client.delete(f"/api/secrets/delete/{secret.id}")
    secret.refresh_from_db()

    assert response.status_code == 404
    response_json = response.json()

    assert response_json["status"] == "error"
    assert response_json["message"] == "Secret not found"
    assert not secret.is_deleted
    assert secret.deleted_at is None
    assert Secret.objects.filter(id=secret.id).exists() is True  # proof of soft delete


@pytest.mark.django_db
def test_secret_delete_api_unauthorized(api_client: APIClient) -> None:
    response = api_client.delete(f"/api/secrets/delete/{uuid.uuid4()}")

    assert response.status_code == 401


@pytest.mark.django_db
def test_secret_list_api(
    api_client: APIClient,
    user_account: User,
) -> None:
    api_client.force_authenticate(user=user_account)
    SecretFactory.create_batch(size=10, creator=user_account)

    response = api_client.get("/api/secrets/")

    assert response.status_code == 200
    response_json = response.json()

    assert response_json["status"] == "success"
    assert response_json["message"] == "Secrets retrieved successfully"
    assert len(response_json["data"]) == 10
    assert response_json["pagination"]["page"] == 1
    assert response_json["pagination"]["page_size"] == 10
    assert response_json["pagination"]["total"] == 10
    assert response_json["pagination"]["has_next"] is False


@pytest.mark.django_db
def test_secret_list_api_with_page_size_20(
    api_client: APIClient,
    user_account: User,
) -> None:
    api_client.force_authenticate(user=user_account)
    SecretFactory.create_batch(size=20, creator=user_account)

    response = api_client.get("/api/secrets/?page_size=20")

    assert response.status_code == 200
    response_json = response.json()

    assert response_json["status"] == "success"
    assert response_json["message"] == "Secrets retrieved successfully"
    assert len(response_json["data"]) == 20
    assert response_json["pagination"]["page"] == 1
    assert response_json["pagination"]["page_size"] == 20
    assert response_json["pagination"]["total"] == 20
    assert response_json["pagination"]["has_next"] is False


@pytest.mark.django_db
def test_secret_list_api_with_page_2(
    api_client: APIClient,
    user_account: User,
) -> None:
    api_client.force_authenticate(user=user_account)
    SecretFactory.create_batch(size=20, creator=user_account)

    response = api_client.get("/api/secrets/?page=2")

    assert response.status_code == 200
    response_json = response.json()

    assert response_json["status"] == "success"
    assert response_json["message"] == "Secrets retrieved successfully"
    assert len(response_json["data"]) == 10
    assert response_json["pagination"]["page"] == 2
    assert response_json["pagination"]["page_size"] == 10
    assert response_json["pagination"]["total"] == 20
    assert response_json["pagination"]["has_next"] is False
    assert response_json["pagination"]["has_prev"] is True


@pytest.mark.django_db
def test_secret_list_api_with_multiple_pages(
    api_client: APIClient,
    user_account: User,
) -> None:
    api_client.force_authenticate(user=user_account)
    SecretFactory.create_batch(size=50, creator=user_account)

    response = api_client.get("/api/secrets/?page=2&page_size=20")

    assert response.status_code == 200
    response_json = response.json()

    assert response_json["status"] == "success"
    assert response_json["message"] == "Secrets retrieved successfully"
    assert len(response_json["data"]) == 20
    assert response_json["pagination"]["page"] == 2
    assert response_json["pagination"]["page_size"] == 20
    assert response_json["pagination"]["total"] == 50
    assert response_json["pagination"]["has_next"] is True
    assert response_json["pagination"]["has_prev"] is True


@pytest.mark.django_db
def test_secret_list_api_with_expired_status(
    api_client: APIClient, user_account: User
) -> None:
    api_client.force_authenticate(user=user_account)
    # Create 10 expired secrets
    SecretFactory.create_batch(
        size=10, creator=user_account, expires_at=timezone.now() - timedelta(days=1)
    )
    # Create 20 active secrets
    SecretFactory.create_batch(size=20, creator=user_account)

    response = api_client.get("/api/secrets/?page=2&page_size=5&status=expired")
    response_json = response.json()

    assert response.status_code == 200
    assert response_json["status"] == "success"
    assert response_json["message"] == "Secrets retrieved successfully"
    assert len(response_json["data"]) == 5
    assert response_json["pagination"]["page"] == 2
    assert response_json["pagination"]["page_size"] == 5
    assert response_json["pagination"]["total"] == 10
    assert response_json["pagination"]["has_next"] is False
    assert response_json["pagination"]["has_prev"] is True


@pytest.mark.django_db
def test_secret_list_api_with_viewed_status(
    api_client: APIClient, user_account: User
) -> None:
    api_client.force_authenticate(user=user_account)
    # Create 10 viewed secrets
    SecretFactory.create_batch(
        size=10, creator=user_account, view_count=1, viewed_at=timezone.now()
    )
    # Create 20 active secrets
    SecretFactory.create_batch(size=20, creator=user_account)

    response = api_client.get("/api/secrets/?page=2&page_size=5&status=viewed")
    response_json = response.json()

    assert response.status_code == 200
    assert response_json["status"] == "success"
    assert response_json["message"] == "Secrets retrieved successfully"
    assert len(response_json["data"]) == 5
    assert response_json["pagination"]["page"] == 2
    assert response_json["pagination"]["page_size"] == 5
    assert response_json["pagination"]["total"] == 10
    assert response_json["pagination"]["has_next"] is False
    assert response_json["pagination"]["has_prev"] is True


@pytest.mark.django_db
def test_secret_list_api_with_active_status(
    api_client: APIClient, user_account: User
) -> None:
    api_client.force_authenticate(user=user_account)
    # Create 10 active secrets
    SecretFactory.create_batch(size=10, creator=user_account)
    # Create 20 expired secrets
    SecretFactory.create_batch(
        size=20, creator=user_account, expires_at=timezone.now() - timedelta(days=1)
    )
    # Create 20 viewed secrets
    SecretFactory.create_batch(
        size=20, creator=user_account, view_count=1, viewed_at=timezone.now()
    )

    response = api_client.get("/api/secrets/?page=2&page_size=5&status=active")
    response_json = response.json()

    assert response.status_code == 200
    assert response_json["status"] == "success"
    assert response_json["message"] == "Secrets retrieved successfully"
    assert len(response_json["data"]) == 5
    assert response_json["pagination"]["page"] == 2
    assert response_json["pagination"]["page_size"] == 5
    assert response_json["pagination"]["total"] == 10
    assert response_json["pagination"]["has_next"] is False
    assert response_json["pagination"]["has_prev"] is True


@pytest.mark.django_db
def test_secret_list_api_with_unauthorized(api_client: APIClient) -> None:
    response = api_client.get("/api/secrets/?page=2&page_size=5&status=active")

    assert response.status_code == 401


@pytest.mark.django_db
def test_secret_list_api_with_invalid_status(
    api_client: APIClient, user_account: User
) -> None:
    api_client.force_authenticate(user=user_account)
    response = api_client.get("/api/secrets/?page=2&page_size=5&status=invalid")
    response_json = response.json()

    assert response.status_code == 400
    assert response_json["status"] == "error"
    assert response_json["message"] == "Invalid status"


@pytest.mark.django_db
def test_secret_list_api_with_different_user(
    api_client: APIClient, user_account: User
) -> None:
    api_client.force_authenticate(user=user_account)
    other_user = UserFactory()
    SecretFactory.create_batch(size=10, creator=other_user)
    response = api_client.get("/api/secrets/?page=1&page_size=10&status=active")
    response_json = response.json()

    assert response.status_code == 200
    assert response_json["status"] == "success"
    assert response_json["message"] == "Secrets retrieved successfully"
    assert len(response_json["data"]) == 0
    assert response_json["pagination"]["page"] == 1
    assert response_json["pagination"]["page_size"] == 10
    assert response_json["pagination"]["total"] == 0
    assert response_json["pagination"]["has_next"] is False
