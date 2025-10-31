from datetime import datetime
from datetime import timedelta
from typing import cast

import pytest
from core.encryption import decrypt_message
from django.utils import timezone
from pytest import MonkeyPatch
from rest_framework.test import APIClient

from backend.settings_test import TEST_ENCRYPTION_KEY


@pytest.mark.django_db
def test_secret_create_api(
    auth_user_api_client: APIClient, monkeypatch: MonkeyPatch
) -> None:
    """Test secret creation API."""
    # Use test encryption key for this test
    monkeypatch.setattr("backend.settings.ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)
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

    assert (
        decrypt_message(
            response_json["data"]["encrypted_content"], TEST_ENCRYPTION_KEY.encode()
        )
        == payload["content"]
    )
    assert response_json["data"]["expires_at"] == cast(
        datetime, payload["expires_at"]
    ).isoformat().replace("+00:00", "Z")
    assert response_json["data"]["max_views"] == payload["max_views"]


@pytest.mark.django_db
def test_secret_create_api_invalid_content(
    auth_user_api_client: APIClient, monkeypatch: MonkeyPatch
) -> None:
    """Test secret creation API with invalid content."""
    # Use test encryption key for this test
    monkeypatch.setattr("backend.settings.ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)
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
def test_secret_create_api_missing_content(
    auth_user_api_client: APIClient, monkeypatch: MonkeyPatch
) -> None:
    """Test secret creation API with missing content."""
    # Use test encryption key for this test
    monkeypatch.setattr("backend.settings.ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)
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
def test_secret_create_api_invalid_expires_at(
    auth_user_api_client: APIClient, monkeypatch: MonkeyPatch
) -> None:
    """Test secret creation API with invalid expires at."""
    # Use test encryption key for this test
    monkeypatch.setattr("backend.settings.ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)
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
def test_secret_create_api_missing_max_views(
    auth_user_api_client: APIClient, monkeypatch: MonkeyPatch
) -> None:
    """Test secret creation API with missing max views."""
    # Use test encryption key for this test
    monkeypatch.setattr("backend.settings.ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)
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
def test_secret_create_api_unauthorized(
    api_client: APIClient, monkeypatch: MonkeyPatch
) -> None:
    """Test secret creation API with unauthorized user."""
    # Use test encryption key for this test
    monkeypatch.setattr("backend.settings.ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)
    payload = {
        "content": "Secret content",
        "expires_at": timezone.now() + timedelta(days=1),
        "max_views": 10,
    }
    response = api_client.post("/api/secrets/create/", payload)

    assert response.status_code == 401
