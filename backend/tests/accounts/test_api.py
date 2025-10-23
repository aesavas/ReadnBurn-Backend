import pytest
from accounts.models import User
from rest_framework.test import APIClient


@pytest.mark.django_db
def test_user_registration_api(api_client: APIClient) -> None:
    """Test user registration api."""
    payload = {
        "email": "new_user@readnburn.com",
        "first_name": "New",
        "last_name": "User",
        "password": "Str0ngP@ss!",
        "password_confirm": "Str0ngP@ss!",
    }
    response = api_client.post("/api/auth/register/", payload)

    response_json = response.json()

    assert response.status_code == 201
    assert response_json["status"] == "success"
    assert response_json["message"] == "User registered successfully"
    assert response_json["data"]["email"] == payload["email"]
    assert User.objects.filter(email=payload["email"]).exists()


@pytest.mark.django_db
def test_user_registeration_api_password_mismatch(api_client: APIClient) -> None:
    """Test user registration api password mismatch."""
    payload = {
        "email": "new_user@readnburn.com",
        "first_name": "New",
        "last_name": "User",
        "password": "somepassword1",
        "password_confirm": "somepassword2",
    }
    response = api_client.post("/api/auth/register/", payload)

    response_json = response.json()

    assert response.status_code == 400
    assert response_json["status"] == "error"
    assert response_json["message"] == "User registration failed"
    assert "password_confirm" in response_json["errors"]


@pytest.mark.django_db
def test_user_registeration_api_with_duplicate_email(
    api_client: APIClient, user_account: User
) -> None:
    """Test user registration api with duplicate email."""
    payload = {
        "email": user_account.email,
        "first_name": "New",
        "last_name": "User",
        "password": "somepassword1",
        "password_confirm": "somepassword2",
    }
    response = api_client.post("/api/auth/register/", payload)

    response_json = response.json()

    assert response.status_code == 400
    assert response_json["status"] == "error"
    assert response_json["message"] == "User registration failed"
    assert "email" in response_json["errors"]


@pytest.mark.django_db
def test_user_registeration_api_with_missing_fields(api_client: APIClient) -> None:
    """Test user registration api with missing fields."""
    payload = {
        "email": "new_user@readnburn.com",
        "first_name": "New",
        "password": "somepassword1",
        "password_confirm": "somepassword2",
    }  # last_name missing
    response = api_client.post("/api/auth/register/", payload)

    response_json = response.json()

    assert response.status_code == 400
    assert response_json["status"] == "error"
    assert response_json["message"] == "User registration failed"
    assert "last_name" in response_json["errors"]


@pytest.mark.django_db
def test_user_registeration_api_with_weak_password(api_client: APIClient) -> None:
    """Test user registration api with weak password."""
    payload = {
        "email": "new_user@readnburn.com",
        "first_name": "New",
        "last_name": "User",
        "password": "weak",
        "password_confirm": "weak",
    }
    response = api_client.post("/api/auth/register/", payload)

    response_json = response.json()

    assert response.status_code == 400
    assert response_json["status"] == "error"
    assert response_json["message"] == "User registration failed"
    assert "password" in response_json["errors"]
