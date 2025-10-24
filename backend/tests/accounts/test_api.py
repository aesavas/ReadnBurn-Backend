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


@pytest.mark.django_db
def test_user_login_api_successful(api_client: APIClient) -> None:
    """Test user login api."""
    user_data = {
        "email": "new_user@readnburn.com",
        "first_name": "New",
        "last_name": "User",
        "password": "Str0ngP@ss!",
        "password_confirm": "Str0ngP@ss!",
    }

    response = api_client.post("/api/auth/register/", user_data)

    assert response.status_code == 201  # User created succesfully.

    # LOGIN PROCESS
    payload = {
        "email": user_data["email"],
        "password": user_data["password"],
    }

    response = api_client.post("/api/auth/login/", payload)

    response_json = response.json()

    assert response.status_code == 200
    assert response_json["status"] == "success"
    assert response_json["message"] == "User logged in successfully"
    assert "access" in response_json["data"]
    assert "refresh" in response_json["data"]
    assert "user" in response_json["data"]
    assert response_json["data"]["user"]["email"] == user_data["email"]
    assert response_json["data"]["user"]["first_name"] == user_data["first_name"]
    assert response_json["data"]["user"]["last_name"] == user_data["last_name"]
    assert not response_json["data"]["user"]["is_superuser"]  # default False
    assert not response_json["data"]["user"]["is_staff"]  # default False
    assert not response_json["data"]["user"]["email_verified"]  # default False


@pytest.mark.django_db
def test_user_login_api_fail_with_wrong_password(
    api_client: APIClient, user_account: User
) -> None:
    """Test user login api fail with wrong password."""

    payload = {
        "email": user_account.email,
        "password": "somewrongpassword",
    }

    response = api_client.post("/api/auth/login/", payload)

    response_json = response.json()

    assert response.status_code == 401
    assert response_json["status"] == "error"
    assert response_json["message"] == "User login failed"


@pytest.mark.django_db
def test_user_login_api_fail_with_missing_field(
    api_client: APIClient, user_account: User
) -> None:
    """Test user login api fail with missing field."""

    payload = {
        "email": user_account.email,
    }

    response = api_client.post("/api/auth/login/", payload)

    response_json = response.json()

    assert response.status_code == 400
    assert response_json["status"] == "error"
    assert response_json["message"] == "User login failed"
    assert "password" in response_json["errors"]["detail"]
