from typing import Callable

import pytest
from accounts.models import User
from freezegun import freeze_time
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
    assert "password" in response_json["errors"]


@pytest.mark.django_db
def test_user_refresh_token_api_successful(
    api_client: APIClient, user_factory: Callable[..., User]
) -> None:
    """Test user refresh token api."""

    user_account = user_factory(password="Str0ngP@ss!")

    login_payload = {
        "email": user_account.email,
        "password": "Str0ngP@ss!",
    }

    response = api_client.post("/api/auth/login/", login_payload)
    assert response.status_code == 200
    tokens = response.json()["data"]
    access_token = tokens["access"]
    refresh_token = tokens["refresh"]

    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    refresh_payload = {"refresh": refresh_token}
    refresh_response = api_client.post("/api/auth/refresh/", refresh_payload)

    assert refresh_response.status_code == 200

    response_json = refresh_response.json()
    assert response_json["status"] == "success"
    assert response_json["message"] == "Token refreshed successfully"
    assert "access" in response_json["data"]
    assert "refresh" in response_json["data"]
    assert (
        response_json["data"]["refresh"] != refresh_token
    )  # refresh token should be rotated


@pytest.mark.django_db
def test_user_refresh_token_api_fail_with_invalid_token(
    api_client: APIClient, user_factory: Callable[..., User]
) -> None:
    """Test user refresh token api fail with invalid token."""

    user_account = user_factory(password="Str0ngP@ss!")

    login_payload = {
        "email": user_account.email,
        "password": "Str0ngP@ss!",
    }

    response = api_client.post("/api/auth/login/", login_payload)
    assert response.status_code == 200
    tokens = response.json()["data"]
    access_token = tokens["access"]

    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    refresh_payload = {"refresh": "refresh_token"}
    refresh_response = api_client.post("/api/auth/refresh/", refresh_payload)

    assert refresh_response.status_code == 401

    response_json = refresh_response.json()
    assert response_json["status"] == "error"
    assert response_json["message"] == "Token refresh failed"
    assert "Token is invalid" in response_json["errors"]


@pytest.mark.django_db
@freeze_time("2025-01-01 00:00:00")
def test_user_refresh_token_api_fail_with_expired_token_from_view(
    api_client: APIClient, user_factory: Callable[..., User]
) -> None:
    """Test user refresh token api fail with expired token."""

    user_account = user_factory(password="Str0ngP@ss!")

    login_payload = {
        "email": user_account.email,
        "password": "Str0ngP@ss!",
    }

    response = api_client.post("/api/auth/login/", login_payload)
    assert response.status_code == 200
    tokens = response.json()["data"]
    refresh_token = tokens["refresh"]

    api_client.credentials()
    refresh_payload = {"refresh": refresh_token}
    # Move time forward past the refresh token's expiration date (3 days)
    with freeze_time("2025-01-05 12:00:00"):
        refresh_response = api_client.post("/api/auth/refresh/", refresh_payload)

        assert refresh_response.status_code == 401

        response_json = refresh_response.json()
        assert response_json["status"] == "error"
        assert response_json["message"] == "Token refresh failed"
        assert "Token is expired" in response_json["errors"]


@pytest.mark.django_db
@freeze_time("2025-01-01 00:00:00")
def test_user_refresh_token_api_fail_with_expired_token_from_middleware(
    api_client: APIClient, user_factory: Callable[..., User]
) -> None:
    """Test user refresh token api fail with expired token."""

    user_account = user_factory(password="Str0ngP@ss!")

    login_payload = {
        "email": user_account.email,
        "password": "Str0ngP@ss!",
    }

    response = api_client.post("/api/auth/login/", login_payload)
    assert response.status_code == 200
    tokens = response.json()["data"]
    access_token = tokens["access"]
    refresh_token = tokens["refresh"]

    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    refresh_payload = {"refresh": refresh_token}
    # Move time forward past the refresh token's expiration date (3 days)
    # However, middleware should catch this and return 401
    with freeze_time("2025-01-05 12:00:00"):
        refresh_response = api_client.post("/api/auth/refresh/", refresh_payload)

        assert refresh_response.status_code == 401

        response_json = refresh_response.json()
        assert response_json["detail"] == "Given token not valid for any token type"
        assert response_json["code"] == "token_not_valid"
        assert response_json["messages"][0]["message"] == "Token is expired"
        assert response_json["messages"][0]["token_type"] == "access"


@pytest.mark.django_db
def test_user_logout_api_successful(
    api_client: APIClient, user_factory: Callable[..., User]
) -> None:
    """Test that a user can successfully log out."""

    user_account = user_factory(password="Str0ngP@ss!")

    login_data = {
        "email": user_account.email,
        "password": "Str0ngP@ss!",
    }

    response = api_client.post("/api/auth/login/", login_data)
    assert response.status_code == 200
    tokens = response.json()["data"]
    access_token = tokens["access"]
    refresh_token = tokens["refresh"]

    # Call the logout endpoint
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    logout_response = api_client.post("/api/auth/logout/", {"refresh": refresh_token})

    assert logout_response.status_code == 200
    assert logout_response.json()["message"] == "User logged out successfully"

    # Verify the refresh token is now blacklisted and cannot be used
    refresh_attempt_response = api_client.post(
        "/api/auth/refresh/", {"refresh": refresh_token}
    )

    assert refresh_attempt_response.status_code == 401
    assert "blacklisted" in refresh_attempt_response.json()["errors"]


@pytest.mark.django_db
def test_user_logout_api_fail_with_missing_refresh_token(
    api_client: APIClient, user_factory: Callable[..., User]
) -> None:
    """Test that a user cannot log out without a refresh token."""

    user_account = user_factory(password="Str0ngP@ss!")

    login_data = {
        "email": user_account.email,
        "password": "Str0ngP@ss!",
    }

    response = api_client.post("/api/auth/login/", login_data)
    assert response.status_code == 200
    tokens = response.json()["data"]
    access_token = tokens["access"]

    # Call the logout endpoint
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    logout_response = api_client.post("/api/auth/logout/")

    assert logout_response.status_code == 400
    logout_response_json = logout_response.json()
    assert logout_response_json["status"] == "error"
    assert logout_response_json["message"] == "User logout failed"
    assert "Refresh token is required" in logout_response_json["errors"]


@pytest.mark.django_db
def test_user_logout_api_fail_with_invalid_refresh_token(
    api_client: APIClient, user_factory: Callable[..., User]
) -> None:
    """Test that a user cannot log out with an invalid refresh token."""

    user_account = user_factory(password="Str0ngP@ss!")

    login_data = {
        "email": user_account.email,
        "password": "Str0ngP@ss!",
    }

    response = api_client.post("/api/auth/login/", login_data)
    assert response.status_code == 200
    tokens = response.json()["data"]
    access_token = tokens["access"]

    # Call the logout endpoint
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    logout_response = api_client.post("/api/auth/logout/", {"refresh": "invalid_token"})

    assert logout_response.status_code == 400
    logout_response_json = logout_response.json()
    assert logout_response_json["status"] == "error"
    assert logout_response_json["message"] == "User logout failed"
    assert "Token is invalid" in logout_response_json["errors"]


@pytest.mark.django_db
def test_user_profile_api_get_successful(
    auth_user_api_client: APIClient, user_account: User
) -> None:
    """Test that a user can successfully get their profile."""
    response = auth_user_api_client.get("/api/user/profile/")
    assert response.status_code == 200
    response_json = response.json()
    assert response_json["status"] == "success"
    assert response_json["message"] == "User profile retrieved successfully"
    assert response_json["data"]["email"] == user_account.email
    assert response_json["data"]["first_name"] == user_account.first_name
    assert response_json["data"]["last_name"] == user_account.last_name


@pytest.mark.django_db
def test_user_profile_api_put_successful_without_email(
    auth_user_api_client: APIClient, user_account: User
) -> None:
    """Test that a user can successfully update their profile."""
    payload = {
        "first_name": "NewFirstName",
        "last_name": "NewLastName",
    }
    response = auth_user_api_client.put("/api/user/profile/", payload)
    assert response.status_code == 200
    response_json = response.json()
    assert response_json["status"] == "success"
    assert response_json["message"] == "User profile updated successfully"
    assert response_json["data"]["first_name"] == payload["first_name"]
    assert response_json["data"]["last_name"] == payload["last_name"]


@pytest.mark.django_db
def test_user_profile_api_put_successful_with_email(
    auth_user_api_client: APIClient, user_account: User
) -> None:
    """Test that a user can successfully update their profile."""
    payload = {
        "email": user_account.email,
        "first_name": "NewFirstName",
        "last_name": "NewLastName",
    }
    response = auth_user_api_client.put("/api/user/profile/", payload)
    assert response.status_code == 200
    response_json = response.json()
    assert response_json["status"] == "success"
    assert response_json["message"] == "User profile updated successfully"
    assert response_json["data"]["first_name"] == payload["first_name"]
    assert response_json["data"]["last_name"] == payload["last_name"]


@pytest.mark.django_db
def test_user_profile_api_put_fail_with_invalid_email(
    auth_user_api_client: APIClient,
) -> None:
    """Test that a user cannot update their profile with an invalid email."""
    payload = {
        "email": "invalid_email",
        "first_name": "NewFirstName",
        "last_name": "NewLastName",
    }
    response = auth_user_api_client.put("/api/user/profile/", payload)
    assert response.status_code == 400
    response_json = response.json()
    assert response_json["status"] == "error"
    assert response_json["message"] == "User profile update failed"
    assert "Enter a valid email address." in response_json["errors"]["email"][0]


@pytest.mark.django_db
def test_user_profile_api_put_fail_with_invalid_first_name(
    auth_user_api_client: APIClient, user_account: User
) -> None:
    """Test that a user cannot update their profile with an invalid first name."""
    payload = {
        "email": user_account.email,
        "first_name": "A",
        "last_name": "NewLastName",
    }
    response = auth_user_api_client.put("/api/user/profile/", payload)
    assert response.status_code == 400
    response_json = response.json()
    assert response_json["status"] == "error"
    assert response_json["message"] == "User profile update failed"
    assert (
        "Ensure this field has at least 2 characters."
        in response_json["errors"]["first_name"][0]
    )


@pytest.mark.django_db
def test_user_profile_api_patch_successful(
    auth_user_api_client: APIClient, user_account: User
) -> None:
    """Test that a user can successfully update their profile."""
    payload = {
        "first_name": "NewFirstName",
    }
    response = auth_user_api_client.patch("/api/user/profile/", payload)
    assert response.status_code == 200
    response_json = response.json()
    assert response_json["status"] == "success"
    assert response_json["message"] == "User profile updated successfully"
    assert response_json["data"]["first_name"] == payload["first_name"]
    assert response_json["data"]["last_name"] == user_account.last_name


@pytest.mark.django_db
def test_user_profile_api_patch_fail_with_invalid_first_name(
    auth_user_api_client: APIClient,
) -> None:
    """Test that a user cannot update their profile with an invalid first name."""
    payload = {
        "first_name": "A",
    }
    response = auth_user_api_client.patch("/api/user/profile/", payload)
    assert response.status_code == 400
    response_json = response.json()
    assert response_json["status"] == "error"
    assert response_json["message"] == "User profile update failed"
    assert (
        "Ensure this field has at least 2 characters."
        in response_json["errors"]["first_name"][0]
    )
