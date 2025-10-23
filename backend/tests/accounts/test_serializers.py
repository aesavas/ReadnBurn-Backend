import pytest
from accounts.models import User
from accounts.serializers import UserRegistrationSerializer


@pytest.mark.django_db
def test_user_registeration_serializer() -> None:
    """Test user registration serializer."""
    payload = {
        "email": "new_user@readnburn.com",
        "first_name": "New",
        "last_name": "User",
        "password": "Str0ngP@ss!",
        "password_confirm": "Str0ngP@ss!",
        "email_notification_enabled": True,
        "sms_notification_enabled": False,
    }
    serializer = UserRegistrationSerializer(data=payload)

    assert serializer.is_valid()
    user = serializer.save()

    assert user.email == payload["email"]
    assert user.first_name == payload["first_name"]
    assert user.check_password(str(payload["password"]))


@pytest.mark.django_db
def test_user_registration_serializer_duplicate_email(user_account: User) -> None:
    """Test user registration serializer duplicate email."""
    payload = {
        "email": user_account.email,
        "first_name": "Duplicate",
        "last_name": "User",
        "password": "Str0ngP@ss!",
        "password_confirm": "Str0ngP@ss!",
    }
    serializer = UserRegistrationSerializer(data=payload)

    assert not serializer.is_valid()
    assert "email" in serializer.errors


@pytest.mark.django_db
def test_user_registration_serializer_password_mismatch() -> None:
    """Test user registration serializer password mismatch."""
    payload = {
        "email": "mismatch@readnburn.com",
        "first_name": "Mismatch",
        "last_name": "User",
        "password": "Str0ngP@ss!",
        "password_confirm": "WrongP@ss!",
    }
    serializer = UserRegistrationSerializer(data=payload)

    assert not serializer.is_valid()
    assert "password_confirm" in serializer.errors


@pytest.mark.django_db
def test_user_registeration_serializer_missing_fields() -> None:
    """Test user registration serializer missing fields."""
    payload = {
        "email": "mismatch@readnburn.com",
        "password": "Str0ngP@ss!",
        "password_confirm": "WrongP@ss!",
    }
    serializer = UserRegistrationSerializer(data=payload)
    assert not serializer.is_valid()
    assert "first_name" in serializer.errors
    assert "last_name" in serializer.errors


@pytest.mark.django_db
def test_user_registeration_serializer_weak_password() -> None:
    """Test user registration serializer weak password."""
    payload = {
        "email": "new_user@readnburn.com",
        "first_name": "New",
        "last_name": "User",
        "password": "weak",
        "password_confirm": "weak",
        "email_notification_enabled": True,
        "sms_notification_enabled": False,
    }
    serializer = UserRegistrationSerializer(data=payload)

    assert not serializer.is_valid()
    assert "password" in serializer.errors


@pytest.mark.django_db
def test_user_registeration_serializer_email_validation(user_account: User) -> None:
    """Test user registration serializer email validation."""
    payload = {
        "email": user_account.email.upper(),
        "first_name": "New",
        "last_name": "User",
        "password": "Str0ngP@ss!",
        "password_confirm": "Str0ngP@ss!",
    }
    serializer = UserRegistrationSerializer(data=payload)

    assert not serializer.is_valid()
    assert "email" in serializer.errors


@pytest.mark.django_db
def test_user_registeration_serializer_notification_default_values() -> None:
    """Test user registration serializer notification default values."""
    payload = {
        "email": "new_user@readnburn.com",
        "first_name": "New",
        "last_name": "User",
        "password": "Str0ngP@ss!",
        "password_confirm": "Str0ngP@ss!",
    }
    serializer = UserRegistrationSerializer(data=payload)

    assert serializer.is_valid()
    user = serializer.save()

    assert user.email_notification_enabled is False
    assert user.sms_notification_enabled is False
