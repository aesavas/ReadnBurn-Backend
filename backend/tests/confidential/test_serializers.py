from datetime import timedelta

import pytest
from confidential.serializers import SecretCreateSerializer
from django.utils import timezone
from rest_framework.exceptions import ValidationError


@pytest.mark.django_db
def test_secret_create_serializer() -> None:
    """Test secret create serializer."""
    payload = {
        "content": "Secret content",
        "expires_at": timezone.now() + timedelta(days=1),
        "max_views": 10,
    }
    serializer = SecretCreateSerializer(data=payload)

    assert serializer.is_valid()


@pytest.mark.django_db
def test_secret_create_serializer_invalid_content() -> None:
    """Test secret create serializer invalid content."""
    payload = {
        "content": "Invalid content" * 1000,
        "expires_at": timezone.now() + timedelta(days=1),
        "max_views": 10,
    }
    serializer = SecretCreateSerializer(data=payload)

    assert not serializer.is_valid()
    with pytest.raises(
        ValidationError, match="Content cannot exceed 10000 characters."
    ):
        serializer.is_valid(raise_exception=True)


@pytest.mark.django_db
def test_secret_create_serializer_empty_content() -> None:
    """Test secret create serializer empty content."""
    payload = {
        "content": "",
        "expires_at": timezone.now() + timedelta(days=1),
        "max_views": 10,
    }
    serializer = SecretCreateSerializer(data=payload)

    assert not serializer.is_valid()
    with pytest.raises(ValidationError):
        serializer.is_valid(raise_exception=True)


@pytest.mark.django_db
def test_secret_create_serializer_without_content() -> None:
    """Test secret create serializer without content."""
    payload = {
        "expires_at": timezone.now() + timedelta(days=1),
        "max_views": 10,
    }
    serializer = SecretCreateSerializer(data=payload)

    assert not serializer.is_valid()
    with pytest.raises(ValidationError):
        serializer.is_valid(raise_exception=True)

    assert "content" in serializer.errors


@pytest.mark.django_db
def test_secret_create_serializer_invalid_expiry() -> None:
    """Test secret create serializer invalid expiry."""
    payload = {
        "content": "Secret content",
        "expires_at": timezone.now() - timedelta(days=1),
        "max_views": 10,
    }
    serializer = SecretCreateSerializer(data=payload)

    assert not serializer.is_valid()
    with pytest.raises(ValidationError, match="Expiration date cannot be in the past."):
        serializer.is_valid(raise_exception=True)


@pytest.mark.django_db
def test_secret_create_serializer_empty_expiry() -> None:
    """Test secret create serializer empty expiry."""
    payload = {
        "content": "Secret content",
        "expires_at": None,
        "max_views": 10,
    }
    serializer = SecretCreateSerializer(data=payload)

    assert not serializer.is_valid()
    with pytest.raises(ValidationError, match="Expiration date is required."):
        serializer.is_valid(raise_exception=True)
