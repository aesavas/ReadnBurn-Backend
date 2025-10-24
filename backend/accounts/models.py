# mypy: ignore-errors

import uuid

from core.models import TimeStampedModel
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.utils.timesince import timesince


class CustomUserManager(BaseUserManager):
    """Custom user manager for handling user creation."""

    def _create_user(self, email: str, password: str, **extra_fields) -> "User":
        """Create and persist a user with a normalized email address."""
        if not email:
            raise ValueError("You have not provided a valid e-mail address")
        # first_name and last_name are required fields, so we expect them in extra_fields
        if "first_name" not in extra_fields:
            raise ValueError("The first_name field must be set")
        if "last_name" not in extra_fields:
            raise ValueError("The last_name field must be set")

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str, **extra_fields) -> "User":
        """Create a regular user account with non-staff, non-superuser flags."""
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("is_active", True)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email: str, password: str, **extra_fields) -> "User":
        """Create an administrator account with staff and superuser privileges."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin, TimeStampedModel):
    "User model"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=255, blank=False)
    last_name = models.CharField(max_length=255, blank=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    last_login = models.DateTimeField(blank=True, null=True)
    email_verified = models.BooleanField(default=False)
    email_notification_enabled = models.BooleanField(default=False)
    sms_notification_enabled = models.BooleanField(default=False)

    @property
    def since_joined(self) -> str:
        """Return a human-readable string of how long ago the user joined."""
        return f"{timesince(self.created_at)} ago"

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]
