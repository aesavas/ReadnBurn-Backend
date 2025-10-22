# mypy: ignore-errors

import uuid

from core.models import TimeStampedModel
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.models import UserManager
from django.db import models


class CustomUserManager(UserManager):
    """Custom user manager for handling user creation."""

    def _create_user(self, first_name, last_name, email, password, **extra_fields):
        """Create and persist a user with a normalized email address."""
        if not email:
            raise ValueError("You have not provided a valid e-mail address")

        email = self.normalize_email(email)
        user = self.model(
            email=email, first_name=first_name, last_name=last_name, **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(
        self, first_name=None, last_name=None, email=None, password=None, **extra_fields
    ):
        """Create a regular user account with non-staff, non-superuser flags."""
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(first_name, last_name, email, password, **extra_fields)

    def create_superuser(
        self, first_name=None, last_name=None, email=None, password=None, **extra_fields
    ):
        """Create an administrator account with staff and superuser privileges."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self._create_user(first_name, last_name, email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin, TimeStampedModel):
    "User model"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=255, blank=False)
    last_name = models.CharField(max_length=255, blank=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    last_login = models.DateTimeField(blank=True, null=True)
    email_verified = models.BooleanField(default=False)
    email_notification_enabled = models.BooleanField(default=False)
    sms_notification_enabled = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = []
