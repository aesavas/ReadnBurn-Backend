from typing import Any
from typing import Dict
from typing import TypedDict

from accounts.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class UserRegistrationSerializer(serializers.ModelSerializer[User]):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = (
            "email",
            "first_name",
            "last_name",
            "password",
            "password_confirm",
            "email_notification_enabled",
            "sms_notification_enabled",
        )
        extra_kwargs = {
            "email": {"required": True},
            "first_name": {"required": True},
            "last_name": {"required": True},
        }

    def validate_email(self, value: str) -> str:
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError({"email": "Email is already registered."})
        return value

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "Passwords do not match."}
            )
        return attrs

    def create(self, validated_data: Dict[str, Any]) -> User:
        validated_data.pop("password_confirm")
        email = validated_data.pop("email")
        password = validated_data.pop("password")
        return User.objects.create_user(
            email=email, password=password, **validated_data
        )


class UserData(TypedDict):
    id: str
    email: str
    first_name: str
    last_name: str
    is_superuser: bool
    is_staff: bool
    email_verified: bool


class UserLoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        # Get the original data, which is Dict[str, str]
        data: Dict[str, str] = super().validate(attrs)

        # Create the user data payload
        assert self.user is not None
        assert isinstance(self.user, User)

        user_data: UserData = {
            "id": str(self.user.id),
            "email": self.user.email,
            "first_name": self.user.first_name,
            "last_name": self.user.last_name,
            "is_superuser": self.user.is_superuser,
            "is_staff": self.user.is_staff,
            "email_verified": self.user.email_verified,
        }

        return {
            **data,
            "user": user_data,
        }
