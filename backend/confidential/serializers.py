from typing import Any
from typing import Dict

from confidential.models import Secret
from django.utils import timezone
from rest_framework import serializers


class SecretCreateSerializer(serializers.ModelSerializer[Secret]):
    """Serializer for secret data."""

    content = serializers.CharField(
        write_only=True, help_text="Plain text content to encrypt"
    )

    class Meta:
        model = Secret
        fields = (
            "content",
            "expires_at",
            "max_views",
        )

        extra_kwargs = {
            "content": {"required": True},
            "expires_at": {"required": True},
        }

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        if attrs["content"] and len(attrs["content"]) > 10000:
            raise serializers.ValidationError(
                {"content": "Content cannot exceed 10000 characters."}
            )
        elif attrs["content"] and attrs["content"] == "":
            raise serializers.ValidationError({"content": "Content cannot be empty."})
        elif attrs["expires_at"] and attrs["expires_at"] < timezone.now():
            raise serializers.ValidationError(
                {"expires_at": "Expiration date cannot be in the past."}
            )
        elif not attrs["expires_at"]:
            raise serializers.ValidationError(
                {"expires_at": "Expiration date is required."}
            )
        return attrs


class SecretResponseSerializer(serializers.ModelSerializer[Secret]):
    """Serializer for secret data."""

    class Meta:
        model = Secret
        fields = (
            "id",
            "max_views",
            "view_count",
            "expires_at",
            "viewed_at",
            "get_shareable_url",
            "is_expired",
        )
        read_only_fields = fields

    def to_representation(self, instance: Secret) -> dict[str, Any]:
        data = super().to_representation(instance)

        if not instance.is_deleted:
            return {
                "id": data["id"],
                "max_views": data["max_views"],
                "view_count": data["view_count"],
                "expires_at": data["expires_at"],
                "get_shareable_url": data["get_shareable_url"],
                "viewed_at": data["viewed_at"],
                "is_expired": data["is_expired"],
            }

        # Return empty dict for deleted secrets (will be filtered out in views)
        return {}
