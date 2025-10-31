from typing import cast
from uuid import UUID

from accounts.models import User
from confidential.exceptions import SecretAlreadyDeletedError
from confidential.exceptions import SecretAlreadyViewedError
from confidential.exceptions import SecretDoesNotExistError
from confidential.exceptions import SecretExpiredError
from confidential.serializers import SecretCreateSerializer
from confidential.serializers import SecretResponseSerializer
from confidential.services import DEFAULT_MAX_VIEWS
from confidential.services import SecretService
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView


class SecretCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = SecretCreateSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            secret = SecretService.create_secret(
                user=cast(User, request.user),
                content=serializer.validated_data.get("content"),
                expires_at=serializer.validated_data.get("expires_at"),
                max_views=serializer.validated_data.get("max_views", DEFAULT_MAX_VIEWS),
            )
        except ValidationError as e:
            return Response(
                {
                    "status": "error",
                    "message": "Secret creation failed",
                    "errors": e.args[0],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "status": "success",
                "message": "Secret created successfully",
                "data": SecretResponseSerializer(secret).data,
            },
            status=status.HTTP_201_CREATED,
        )


class SecretRetrieveView(APIView):
    permission_classes = [AllowAny]

    def get(self, request: Request, secret_id: UUID) -> Response:
        try:
            secret_content = SecretService.retrieve_and_destroy_secret(
                uuid=secret_id,
                ip_address=str(request.META.get("REMOTE_ADDR")),
                user_agent=str(request.META.get("HTTP_USER_AGENT")),
            )
            return Response(
                {
                    "status": "success",
                    "message": "Secret retrieved successfully",
                    "data": {"content": secret_content},
                },
                status=status.HTTP_200_OK,
            )
        except SecretDoesNotExistError:
            # 404 - Secret not found
            return Response(
                {
                    "status": "error",
                    "message": "Secret not found",
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        except SecretExpiredError:
            # 410 - Gone (expired)
            return Response(
                {
                    "status": "error",
                    "message": "Secret has expired",
                },
                status=status.HTTP_410_GONE,
            )
        except (SecretAlreadyViewedError, SecretAlreadyDeletedError):
            # 410 - Gone (already consumed)
            return Response(
                {
                    "status": "error",
                    "message": "Secret has already been viewed or deleted",
                },
                status=status.HTTP_410_GONE,
            )
        except ValueError:
            # 400 - Invalid UUID format
            return Response(
                {
                    "status": "error",
                    "message": "Invalid secret ID format",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception:
            # 500 - Unexpected server error
            return Response(
                {
                    "status": "error",
                    "message": "An unexpected error occurred",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
