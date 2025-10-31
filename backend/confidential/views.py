from typing import cast

from accounts.models import User
from confidential.services import SecretService
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import SecretCreateSerializer
from .serializers import SecretResponseSerializer
from .services import DEFAULT_MAX_VIEWS


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
