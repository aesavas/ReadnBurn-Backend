from accounts.serializers import UserLoginSerializer
from accounts.serializers import UserRegistrationSerializer
from rest_framework import permissions
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.exceptions import ValidationError
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView


class UserRegistrationView(APIView):
    """Handle user registration requests."""

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "status": "success",
                    "message": "User registered successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {
                "status": "error",
                "message": "User registration failed",
                "errors": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class UserLoginView(APIView):
    """Handle user login requests."""

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        serializer = UserLoginSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            return Response(
                {
                    "status": "error",
                    "message": "User login failed",
                    "errors": {"detail": e.detail},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except AuthenticationFailed as e:
            return Response(
                {
                    "status": "error",
                    "message": "User login failed",
                    "errors": {"detail": e.detail},
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        return Response(
            {
                "status": "success",
                "message": "User logged in successfully",
                "data": serializer.validated_data,
            },
            status=status.HTTP_200_OK,
        )
