from typing import cast

from accounts.models import User
from accounts.serializers import UserLoginSerializer
from accounts.serializers import UserProfileSerializer
from accounts.serializers import UserRegistrationSerializer
from rest_framework import permissions
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.exceptions import ValidationError
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken


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
                    "errors": e.args[0],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except AuthenticationFailed as e:
            return Response(
                {
                    "status": "error",
                    "message": "User login failed",
                    "errors": e.args[0],
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


class UserTokenRefreshView(APIView):
    """Handle token refresh requests."""

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        serializer = TokenRefreshSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except (InvalidToken, TokenError) as e:
            return Response(
                {
                    "status": "error",
                    "message": "Token refresh failed",
                    "errors": e.args[0],
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except ValidationError as e:
            return Response(
                {
                    "status": "error",
                    "message": "Token refresh failed",
                    "errors": e.args[0],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "status": "success",
                "message": "Token refreshed successfully",
                "data": serializer.validated_data,
            },
            status=status.HTTP_200_OK,
        )


class UserLogoutView(APIView):
    """Handle user logout requests by blacklisting the refresh token."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {
                        "status": "error",
                        "message": "User logout failed",
                        "errors": "Refresh token is required",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(
                {
                    "status": "success",
                    "message": "User logged out successfully",
                },
                status=status.HTTP_200_OK,
            )
        except (InvalidToken, TokenError) as e:
            return Response(
                {
                    "status": "error",
                    "message": "User logout failed",
                    "errors": e.args[0],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


class UserProfileView(APIView):
    """Retrieve or update the authenticated user's profile."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request) -> Response:
        user = cast(User, request.user)
        serializer = UserProfileSerializer(user)
        return Response(
            {
                "status": "success",
                "message": "User profile retrieved successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    def put(self, request: Request) -> Response:
        user = cast(User, request.user)
        # To allow update without email
        data = request.data.copy()
        if not data.get("email"):
            data["email"] = user.email
        try:
            serializer = UserProfileSerializer(user, data=data)
            serializer.is_valid(raise_exception=True)  # 400 Bad Request
            serializer.save()
        except ValidationError as e:
            return Response(
                {
                    "status": "error",
                    "message": "User profile update failed",
                    "errors": e.args[0],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(
            {
                "status": "success",
                "message": "User profile updated successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    def patch(self, request: Request) -> Response:
        user = cast(User, request.user)
        try:
            serializer = UserProfileSerializer(user, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)  # 400 Bad Request
            serializer.save()
        except ValidationError as e:
            return Response(
                {
                    "status": "error",
                    "message": "User profile update failed",
                    "errors": e.args[0],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(
            {
                "status": "success",
                "message": "User profile updated successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )
