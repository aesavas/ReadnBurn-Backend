from typing import cast

from accounts.models import User
from analytics.services import AnalyticsService
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView


class DashboardStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        user = cast(User, request.user)
        stats = AnalyticsService.get_user_stats(user)
        return Response(
            {
                "status": "success",
                "message": "Dashboard stats retrieved successfully",
                "data": stats,
            },
            status=status.HTTP_200_OK,
        )
