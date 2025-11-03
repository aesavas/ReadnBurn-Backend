from analytics.views import DashboardStatsView
from django.urls import path

urlpatterns = [
    path("stats/", DashboardStatsView.as_view(), name="dashboard_stats"),
]
