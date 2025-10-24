from accounts.views import UserLoginView
from accounts.views import UserLogoutView
from accounts.views import UserRegistrationView
from accounts.views import UserTokenRefreshView
from django.urls import path

urlpatterns = [
    path("auth/register/", UserRegistrationView.as_view(), name="user_register"),
    path("auth/login/", UserLoginView.as_view(), name="user_login"),
    path("auth/refresh/", UserTokenRefreshView.as_view(), name="user_token_refresh"),
    path("auth/logout/", UserLogoutView.as_view(), name="user_logout"),
]
