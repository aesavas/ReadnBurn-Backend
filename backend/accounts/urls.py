from accounts.views import UserLoginView
from accounts.views import UserRegistrationView
from django.urls import path

urlpatterns = [
    path("auth/register/", UserRegistrationView.as_view(), name="user_register"),
    path("auth/login/", UserLoginView.as_view(), name="user_login"),
]
