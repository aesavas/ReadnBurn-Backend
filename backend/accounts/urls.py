from accounts.views import UserRegistrationView
from django.urls import path

urlpatterns = [
    path("auth/register/", UserRegistrationView.as_view(), name="user_register"),
]
