from django.urls import path

from .views import SecretCreateView

urlpatterns = [
    path("create/", SecretCreateView.as_view(), name="secret_create"),
]
