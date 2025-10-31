from django.urls import path

from .views import SecretCreateView
from .views import SecretRetrieveView

urlpatterns = [
    path("create/", SecretCreateView.as_view(), name="secret_create"),
    path(
        "retrieve/<uuid:secret_id>",
        SecretRetrieveView.as_view(),
        name="secret_retrieve",
    ),
]
