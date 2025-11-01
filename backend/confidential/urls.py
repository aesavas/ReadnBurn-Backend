from confidential.views import SecretCreateView
from confidential.views import SecretDeleteView
from confidential.views import SecretDetailView
from confidential.views import SecretRetrieveView
from django.urls import path

urlpatterns = [
    path("create/", SecretCreateView.as_view(), name="secret_create"),
    path(
        "retrieve/<uuid:secret_id>",
        SecretRetrieveView.as_view(),
        name="secret_retrieve",
    ),
    path(
        "detail/<uuid:secret_id>",
        SecretDetailView.as_view(),
        name="secret_detail",
    ),
    path(
        "delete/<uuid:secret_id>",
        SecretDeleteView.as_view(),
        name="secret_delete",
    ),
]
