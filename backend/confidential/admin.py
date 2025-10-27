from django.contrib import admin

from .models import Secret
from .models import SecretViewLog

admin.site.register(Secret)
admin.site.register(SecretViewLog)
