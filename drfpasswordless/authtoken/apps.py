from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class AuthTokenConfig(AppConfig):
    name = 'drfpasswordless.authtoken'
    verbose_name = _("Auth Token")
