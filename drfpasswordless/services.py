from django.utils.module_loading import import_string
from drfpasswordless.settings import api_settings
from drfpasswordless.utils import (
    create_callback_token_for_user,
    is_test_mobile_user,
)


class TokenService(object):
    @staticmethod
    def send_token(user, alias_type, token_type, **message_payload):
        token = create_callback_token_for_user(user, alias_type, token_type)
        send_action = None

        # Skip sending for demo users (by PK)
        if user.pk in api_settings.PASSWORDLESS_DEMO_USERS.keys():
            return True

        # Skip sending for test mobile users (non-production only)
        if is_test_mobile_user(user):
            return True

        if alias_type == 'email':
            send_action = import_string(api_settings.PASSWORDLESS_EMAIL_CALLBACK)
        elif alias_type == 'mobile':
            send_action = import_string(api_settings.PASSWORDLESS_SMS_CALLBACK)
        # Send to alias
        success = send_action(user, token, **message_payload)
        return success
