from rest_framework import status
from rest_framework.test import APITestCase

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse
from drfpasswordless.authtoken.models import Token
from drfpasswordless.settings import api_settings, DEFAULTS

User = get_user_model()


class PasswordTestCase(APITestCase):

    def setUp(self):
        cache.clear()
        api_settings.PASSWORDLESS_AUTH_TYPES = ['MOBILE']
        api_settings.PASSWORDLESS_PASSWORD_AUTH_ENABLED = True

        self.mobile = '+15551234567'
        self.password = 'correct horse battery staple'
        self.user = User.objects.create(mobile=self.mobile)
        self.user.set_password(self.password)
        self.user.save()

        self.login_url = reverse('drfpasswordless:auth_password')

    def tearDown(self):
        api_settings.PASSWORDLESS_AUTH_TYPES = DEFAULTS['PASSWORDLESS_AUTH_TYPES']
        api_settings.PASSWORDLESS_PASSWORD_AUTH_ENABLED = DEFAULTS['PASSWORDLESS_PASSWORD_AUTH_ENABLED']
        api_settings.PASSWORDLESS_PASSWORD_AUTH_BLOCK_SUPERUSERS = \
            DEFAULTS['PASSWORDLESS_PASSWORD_AUTH_BLOCK_SUPERUSERS']
        api_settings.PASSWORDLESS_PASSWORD_AUTH_MAX_FAILURES = DEFAULTS['PASSWORDLESS_PASSWORD_AUTH_MAX_FAILURES']
        cache.clear()


class PasswordLoginTests(PasswordTestCase):

    def login(self, **extra):
        data = {'mobile': self.mobile, 'password': self.password}
        data.update(extra)
        return self.client.post(self.login_url, data)

    def test_disabled_returns_404(self):
        api_settings.PASSWORDLESS_PASSWORD_AUTH_ENABLED = False
        self.assertEqual(self.login().status_code, status.HTTP_404_NOT_FOUND)

    def test_success_returns_device_token(self):
        response = self.login(device_id='device-1', device_type=Token.WEB)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        token = Token.objects.get(key=response.data['token'])
        self.assertEqual(token.user, self.user)
        self.assertEqual(token.device_id, 'device-1')
        self.assertEqual(token.device_type, Token.WEB)

    def test_same_device_reuses_token(self):
        first = self.login(device_id='device-1')
        second = self.login(device_id='device-1')
        self.assertEqual(first.data['token'], second.data['token'])

    def test_unknown_device_type_is_dropped(self):
        response = self.login(device_id='device-1', device_type='NOT_A_TYPE')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(Token.objects.get(key=response.data['token']).device_type)

    def test_credential_failures_are_indistinguishable(self):
        wrong_password = self.login(password='wrong')

        unknown_mobile = self.login(mobile='+15559999999')

        no_password = User.objects.create(mobile='+15550000001')
        no_password.set_unusable_password()
        no_password.save()
        unusable = self.login(mobile=no_password.mobile)

        User.objects.create(mobile='+15550000002', password='')
        empty = self.login(mobile='+15550000002', password='')

        inactive = User.objects.create(mobile='+15550000003', is_active=False)
        inactive.set_password(self.password)
        inactive.save()
        inactive_response = self.login(mobile=inactive.mobile)

        responses = [wrong_password, unknown_mobile, unusable, inactive_response]
        for response in responses:
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data, wrong_password.data)
        self.assertEqual(empty.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(Token.objects.exists())

    def test_superuser_blocked_by_default(self):
        self.user.is_superuser = True
        self.user.save()

        response = self.login()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, self.login(password='wrong').data)

        api_settings.PASSWORDLESS_PASSWORD_AUTH_BLOCK_SUPERUSERS = False
        self.assertEqual(self.login().status_code, status.HTTP_200_OK)

    def test_alias_type_must_be_enabled(self):
        self.user.email = 'aaron@example.com'
        self.user.save()

        response = self.client.post(self.login_url, {'email': self.user.email, 'password': self.password})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_requires_exactly_one_alias(self):
        response = self.client.post(self.login_url, {'password': self.password})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        api_settings.PASSWORDLESS_AUTH_TYPES = ['EMAIL', 'MOBILE']
        response = self.login(email='aaron@example.com')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class PasswordLockoutTests(PasswordTestCase):

    def setUp(self):
        super().setUp()
        api_settings.PASSWORDLESS_PASSWORD_AUTH_MAX_FAILURES = 5

    def login(self, mobile=None, password=None):
        return self.client.post(self.login_url, {'mobile': mobile or self.mobile,
                                                 'password': password or self.password})

    def fail_times(self, count, mobile=None):
        for _ in range(count):
            self.assertEqual(self.login(mobile=mobile, password='wrong').status_code,
                             status.HTTP_400_BAD_REQUEST)

    def test_locked_after_max_failures_even_with_right_password(self):
        self.fail_times(5)

        response = self.login()
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertFalse(Token.objects.exists())

    def test_success_resets_the_count(self):
        self.fail_times(4)
        self.assertEqual(self.login().status_code, status.HTTP_200_OK)

        self.fail_times(4)
        self.assertEqual(self.login().status_code, status.HTTP_200_OK)

    def test_lockout_is_per_mobile(self):
        other = User.objects.create(mobile='+15550000020')
        other.set_password(self.password)
        other.save()

        self.fail_times(5)
        self.assertEqual(self.login(mobile=other.mobile).status_code, status.HTTP_200_OK)

    def test_unknown_mobile_locks_the_same_way(self):
        unknown = '+15559999999'
        self.fail_times(5, mobile=unknown)
        self.assertEqual(self.login(mobile=unknown, password='wrong').status_code,
                         status.HTTP_429_TOO_MANY_REQUESTS)

    def test_zero_disables_lockout(self):
        api_settings.PASSWORDLESS_PASSWORD_AUTH_MAX_FAILURES = 0
        self.fail_times(10)
        self.assertEqual(self.login().status_code, status.HTTP_200_OK)
