from rest_framework import status
from rest_framework.test import APITestCase

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from drfpasswordless.authtoken.models import Token
from drfpasswordless.settings import api_settings, DEFAULTS

User = get_user_model()


class PasswordTestCase(APITestCase):

    def setUp(self):
        api_settings.PASSWORDLESS_AUTH_TYPES = ['MOBILE']
        api_settings.PASSWORDLESS_PASSWORD_AUTH_ENABLED = True

        self.mobile = '+15551234567'
        self.password = 'correct horse battery staple'
        self.user = User.objects.create(mobile=self.mobile)
        self.user.set_password(self.password)
        self.user.save()

        self.login_url = reverse('drfpasswordless:auth_password')
        self.set_url = reverse('drfpasswordless:auth_password_set')

    def tearDown(self):
        api_settings.PASSWORDLESS_AUTH_TYPES = DEFAULTS['PASSWORDLESS_AUTH_TYPES']
        api_settings.PASSWORDLESS_PASSWORD_AUTH_ENABLED = DEFAULTS['PASSWORDLESS_PASSWORD_AUTH_ENABLED']
        api_settings.PASSWORDLESS_PASSWORD_AUTH_BLOCK_SUPERUSERS = \
            DEFAULTS['PASSWORDLESS_PASSWORD_AUTH_BLOCK_SUPERUSERS']


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


class SetPasswordTests(PasswordTestCase):

    def setUp(self):
        super().setUp()
        self.new_user = User.objects.create(mobile='+15550000010')
        self.new_user.set_unusable_password()
        self.new_user.save()

    def test_disabled_returns_404(self):
        api_settings.PASSWORDLESS_PASSWORD_AUTH_ENABLED = False
        self.client.force_authenticate(self.new_user)
        response = self.client.post(self.set_url, {'new_password': 'a new password'})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_requires_authentication(self):
        response = self.client.post(self.set_url, {'new_password': 'a new password'})
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    def test_first_password_needs_no_current_password(self):
        self.client.force_authenticate(self.new_user)
        response = self.client.post(self.set_url, {'new_password': 'a new password'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.client.force_authenticate(None)

        login = self.client.post(self.login_url, {'mobile': self.new_user.mobile, 'password': 'a new password'})
        self.assertEqual(login.status_code, status.HTTP_200_OK)

    def test_empty_password_counts_as_no_password(self):
        user = User.objects.create(mobile='+15550000011', password='')
        self.client.force_authenticate(user)
        response = self.client.post(self.set_url, {'new_password': 'a new password'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_change_requires_correct_current_password(self):
        self.client.force_authenticate(self.user)

        missing = self.client.post(self.set_url, {'new_password': 'a new password'})
        self.assertEqual(missing.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('current_password', missing.data)

        wrong = self.client.post(self.set_url, {'new_password': 'a new password', 'current_password': 'wrong'})
        self.assertEqual(wrong.status_code, status.HTTP_400_BAD_REQUEST)

        right = self.client.post(self.set_url, {'new_password': 'a new password',
                                                'current_password': self.password})
        self.assertEqual(right.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('a new password'))

    @override_settings(AUTH_PASSWORD_VALIDATORS=[
        {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
         'OPTIONS': {'min_length': 10}},
    ])
    def test_password_validators_apply(self):
        self.client.force_authenticate(self.new_user)
        response = self.client.post(self.set_url, {'new_password': 'short'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('new_password', response.data)
