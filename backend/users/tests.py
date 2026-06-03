from django.test import TestCase
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password, get_hasher
from django.utils import timezone
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from datetime import timedelta
from unittest.mock import patch
import pyotp

from users.models import UserProfile, ProfileChangeToken
from users.crypto import encrypt_value


THROTTLE_MOCK = patch(
    "users.views.AuthThrottle.allow_request",
    return_value=True,
)


def _criar_usuario_totp(username, email, password):
    """Cria usuário com TOTP já configurado, retorna (user, totp_secret)."""
    totp_secret = pyotp.random_base32()
    user = User.objects.create_user(username=username, email=email, password=password)
    UserProfile.objects.create(
        user=user,
        is_verified=True,
        totp_enabled=True,
        totp_secret=encrypt_value(totp_secret),
    )
    return user, totp_secret


def login_e_obter_jwt(client, email, password):
    """Faz login completo (login + TOTP mockado) e retorna os JWTs."""
    resp = client.post(reverse("login"), {"email": email, "password": password})
    pending_token = resp.data["pending_token"]

    with patch("users.services.pyotp.TOTP") as mock_totp_cls:
        mock_totp_cls.return_value.verify.return_value = True
        resp = client.post(reverse("verify-2fa"), {
            "pending_token": pending_token,
            "totp_code": "123456",
        })
    return resp.data


# 1.1  Hash
class HashCriptograficoTest(TestCase):

    def test_senha_armazenada_com_argon2(self):
        user = User.objects.create_user(
            username="hashtest", email="hash@test.com", password="SenhaForte123!"
        )
        self.assertTrue(
            user.password.startswith("argon2"),
            f"Esperado hash Argon2, mas obteve: {user.password[:30]}..."
        )

    def test_senha_nao_armazenada_em_texto_plano(self):
        user = User.objects.create_user(
            username="plaintest", email="plain@test.com", password="SenhaForte123!"
        )
        self.assertNotEqual(user.password, "SenhaForte123!")
        self.assertNotIn("SenhaForte123!", user.password)


# 1.2 — parâmetros configurados
class ParametrosCustoHashTest(TestCase):

    def test_argon2_e_hasher_padrao(self):
        hasher = get_hasher("default")
        self.assertEqual(hasher.algorithm, "argon2")

    def test_parametros_custo_definidos(self):
        hasher = get_hasher("default")
        self.assertGreaterEqual(hasher.time_cost, 2, "time_cost deve ser >= 2")
        self.assertGreaterEqual(hasher.memory_cost, 19456, "memory_cost deve ser >= 19MB")
        self.assertGreaterEqual(hasher.parallelism, 1, "parallelism deve ser >= 1")


# 1.3  Salt unico por user
class SaltUnicoTest(TestCase):

    def test_salt_unico_para_usuarios_com_mesma_senha(self):
        user1 = User.objects.create_user(
            username="salt1", email="s1@test.com", password="MesmaSenha123!"
        )
        user2 = User.objects.create_user(
            username="salt2", email="s2@test.com", password="MesmaSenha123!"
        )
        self.assertNotEqual(
            user1.password, user2.password,
            "Dois usuários com a mesma senha devem ter hashes diferentes (salt único)"
        )


# 1.4  hash + salt
class ArmazenamentoHashSaltTest(TestCase):

    def test_formato_hash_argon2_contem_salt(self):
        user = User.objects.create_user(
            username="formattest", email="fmt@test.com", password="SenhaForte123!"
        )
        partes = user.password.split("$")
        self.assertGreaterEqual(
            len(partes), 4,
            "Hash Argon2 deve conter: algoritmo$params$salt$hash"
        )

    def test_verificacao_de_senha_funciona(self):
        user = User.objects.create_user(
            username="verifytest", email="ver@test.com", password="SenhaForte123!"
        )
        self.assertTrue(check_password("SenhaForte123!", user.password))
        self.assertFalse(check_password("SenhaErrada!", user.password))


# 1.5 — TOTP (Google Authenticator)
class TwoFactorImplementadoTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.user, self.totp_secret = _criar_usuario_totp(
            "user2fa", "2fa@test.com", "SenhaForte123!"
        )

    @THROTTLE_MOCK
    def test_login_requer_totp(self, mock_throttle):
        response = self.client.post(reverse("login"), {
            "email": "2fa@test.com",
            "password": "SenhaForte123!",
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get("totp_required"))

    @THROTTLE_MOCK
    def test_login_cria_token_totp_pendente(self, mock_throttle):
        self.client.post(reverse("login"), {
            "email": "2fa@test.com",
            "password": "SenhaForte123!",
        })
        token_exists = ProfileChangeToken.objects.filter(
            user=self.user, change_type="totp_pending"
        ).exists()
        self.assertTrue(token_exists, "Token TOTP pendente deve ser criado no banco")

    @THROTTLE_MOCK
    def test_login_nao_retorna_jwt_direto(self, mock_throttle):
        response = self.client.post(reverse("login"), {
            "email": "2fa@test.com",
            "password": "SenhaForte123!",
        })
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)


# 1.6 — Validação do TOTP
class Validacao2FATest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.user, self.totp_secret = _criar_usuario_totp(
            "val2fa", "val@test.com", "SenhaForte123!"
        )

    @THROTTLE_MOCK
    def test_totp_valido_retorna_jwt(self, mock_throttle):
        resp_login = self.client.post(reverse("login"), {
            "email": "val@test.com",
            "password": "SenhaForte123!",
        })
        pending_token = resp_login.data["pending_token"]

        with patch("users.services.pyotp.TOTP") as mock_totp_cls:
            mock_totp_cls.return_value.verify.return_value = True
            response = self.client.post(reverse("verify-2fa"), {
                "pending_token": pending_token,
                "totp_code": "123456",
            })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_totp_invalido_rejeitado(self):
        from users.services import create_totp_pending_token
        pending_token = create_totp_pending_token(self.user)

        with patch("users.services.pyotp.TOTP") as mock_totp_cls:
            mock_totp_cls.return_value.verify.return_value = False
            response = self.client.post(reverse("verify-2fa"), {
                "pending_token": pending_token,
                "totp_code": "000000",
            })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_pending_token_inexistente_rejeitado(self):
        response = self.client.post(reverse("verify-2fa"), {
            "pending_token": "00000000-0000-0000-0000-000000000000",
            "totp_code": "123456",
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


# 1.9 — sessão com tempo de expiração
class SessaoExpiracaoTest(TestCase):

    def test_access_token_expira_em_15_minutos(self):
        from django.conf import settings
        lifetime = settings.SIMPLE_JWT.get("ACCESS_TOKEN_LIFETIME")
        self.assertEqual(lifetime, timedelta(minutes=15))

    def test_refresh_token_expira_em_1_dia(self):
        from django.conf import settings
        lifetime = settings.SIMPLE_JWT.get("REFRESH_TOKEN_LIFETIME")
        self.assertEqual(lifetime, timedelta(days=1))


# 1.10 — Invalidação no logout
class LogoutInvalidacaoTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.user, _ = _criar_usuario_totp(
            "logoutuser", "logout@test.com", "SenhaForte123!"
        )

    @THROTTLE_MOCK
    def test_logout_invalida_refresh_token(self, mock_throttle):
        tokens = login_e_obter_jwt(self.client, "logout@test.com", "SenhaForte123!")

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        logout_response = self.client.post(reverse("logout"), {
            "refresh": tokens["refresh"]
        })
        self.assertEqual(logout_response.status_code, status.HTTP_205_RESET_CONTENT)

    @THROTTLE_MOCK
    def test_refresh_token_nao_funciona_apos_logout(self, mock_throttle):
        tokens = login_e_obter_jwt(self.client, "logout@test.com", "SenhaForte123!")

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        self.client.post(reverse("logout"), {"refresh": tokens["refresh"]})

        from rest_framework_simplejwt.tokens import RefreshToken
        with self.assertRaises(Exception):
            token = RefreshToken(tokens["refresh"])
            token.blacklist()


# 1.11 rate limit
class ForcaBrutaProtecaoTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        User.objects.create_user(
            username="bruteuser", email="brute@test.com", password="SenhaForte123!"
        )

    def test_rate_limit_bloqueia_apos_3_tentativas(self):
        url = reverse("login")
        dados_errados = {"email": "brute@test.com", "password": "SenhaErrada!"}

        for _ in range(3):
            self.client.post(url, dados_errados)

        response = self.client.post(url, dados_errados)
        self.assertEqual(
            response.status_code,
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Após 3 tentativas, o sistema deve bloquear com HTTP 429"
        )


# Token TOTP — Expiração e invalidação
class Token2FAExpiracaoTest(TestCase):

    def setUp(self):
        self.user, self.totp_secret = _criar_usuario_totp(
            "tokenexp", "exp@test.com", "SenhaForte123!"
        )

    def test_token_totp_invalido_apos_uso(self):
        from users.services import create_totp_pending_token, validate_totp_login_and_get_jwt

        pending_token = create_totp_pending_token(self.user)

        with patch("users.services.pyotp.TOTP") as mock_totp_cls:
            mock_totp_cls.return_value.verify.return_value = True
            validate_totp_login_and_get_jwt(pending_token, "123456")

        with patch("users.services.pyotp.TOTP") as mock_totp_cls:
            mock_totp_cls.return_value.verify.return_value = True
            with self.assertRaises(ValueError):
                validate_totp_login_and_get_jwt(pending_token, "123456")

    def test_token_totp_expirado_e_rejeitado(self):
        from users.services import create_totp_pending_token, validate_totp_login_and_get_jwt

        pending_token = create_totp_pending_token(self.user)
        token_obj = ProfileChangeToken.objects.get(
            user=self.user, change_type="totp_pending"
        )
        token_obj.created_at = timezone.now() - timedelta(minutes=20)
        token_obj.save(update_fields=["created_at"])

        with patch("users.services.pyotp.TOTP") as mock_totp_cls:
            mock_totp_cls.return_value.verify.return_value = True
            with self.assertRaises(ValueError, msg="Token expirado deve ser rejeitado"):
                validate_totp_login_and_get_jwt(pending_token, "123456")


class RegistroUsuarioTest(TestCase):

    def setUp(self):
        self.client = APIClient()

    @patch("users.services._send_email")
    def test_registro_cria_usuario_e_perfil(self, mock_email):
        response = self.client.post(reverse("register"), {
            "username": "novousuario",
            "email": "novo@test.com",
            "password": "SenhaForte123!",
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username="novousuario").exists())
        user = User.objects.get(username="novousuario")
        self.assertTrue(hasattr(user, "profile"))
        self.assertFalse(user.profile.is_verified)

    def test_registro_rejeita_senha_curta(self):
        response = self.client.post(reverse("register"), {
            "username": "curto",
            "email": "curto@test.com",
            "password": "123",
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @THROTTLE_MOCK
    def test_credenciais_invalidas_retorna_401(self, mock_throttle):
        response = self.client.post(reverse("login"), {
            "email": "naoexiste@test.com",
            "password": "SenhaErrada!",
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


# 3.4 — Cifragem AES de PII em repouso
class CifragemAESNewValueTest(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="aestest",
            email="aes@test.com",
            password="SenhaForte123!",
        )

    def test_new_value_armazenado_cifrado(self):
        from users.services import _create_token

        novo_email = "novo.endereco@test.com"
        _create_token(self.user, "email_new", new_value=novo_email)

        token_obj = ProfileChangeToken.objects.get(
            user=self.user, change_type="email_new"
        )

        self.assertNotIn(novo_email, token_obj.new_value)
        self.assertNotIn("novo.endereco", token_obj.new_value)
        self.assertTrue(
            token_obj.new_value.startswith("gAAAAA"),
            f"Esperado token Fernet, obteve: {token_obj.new_value[:30]}..."
        )

    def test_new_value_decifravel_com_chave_correta(self):
        from users.services import _create_token, get_token_new_value

        novo_email = "outro@test.com"
        _create_token(self.user, "email_new", new_value=novo_email)

        token_obj = ProfileChangeToken.objects.get(
            user=self.user, change_type="email_new"
        )

        decifrado = get_token_new_value(token_obj)
        self.assertEqual(decifrado, novo_email)

    def test_cifragem_nao_deterministica(self):
        valor = "mesmo@email.com"
        ct1 = encrypt_value(valor)
        ct2 = encrypt_value(valor)
        self.assertNotEqual(ct1, ct2)

    def test_new_value_vazio_nao_quebra(self):
        from users.services import _create_token

        _create_token(self.user, "2fa_login")

        token_obj = ProfileChangeToken.objects.get(
            user=self.user, change_type="2fa_login"
        )
        self.assertEqual(token_obj.new_value, "")