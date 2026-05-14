import re
from django.test import TestCase
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password, get_hasher
from django.utils import timezone
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from datetime import timedelta
from unittest.mock import patch

from users.models import UserProfile, ProfileChangeToken
from users.services import generate_2fa_token, validate_2fa_and_get_jwt


THROTTLE_MOCK = patch(
    "users.views.AuthThrottle.allow_request",
    return_value=True,
)


def _extrair_segredo_do_email(mock_email):
    """
    Como o token agora é hasheado no banco, o segredo só existe no e-mail
    enviado ao usuário. Captura o UUID do parâmetro `message` do _send_email.
    """
    call_args = mock_email.call_args
    message = call_args.kwargs.get("message") or call_args.args[1]
    match = re.search(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        message,
    )
    return match.group(0) if match else None


def login_e_obter_jwt(client, username, password):
    """Faz login completo (login + 2FA) e retorna os JWTs."""
    with patch("users.services._send_email") as mock_email:
        client.post(reverse("login"), {
            "username": username,
            "password": password,
        })
        secret = _extrair_segredo_do_email(mock_email)

    response = client.post(reverse("verify-2fa"), {
        "token": secret,
    })
    return response.data


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



# 1.2 — paramtros configurados
class ParametrosCustoHashTest(TestCase):

    def test_argon2_e_hasher_padrao(self):
        hasher = get_hasher("default")
        self.assertEqual(hasher.algorithm, "argon2")

    def test_parametros_custo_definidos(self):
        hasher = get_hasher("default")
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


# 1.5 — 2FA
class TwoFactorImplementadoTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="user2fa", email="2fa@test.com", password="SenhaForte123!"
        )
        UserProfile.objects.create(user=self.user, is_verified=True)

    @THROTTLE_MOCK
    @patch("users.services._send_email")
    def test_login_gera_token_2fa(self, mock_email, mock_throttle):
        response = self.client.post(reverse("login"), {
            "username": "user2fa",
            "password": "SenhaForte123!"
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get("2fa_required"))

        #verifica se o token foi criado no banco
        token_exists = ProfileChangeToken.objects.filter(
            user=self.user, change_type="2fa_login"
        ).exists()
        self.assertTrue(token_exists, "Token 2FA deve ser criado no banco")

    @THROTTLE_MOCK
    @patch("users.services._send_email")
    def test_login_envia_email_2fa(self, mock_email, mock_throttle):
        self.client.post(reverse("login"), {
            "username": "user2fa",
            "password": "SenhaForte123!"
        })
        mock_email.assert_called_once()



# 1.6 — Validação do 2FA, autenticação primária
class Validacao2FATest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="val2fa", email="val@test.com", password="SenhaForte123!"
        )
        UserProfile.objects.create(user=self.user, is_verified=True)

    @THROTTLE_MOCK
    @patch("users.services._send_email")
    def test_login_nao_retorna_jwt_sem_2fa(self, mock_email, mock_throttle):
        response = self.client.post(reverse("login"), {
            "username": "val2fa",
            "password": "SenhaForte123!"
        })
        #NÃO deve retornar token
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)

    @THROTTLE_MOCK
    @patch("users.services._send_email")
    def test_2fa_valido_retorna_jwt(self, mock_email, mock_throttle):
        # login (envia o segredo por e-mail)
        self.client.post(reverse("login"), {
            "username": "val2fa",
            "password": "SenhaForte123!"
        })

        # captura o segredo do e-mail (não está mais em claro no banco)
        secret = _extrair_segredo_do_email(mock_email)
        self.assertIsNotNone(secret, "Segredo deve estar no e-mail enviado")

        # verifica o 2FA
        response = self.client.post(reverse("verify-2fa"), {
            "token": secret
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_2fa_invalido_rejeitado(self):
        response = self.client.post(reverse("verify-2fa"), {
            "token": "00000000-0000-0000-0000-000000000000"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



# 1.9 — sessao com tempo de expiracao
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
        self.user = User.objects.create_user(
            username="logoutuser", email="logout@test.com", password="SenhaForte123!"
        )
        UserProfile.objects.create(user=self.user, is_verified=True)

    @THROTTLE_MOCK
    @patch("users.services._send_email")
    def test_logout_invalida_refresh_token(self, mock_email, mock_throttle):
        tokens = login_e_obter_jwt(self.client, "logoutuser", "SenhaForte123!")

        # Faz logout
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        logout_response = self.client.post(reverse("logout"), {
            "refresh": tokens["refresh"]
        })
        self.assertEqual(logout_response.status_code, status.HTTP_205_RESET_CONTENT)

    @THROTTLE_MOCK
    @patch("users.services._send_email")
    def test_refresh_token_nao_funciona_apos_logout(self, mock_email, mock_throttle):
        tokens = login_e_obter_jwt(self.client, "logoutuser", "SenhaForte123!")

        # logout
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        self.client.post(reverse("logout"), {"refresh": tokens["refresh"]})

        # tenta usar o refresh token novamente
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
        dados_errados = {"username": "bruteuser", "password": "SenhaErrada!"}

        # Faz 3 tentativas
        for i in range(3):
            self.client.post(url, dados_errados)

        # A 4 tentativa deve ser bloqueada
        response = self.client.post(url, dados_errados)
        self.assertEqual(
            response.status_code,
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Após 3 tentativas, o sistema deve bloquear com HTTP 429"
        )



#token 2FA — Expiração e invalidação
class Token2FAExpiracaoTest(TestCase):


    def setUp(self):
        self.user = User.objects.create_user(
            username="tokenexp", email="exp@test.com", password="SenhaForte123!"
        )
        UserProfile.objects.create(user=self.user, is_verified=True)

    @patch("users.services._send_email")
    def test_token_2fa_invalido_apos_uso(self, mock_email):
        token_str = generate_2fa_token(self.user)
        #  deve funcionar
        validate_2fa_and_get_jwt(token_str)
        #deve falhar pois o token foi delletado
        with self.assertRaises(ValueError):
            validate_2fa_and_get_jwt(token_str)

    @patch("users.services._send_email")
    def test_token_2fa_expirado_e_rejeitado(self, mock_email):
        token_str = generate_2fa_token(self.user)
        token_obj = ProfileChangeToken.objects.get(
            user=self.user, change_type="2fa_login"
        )
        token_obj.created_at = timezone.now() - timedelta(minutes=20)
        token_obj.save(update_fields=["created_at"])

        with self.assertRaises(ValueError, msg="Token expirado deve ser rejeitado"):
            validate_2fa_and_get_jwt(token_str)



class RegistroUsuarioTest(TestCase):

    def setUp(self):
        self.client = APIClient()

    @patch("users.services._send_email")
    def test_registro_cria_usuario_e_perfil(self, mock_email):
        response = self.client.post(reverse("register"), {
            "username": "novousuario",
            "email": "novo@test.com",
            "password": "SenhaForte123!"
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
            "password": "123"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @THROTTLE_MOCK
    def test_credenciais_invalidas_retorna_401(self, mock_throttle):
        response = self.client.post(reverse("login"), {
            "username": "naoexiste",
            "password": "SenhaErrada!"
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


# 3.4 — Cifragem AES de PII em repouso (Seção 3 do checklist)
class CifragemAESNewValueTest(TestCase):
    """
    Requisito 3.4 — Dados sensíveis criptografados em repouso.

    Verifica que o campo new_value de ProfileChangeToken, que armazena
    PII (novo e-mail solicitado pelo usuário), é cifrado com AES-256-GCM
    via Fernet antes de ser persistido no banco.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="aestest",
            email="aes@test.com",
            password="SenhaForte123!",
        )

    def test_new_value_armazenado_cifrado(self):
        """O campo new_value não pode estar em texto claro no banco."""
        from users.services import _create_token

        novo_email = "novo.endereco@test.com"
        _create_token(self.user, "email_new", new_value=novo_email)

        token_obj = ProfileChangeToken.objects.get(
            user=self.user, change_type="email_new"
        )

        # O valor cifrado NÃO pode conter o e-mail em claro
        self.assertNotIn(novo_email, token_obj.new_value)
        self.assertNotIn("novo.endereco", token_obj.new_value)

        # Tokens Fernet começam com "gAAAAA"
        self.assertTrue(
            token_obj.new_value.startswith("gAAAAA"),
            f"Esperado token Fernet, obteve: {token_obj.new_value[:30]}..."
        )

    def test_new_value_decifravel_com_chave_correta(self):
        """O valor cifrado deve voltar ao original ao ser decifrado."""
        from users.services import _create_token, get_token_new_value

        novo_email = "outro@test.com"
        _create_token(self.user, "email_new", new_value=novo_email)

        token_obj = ProfileChangeToken.objects.get(
            user=self.user, change_type="email_new"
        )

        decifrado = get_token_new_value(token_obj)
        self.assertEqual(decifrado, novo_email)

    def test_cifragem_nao_deterministica(self):
        """
        Cifrar o mesmo valor duas vezes deve produzir ciphertexts diferentes
        (Fernet usa IV aleatório por operação).
        """
        from users.crypto import encrypt_value

        valor = "mesmo@email.com"
        ct1 = encrypt_value(valor)
        ct2 = encrypt_value(valor)

        self.assertNotEqual(ct1, ct2)

    def test_new_value_vazio_nao_quebra(self):
        """
        Tokens sem new_value (verify, 2fa_login, password_reset) devem
        continuar funcionando normalmente.
        """
        from users.services import _create_token

        _create_token(self.user, "2fa_login")  # sem new_value

        token_obj = ProfileChangeToken.objects.get(
            user=self.user, change_type="2fa_login"
        )
        self.assertEqual(token_obj.new_value, "")