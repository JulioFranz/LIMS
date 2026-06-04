"""
LIMS — Views / Controllers da API REST (views.py)

Este módulo implementa os endpoints da API de autenticação e LGPD.
Cada view documenta as proteções de segurança aplicadas.

Proteções implementadas neste arquivo:
  - Rate Limiting por escopo (AuthThrottle 3/min, PasswordResetThrottle 5/hora)
  - Extração segura de IP do cliente (X-Forwarded-For com proxy reverso)
  - Autenticação JWT stateless com permissões por endpoint
  - Fluxo de login em duas etapas (credenciais + 2FA obrigatório)
  - Registro de auditoria em tentativas de login falhadas (com IP e User-Agent)
  - Logout com blacklist do refresh token (impede reutilização)
  - Endpoint LGPD /me/ (Art. 9º, 18 e 8º §5º) — acesso, portabilidade e exclusão
  - Mensagem genérica no reset de senha (anti-enumeração de e-mail)
"""

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.throttling import AnonRateThrottle
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    RegisterSerializer, LoginSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    TOTPPendingSerializer, TOTPCodeSerializer, DisableTOTPSerializer,
)
from .services import (
    register_user,
    confirm_email_verification,
    request_password_reset, confirm_password_reset,
    create_totp_pending_token, create_totp_setup_pending_token,
    get_totp_setup_uri, confirm_totp_setup_and_get_jwt,
    validate_totp_login_and_get_jwt, disable_totp,
    _audit, _hash_email,
)
from .selectors import get_profile
from .models import AuditLog
from .crypto import decrypt_value
import pyotp


# =============================================================================
# SEGURANÇA: Throttle Classes — Rate Limiting por escopo
# (OWASP API4:2023 - Unrestricted Resource Consumption)
#
# AuthThrottle (scope='auth'): limita endpoints de autenticação a 3 req/min.
#   Protege contra brute-force de senhas e códigos TOTP. Valor baixo intencional
#   porque o Argon2 consome muita CPU/RAM por hash, tornando DoS assimétrico viável.
#
# PasswordResetThrottle (scope='password_reset'): limita a 5 req/hora.
#   Impede enumeração de e-mails e spam de e-mails de reset.
# =============================================================================

class AuthThrottle(AnonRateThrottle):
    scope = 'auth'


class PasswordResetThrottle(AnonRateThrottle):
    scope = 'password_reset'


def _client_ip(request) -> str:
    """
    Extrai o IP real do cliente, considerando proxy reverso.

    Proteção: quando atrás de proxy (Nginx, Cloudflare, Render), o IP real
    vem no header X-Forwarded-For. O primeiro IP da lista é o do cliente
    original. Usado na trilha de auditoria para rastreabilidade de incidentes.
    """
    xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


class RegisterView(APIView):
    """
    POST /api/users/register/ — Cadastro de novo usuário.

    Proteções:
      - Rate Limiting: AuthThrottle (3 req/min) impede spam de cadastros.
      - Validação de entrada via RegisterSerializer (email, senha, consentimento).
      - Anti-enumeração: register_user() retorna resposta idêntica se e-mail já existe.
      - Consentimento LGPD obrigatório (validado no serializer).
    """
    permission_classes = [AllowAny]
    throttle_classes = [AuthThrottle]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        register_user(**serializer.validated_data)
        return Response({"detail": "Usuário criado. Verifique seu e-mail."}, status=status.HTTP_201_CREATED)


class VerifyEmailView(APIView):
    """
    POST /api/users/verify-email/ — Verificação de e-mail via código.

    Proteção: o código é comparado por hash SHA-256 (o segredo nunca é
    armazenado em texto plano no banco). Token de uso único com expiração.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get("token")
        if not token:
            return Response({"detail": "Token é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            confirm_email_verification(token)
            return Response({"detail": "E-mail verificado com sucesso! Agora você pode fazer login."})
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """
    POST /api/users/login/ — Login (primeira etapa).

    Proteções:
      - Rate Limiting: AuthThrottle (3 req/min) contra brute-force.
      - NÃO emite JWT nesta etapa — o login é SEMPRE em duas etapas:
        1) Credenciais (email + senha) → retorna pending_token.
        2) Código TOTP (Verify2FAView ou Setup2FAView) → emite JWT.
        Isso garante que o 2FA é OBRIGATÓRIO para todos os usuários.
      - Tentativas falhadas são registradas na trilha de auditoria com IP e User-Agent.
      - Busca case-insensitive por e-mail (email__iexact) para UX.
      - Mensagem genérica "Credenciais inválidas" (não revela se é e-mail ou senha errada).
    """
    permission_classes = [AllowAny]
    throttle_classes = [AuthThrottle]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        try:
            user_obj = User.objects.get(email__iexact=email.strip())
            user = authenticate(username=user_obj.username, password=password)
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            user = None

        if not user:
            # SEGURANÇA: Registra login falhado na trilha de auditoria (com IP e User-Agent)
            _audit(
                event="login_failed",
                result="invalid_credentials",
                email_hash=_hash_email(email),
                client_ip=_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
            )
            return Response({"detail": "Credenciais inválidas."}, status=status.HTTP_401_UNAUTHORIZED)

        profile = get_profile(user)

        # SEGURANÇA: Se 2FA já está configurado, exige código TOTP antes de emitir JWT
        if profile and profile.totp_enabled:
            pending_token = create_totp_pending_token(user)
            return Response({"totp_required": True, "pending_token": pending_token})

        # SEGURANÇA: Se 2FA ainda não foi configurado, força o setup antes de emitir JWT
        pending_token = create_totp_setup_pending_token(user)
        return Response({"setup_required": True, "pending_token": pending_token})


class Verify2FAView(APIView):
    """
    POST /api/users/login/verify/ — Verificação do código TOTP (segunda etapa do login).

    Proteções:
      - Rate Limiting: AuthThrottle (3 req/min) contra brute-force no código TOTP.
      - Código validado com valid_window=2 (tolerância de ±60s para relógio).
      - Token pendente de uso único com expiração de 10 minutos.
      - Falhas registradas na trilha de auditoria (totp_login_failed).
    """
    permission_classes = [AllowAny]
    throttle_classes = [AuthThrottle]

    def post(self, request):
        serializer = TOTPCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            tokens = validate_totp_login_and_get_jwt(
                serializer.validated_data['pending_token'],
                serializer.validated_data['totp_code'],
                client_ip=_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
            )
            return Response(tokens)
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class Setup2FAView(APIView):
    """
    POST /api/users/2fa/setup/ — Geração do QR Code para configuração do TOTP.

    Proteções:
      - Rate Limiting: AuthThrottle (3 req/min) contra abuso.
      - Segredo TOTP gerado com CSPRNG (pyotp.random_base32).
      - Segredo cifrado com Fernet AES antes do armazenamento.
      - Token pendente com expiração de 10 minutos.
    """
    permission_classes = [AllowAny]
    throttle_classes = [AuthThrottle]

    def post(self, request):
        serializer = TOTPPendingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            result = get_totp_setup_uri(serializer.validated_data['pending_token'])
            return Response(result)
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ConfirmSetup2FAView(APIView):
    """
    POST /api/users/2fa/setup/confirm/ — Confirmação do setup do 2FA com código TOTP.

    Proteções:
      - Rate Limiting: AuthThrottle (3 req/min) contra brute-force no código.
      - Valida código TOTP antes de ativar o 2FA permanentemente.
      - Emite JWT somente após confirmação bem-sucedida.
    """
    permission_classes = [AllowAny]
    throttle_classes = [AuthThrottle]

    def post(self, request):
        serializer = TOTPCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            tokens = confirm_totp_setup_and_get_jwt(
                serializer.validated_data['pending_token'],
                serializer.validated_data['totp_code'],
            )
            return Response(tokens)
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class Disable2FAView(APIView):
    """
    POST /api/users/2fa/disable/ — Desativação do 2FA.

    Proteções:
      - IsAuthenticated: requer JWT válido (não acessível por anônimos).
      - Exige código TOTP válido para desativar (impede desativação por terceiro
        que roubou o token JWT mas não tem acesso ao app autenticador).
      - valid_window=1 (tolerância menor que no login — operação sensível).
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DisableTOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        profile = get_profile(request.user)
        if not profile or not profile.totp_enabled:
            return Response({"detail": "2FA não está ativado."}, status=status.HTTP_400_BAD_REQUEST)

        # SEGURANÇA: Decifra segredo TOTP e valida código antes de desativar
        secret = decrypt_value(profile.totp_secret)
        if not pyotp.TOTP(secret).verify(serializer.validated_data['totp_code'].strip(), valid_window=1):
            return Response({"detail": "Código inválido."}, status=status.HTTP_400_BAD_REQUEST)

        disable_totp(request.user)
        return Response({"detail": "2FA desativado com sucesso."})


class LogoutView(APIView):
    """
    POST /api/users/logout/ — Logout com invalidação do refresh token.

    Proteções:
      - IsAuthenticated: requer JWT válido.
      - Blacklist do refresh token: o token é adicionado à tabela de tokens
        banidos (rest_framework_simplejwt.token_blacklist), impedindo que seja
        usado para gerar novos access tokens após o logout.
      - O access token existente expira naturalmente em 15 minutos (SIMPLE_JWT).
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            # SEGURANÇA: Adiciona refresh token à blacklist — impede reutilização pós-logout
            token.blacklist()
            return Response({"detail": "Logout realizado com sucesso."}, status=status.HTTP_205_RESET_CONTENT)
        except (TokenError, Exception):
            return Response(status=status.HTTP_400_BAD_REQUEST)


# =============================================================================
# Recuperação de senha
# =============================================================================

class PasswordResetRequestView(APIView):
    """
    POST /api/users/password-reset/ — Solicita recuperação de senha.

    Proteções:
      - Rate Limiting: PasswordResetThrottle (5 req/hora) — impede enumeração
        de e-mails e spam de e-mails de reset.
      - Resposta GENÉRICA fixa (GENERIC_RESPONSE): retorna sempre a mesma
        mensagem, independentemente de o e-mail existir ou não. Isso impede que
        atacantes descubram quais e-mails estão cadastrados (anti-enumeração).
    """
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]

    GENERIC_RESPONSE = {
        "detail": (
            "Se existir uma conta com esse e-mail, enviaremos instruções "
            "para redefinição de senha em instantes."
        ),
    }

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        request_password_reset(
            email=serializer.validated_data['email'],
            request=request,
            client_ip=_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )
        return Response(self.GENERIC_RESPONSE, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    """
    POST /api/users/password-reset/confirm/ — Confirma reset de senha com token.

    Proteções:
      - Rate Limiting: PasswordResetThrottle (5 req/hora).
      - Token de uso único com expiração de 30 minutos.
      - Segredo comparado por hash SHA-256 (nunca em texto plano).
      - Validação da nova senha com 5 validadores.
      - Invalidação de todas as sessões JWT ativas.
    """
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            confirm_password_reset(
                token_id=serializer.validated_data['uid'],
                secret=serializer.validated_data['token'],
                new_password=serializer.validated_data['new_password'],
                client_ip=_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
            )
            return Response(
                {"detail": "Senha redefinida com sucesso."},
                status=status.HTTP_200_OK,
            )
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# =============================================================================
# LGPD: Direitos do Titular (Art. 9º, 18 e 8º §5º)
# =============================================================================

class MeView(APIView):
    """
    GET  /api/users/me/ — Acesso aos dados pessoais do titular (LGPD Art. 18, II).
    DELETE /api/users/me/ — Exclusão de conta e revogação de consentimento (LGPD Art. 8º §5º).

    Proteções e conformidade LGPD:
      - IsAuthenticated: apenas o próprio titular acessa seus dados.
      - GET: retorna TODOS os dados pessoais coletados com finalidade e base legal
        de cada campo, conforme Art. 9º da LGPD (transparência). Inclui histórico
        de auditoria com IPs e User-Agents dos últimos 50 eventos.
      - DELETE: exclui a conta do titular e revoga o consentimento, conforme
        Art. 8º §5º e Art. 18, VI da LGPD (direito à eliminação). Registra o
        evento na trilha de auditoria ANTES da exclusão para rastreabilidade.
      - O frontend (MyData.tsx) permite exportação dos dados em JSON, atendendo
        ao Art. 18, II (portabilidade dos dados).
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        profile = get_profile(user)

        audit_events = (
            AuditLog.objects
            .filter(user=user)
            .order_by('-created_at')
            .values('created_at', 'event', 'result', 'ip', 'user_agent')[:50]
        )

        audit_list = [
            {
                "data": e['created_at'].isoformat(),
                "evento": e['event'],
                "resultado": e['result'],
                "ip": e['ip'] or "—",
                "user_agent": e['user_agent'] or "—",
            }
            for e in audit_events
        ]

        # LGPD Art. 9º — Transparência: cada dado pessoal é retornado com
        # sua finalidade e base legal explícita para o titular.
        dados_pessoais = [
            {
                "dado": "Nome de usuário",
                "valor": user.username,
                "finalidade": "Identificação única no sistema",
                "base_legal": "Execução de contrato – Art. 7º, V, LGPD",
            },
            {
                "dado": "Endereço de e-mail",
                "valor": user.email,
                "finalidade": "Comunicação, verificação de conta e recuperação de senha",
                "base_legal": "Execução de contrato – Art. 7º, V, LGPD",
            },
            {
                "dado": "Senha",
                "valor": "Armazenada apenas como hash Argon2 (não recuperável)",
                "finalidade": "Autenticação segura",
                "base_legal": "Execução de contrato – Art. 7º, V, LGPD",
            },
            {
                "dado": "Data de cadastro",
                "valor": user.date_joined.isoformat(),
                "finalidade": "Registro histórico e rastreabilidade da conta",
                "base_legal": "Legítimo interesse – Art. 7º, IX, LGPD",
            },
            {
                "dado": "Último acesso",
                "valor": user.last_login.isoformat() if user.last_login else "Nunca registrado",
                "finalidade": "Controle de sessão e detecção de acessos indevidos",
                "base_legal": "Legítimo interesse – Art. 7º, IX, LGPD",
            },
            {
                "dado": "E-mail verificado",
                "valor": "Sim" if (profile and profile.is_verified) else "Não",
                "finalidade": "Confirmar titularidade do endereço de e-mail",
                "base_legal": "Execução de contrato – Art. 7º, V, LGPD",
            },
            {
                "dado": "Autenticação de dois fatores (2FA)",
                "valor": "Ativa" if (profile and profile.totp_enabled) else "Inativa",
                "finalidade": "Proteção adicional da conta contra acesso não autorizado",
                "base_legal": "Legítimo interesse – Art. 7º, IX, LGPD",
            },
            {
                "dado": "Endereços IP (logs de auditoria)",
                "valor": "Registrados em eventos de segurança (ver histórico abaixo)",
                "finalidade": "Auditoria de segurança e rastreabilidade de incidentes",
                "base_legal": "Legítimo interesse – Art. 7º, IX, LGPD",
            },
            {
                "dado": "Agente de usuário (User-Agent)",
                "valor": "Registrado em eventos de segurança (ver histórico abaixo)",
                "finalidade": "Identificação do dispositivo em logs de auditoria",
                "base_legal": "Legítimo interesse – Art. 7º, IX, LGPD",
            },
        ]

        return Response({
            "titular": user.username,
            "dados_pessoais": dados_pessoais,
            "historico_auditoria": audit_list,
        })

    def delete(self, request):
        """
        LGPD Art. 8º §5º e Art. 18, VI — Revogação de consentimento e eliminação de dados.

        Proteção: o evento é registrado na trilha de auditoria ANTES da exclusão
        do usuário, garantindo rastreabilidade forense mesmo após a remoção.
        O AuditLog usa SET_NULL, então o registro persiste sem referência ao titular.
        """
        user = request.user
        _audit(
            event='account_deleted',
            result='success',
            user=user,
            email_hash=_hash_email(user.email),
            client_ip=_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )
        user.delete()
        return Response(
            {"detail": "Conta excluída e consentimento revogado com sucesso."},
            status=status.HTTP_204_NO_CONTENT
        )
