from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.throttling import AnonRateThrottle
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    RegisterSerializer, LoginSerializer, TwoFactorSerializer,
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
)
from .selectors import get_profile
from .crypto import decrypt_value
from .models import AuditLog
import pyotp


class AuthThrottle(AnonRateThrottle):
    scope = 'auth'


class PasswordResetThrottle(AnonRateThrottle):
    scope = 'password_reset'


def _client_ip(request) -> str:
    xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        register_user(**serializer.validated_data)
        return Response({"detail": "Usuário criado. Verifique seu e-mail."}, status=status.HTTP_201_CREATED)


class VerifyEmailView(APIView):
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
            return Response({"detail": "Credenciais inválidas."}, status=status.HTTP_401_UNAUTHORIZED)

        profile = get_profile(user)

        if profile and profile.totp_enabled:
            pending_token = create_totp_pending_token(user)
            return Response({"totp_required": True, "pending_token": pending_token})

        pending_token = create_totp_setup_pending_token(user)
        return Response({"setup_required": True, "pending_token": pending_token})


class Verify2FAView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = TOTPCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            tokens = validate_totp_login_and_get_jwt(
                serializer.validated_data['pending_token'],
                serializer.validated_data['totp_code'],
            )
            return Response(tokens)
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class Setup2FAView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = TOTPPendingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            result = get_totp_setup_uri(serializer.validated_data['pending_token'])
            return Response(result)
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ConfirmSetup2FAView(APIView):
    permission_classes = [AllowAny]

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
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DisableTOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        profile = get_profile(request.user)
        if not profile or not profile.totp_enabled:
            return Response({"detail": "2FA não está ativado."}, status=status.HTTP_400_BAD_REQUEST)

        secret = decrypt_value(profile.totp_secret)
        if not pyotp.TOTP(secret).verify(serializer.validated_data['totp_code'].strip(), valid_window=1):
            return Response({"detail": "Código inválido."}, status=status.HTTP_400_BAD_REQUEST)

        disable_totp(request.user)
        return Response({"detail": "2FA desativado com sucesso."})


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout realizado com sucesso."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response(status=status.HTTP_400_BAD_REQUEST)


# ---------- Recuperação de senha ----------

class PasswordResetRequestView(APIView):
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


# ---------- LGPD: Dados do titular (Requisitos 4.1 e 4.8) ----------

class MeView(APIView):
    """
    GET /api/users/me/
    Retorna todos os dados pessoais coletados sobre o titular autenticado,
    com a finalidade e a base legal de cada campo — Art. 9º da LGPD.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        profile = get_profile(user)

        # Logs de auditoria associados ao usuário (apenas eventos registrados)
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
        DELETE /api/users/me/
        Revoga o consentimento e exclui a conta do usuário (LGPD 4.6 e 4.10).
        """
        user = request.user
        
        # Opcional: registrar em log de auditoria que a conta foi excluída
        # Mas como o usuário será excluído e user será null, o email_hash pode ser usado.
        email_hash = getattr(user.audit_logs.first(), 'email_hash', '') if user.audit_logs.exists() else ''
        
        # Registra a exclusão da conta em um log genérico sem o user
        AuditLog.objects.create(
            event='account_deleted',
            result='success',
            email_hash=email_hash,
            ip=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        user.delete()
        
        return Response(
            {"detail": "Conta excluída e consentimento revogado com sucesso."},
            status=status.HTTP_204_NO_CONTENT
        )
