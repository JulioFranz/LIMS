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
)
from .services import (
    register_user, generate_2fa_token, validate_2fa_and_get_jwt,
    confirm_email_verification,
    request_password_reset, confirm_password_reset,
)


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
        user = register_user(**serializer.validated_data)
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

        if user:
            generate_2fa_token(user)
            return Response({
                "detail": "Código 2FA enviado para seu e-mail.",
                "2fa_required": True
            })

        return Response({"detail": "Credenciais inválidas."}, status=status.HTTP_401_UNAUTHORIZED)


class Verify2FAView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = TwoFactorSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            tokens = validate_2fa_and_get_jwt(serializer.validated_data['token'])
            return Response(tokens)
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


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
    """
    Requisito 2.1 — funcionalidade implementada (etapa de solicitação).
    Requisito 2.6 — log da solicitação.

    Resposta sempre idêntica (existindo ou não o e-mail) para não permitir
    enumeração de usuários.
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
    Requisito 2.1 — funcionalidade implementada (etapa de confirmação).
    Requisitos 2.2, 2.3, 2.4, 2.5 — validação e invalidação do token.
    Requisito 2.7 — log de sucesso/falha.
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