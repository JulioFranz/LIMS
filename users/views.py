from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.throttling import AnonRateThrottle
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import RegisterSerializer, LoginSerializer, TwoFactorSerializer
from .services import register_user, generate_2fa_token, validate_2fa_and_get_jwt, confirm_email_verification


class AuthThrottle(AnonRateThrottle):
    scope = 'auth'


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
    throttle_classes = [AuthThrottle]  # Requisito 1.12 aplicado aqui

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password']
        )

        if user:
            # Requisito 1.5 e 1.6: Em vez de dar o acesso, gera o 2FA
            token_2fa = generate_2fa_token(user)
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
            # Valida o token e retorna os tokens JWT finais (Requisito 1.6)
            tokens = validate_2fa_and_get_jwt(serializer.validated_data['token'])
            return Response(tokens)
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Requisito 1.11: Invalidação de sessão (Blacklist do Refresh Token)
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout realizado com sucesso."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response(status=status.HTTP_400_BAD_REQUEST)