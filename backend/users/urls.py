"""
LIMS — Mapeamento de URLs da API de autenticação (urls.py)

Endpoints e suas proteções:
  POST /api/users/register/              — Cadastro (Rate Limit: 3/min, anti-enumeração)
  POST /api/users/login/                 — Login etapa 1 (Rate Limit: 3/min, auditoria)
  POST /api/users/login/verify/          — Login etapa 2 - código TOTP (Rate Limit: 3/min)
  POST /api/users/logout/                — Logout com blacklist do JWT (IsAuthenticated)
  POST /api/users/verify-email/          — Verificação de e-mail via código hasheado
  POST /api/users/password-reset/        — Solicita reset (Rate Limit: 5/hora, anti-enumeração)
  POST /api/users/password-reset/confirm/ — Confirma reset (token uso único + hash + expiração)
  POST /api/users/2fa/setup/             — Gera QR Code TOTP (Rate Limit: 3/min)
  POST /api/users/2fa/setup/confirm/     — Confirma setup 2FA (Rate Limit: 3/min)
  POST /api/users/2fa/disable/           — Desativa 2FA (IsAuthenticated + código TOTP)
  GET  /api/users/me/                    — Dados do titular LGPD (IsAuthenticated)
  DELETE /api/users/me/                  — Exclusão de conta LGPD (IsAuthenticated)

Todos os endpoints também possuem Rate Limiting GLOBAL (AnonRateThrottle 30/min,
UserRateThrottle 120/min) configurado em settings.py DEFAULT_THROTTLE_CLASSES.
"""

from django.urls import path
from .views import (
    RegisterView, LoginView, Verify2FAView, LogoutView, VerifyEmailView,
    PasswordResetRequestView, PasswordResetConfirmView,
    Setup2FAView, ConfirmSetup2FAView, Disable2FAView,
    MeView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('login/verify/', Verify2FAView.as_view(), name='verify-2fa'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('2fa/setup/', Setup2FAView.as_view(), name='2fa-setup'),
    path('2fa/setup/confirm/', ConfirmSetup2FAView.as_view(), name='2fa-setup-confirm'),
    path('2fa/disable/', Disable2FAView.as_view(), name='2fa-disable'),
    path('me/', MeView.as_view(), name='me'),
]
