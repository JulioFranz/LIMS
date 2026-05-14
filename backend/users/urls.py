from django.urls import path
from .views import (
    RegisterView, LoginView, Verify2FAView, LogoutView, VerifyEmailView,
    PasswordResetRequestView, PasswordResetConfirmView,
    Setup2FAView, ConfirmSetup2FAView, Disable2FAView,
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
]
