from django.urls import path
from .frontend_views import login_page, register_page, verify_2fa_page, verify_email_page, dashboard_page

urlpatterns = [
    path('', login_page, name='frontend-login'),
    path('register/', register_page, name='frontend-register'),
    path('verify-2fa/', verify_2fa_page, name='frontend-verify-2fa'),
    path('verify-email/', verify_email_page, name='frontend-verify-email'),
    path('dashboard/', dashboard_page, name='frontend-dashboard'),
]
