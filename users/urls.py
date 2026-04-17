from django.urls import path
from .views import RegisterView, LoginView, Verify2FAView, LogoutView, VerifyEmailView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('login/verify/', Verify2FAView.as_view(), name='verify-2fa'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
]
