import uuid
from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.db import transaction
from rest_framework_simplejwt.tokens import RefreshToken
import logging

from .models import ProfileChangeToken, UserProfile
from .selectors import get_token_info

logger = logging.getLogger(__name__)


def _create_token(user: User, change_type: str, new_value: str = "") -> str:
    token = str(uuid.uuid4())
    ProfileChangeToken.objects.filter(user=user, change_type=change_type).delete()
    ProfileChangeToken.objects.create(
        user=user,
        token=token,
        change_type=change_type,
        new_value=new_value,
    )
    return token


def _send_email(subject: str, message: str, recipient: str) -> None:
    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[recipient],
    )


@transaction.atomic
def register_user(username: str, email: str, password: str) -> User:
    user = User.objects.create_user(username=username, email=email, password=password)
    UserProfile.objects.create(user=user, is_verified=False)

    try:
        #confirmar o e-mail no momento do cadastro
        token = _create_token(user, "verify")
        _send_email(
            "Verifique sua conta",
            f"Bem-vindo! Use este token para verificar sua conta: {token}",
            user.email
        )
    except Exception as e:
        logger.error(f"Falha ao enviar e-mail para {email}", exc_info=True)

    return user



def generate_2fa_token(user: User) -> str:
    """Gera o token 2FA e envia por e-mail APÓS a senha estar correta."""
    token = _create_token(user, "2fa_login")
    _send_email(
        subject="Seu código de Autenticação em Duas Etapas (2FA)",
        message=f"Olá {user.username},\n\nPara concluir seu login, utilize o token abaixo:\n\n{token}\n\nEste token expira em 15 minutos.",
        recipient=user.email
    )
    # Log de auditoria
    logger.info(f"Token 2FA gerado para o usuário {user.username}.")
    return token


def validate_2fa_and_get_jwt(token_str: str) -> dict:
    """Valida o 2FA e, se correto, entrega o JWT final."""
    token_obj = get_token_info(token_str, "2fa_login")
    user = token_obj.user

    #tokens de acesso
    refresh = RefreshToken.for_user(user)

    # Invalidar após uso
    token_obj.delete()

    logger.info(f"Login com 2FA concluído com sucesso para o usuário {user.username}.")

    return {
        "access": str(refresh.access_token),
        "refresh": str(refresh),
    }


def confirm_email_verification(token_str: str) -> None:
    """Valida o token de verificação e ativa a conta do usuário."""
    # Busca o token no banco validando se é do tipo correto e se não expirou
    token_obj = get_token_info(token_str, "verify")

    # Atualiza o perfil para verificado
    profile = token_obj.user.profile
    profile.is_verified = True
    profile.save(update_fields=["is_verified"])

    # Deleta o token após o uso (Requisito 2.5)
    token_obj.delete()