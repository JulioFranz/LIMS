from django.contrib.auth.models import User
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from datetime import timedelta
from .models import ProfileChangeToken, UserProfile

#tipos de token
TOKEN_EXPIRATION_MINUTES = {
    '2fa_login': 15,
    'verify': 60 * 24,
    'password_reset': 30,
    'email': 60,
    'email_new': 60,
    'password': 15,
    'totp_pending': 10,
    'totp_setup_pending': 10,
}
DEFAULT_EXPIRATION_MINUTES = 15


def _expiration_for(change_type: str) -> timedelta:
    return timedelta(minutes=TOKEN_EXPIRATION_MINUTES.get(change_type, DEFAULT_EXPIRATION_MINUTES))


def get_profile(user: User) -> UserProfile | None:
    return getattr(user, "profile", None)


def get_token_info(token_str: str, change_type: str) -> ProfileChangeToken:
    try:
        token_obj = ProfileChangeToken.objects.select_related("user").get(
            token=token_str,
            change_type=change_type,
        )

        # valida expiracao
        if timezone.now() > token_obj.created_at + _expiration_for(change_type):
            token_obj.delete()
            raise ValueError("Token expirado.")

        return token_obj
    except (ProfileChangeToken.DoesNotExist, DjangoValidationError):
        raise ValueError("Token inválido.")


def get_password_reset_token(token_id: str, token_secret_hash: str) -> ProfileChangeToken:
    """
    Busca o token de reset de senha validando id público + hash do segredo.
    Lança ValueError genérico em qualquer falha (evita enumeração).
    """
    try:
        token_obj = ProfileChangeToken.objects.select_related("user").get(
            token=token_id,
            change_type='password_reset',
        )
    except (ProfileChangeToken.DoesNotExist, DjangoValidationError):
        raise ValueError("Link inválido ou expirado.")

    # token usado
    if token_obj.used_at is not None:
        raise ValueError("Link inválido ou expirado.")

    # segredo errado
    if token_obj.token_hash != token_secret_hash:
        raise ValueError("Link inválido ou expirado.")

    # expiracao
    if timezone.now() > token_obj.created_at + _expiration_for('password_reset'):
        raise ValueError("Link inválido ou expirado.")

    return token_obj
