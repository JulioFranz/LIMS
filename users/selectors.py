from django.contrib.auth.models import User
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from datetime import timedelta
from .models import ProfileChangeToken, UserProfile


def get_profile(user: User) -> UserProfile | None:
    return getattr(user, "profile", None)


def get_token_info(token_str: str, change_type: str) -> ProfileChangeToken:
    try:
        token_obj = ProfileChangeToken.objects.select_related("user").get(
            token=token_str,
            change_type=change_type,
        )

        # VALIDAÇÃO DE EXPIRAÇÃO
        if timezone.now() > token_obj.created_at + timedelta(minutes=15):
            token_obj.delete()  # Falha para token expirado
            raise ValueError("Token expirado.")

        return token_obj
    except (ProfileChangeToken.DoesNotExist, DjangoValidationError):
        raise ValueError("Token inválido.")