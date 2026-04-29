import hashlib
import secrets
import uuid
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.urls import reverse
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
import logging
import threading

from .models import ProfileChangeToken, UserProfile
from .selectors import get_token_info, get_password_reset_token
from .crypto import encrypt_value, decrypt_value

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("users.audit")


# ---------- Helpers ----------

def _create_token(user: User, change_type: str, new_value: str = "") -> str:
    token_id = str(uuid.uuid4())
    secret = str(uuid.uuid4())
    secret_hash = _hash_secret(secret)

    ProfileChangeToken.objects.filter(user=user, change_type=change_type).delete()
    ProfileChangeToken.objects.create(
        user=user,
        token=token_id,
        change_type=change_type,
        new_value=encrypt_value(new_value),
        token_hash=secret_hash,
    )
    return secret


def get_token_new_value(token_obj) -> str:
    """
    Decifra o campo new_value de um ProfileChangeToken.
    Use sempre que precisar ler new_value em outras partes do código.
    """
    return decrypt_value(token_obj.new_value)


def _send_email(subject: str, message: str, recipient: str) -> None:

    def send_task():
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[recipient],
                fail_silently=False,
            )
            logger.info(f"E-mail enviado com sucesso para {recipient}")
        except Exception:
            logger.error(f"Falha ao enviar e-mail para {recipient}", exc_info=True)

    threading.Thread(target=send_task).start()


def _hash_email(email: str) -> str:
    """Hash de e-mail para logs (LGPD: não logar dado pessoal em claro)."""
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()[:16]


def _audit(event: str, result: str, *, user=None, email_hash: str = "",
           client_ip: str = "", user_agent: str = "") -> None:
    """Grava evento de auditoria no banco e no arquivo de log."""
    from .models import AuditLog

    try:
        AuditLog.objects.create(
            event=event,
            result=result,
            user=user,
            email_hash=email_hash,
            ip=client_ip or None,
            user_agent=user_agent[:200],
        )
    except Exception:
        logger.exception("Falha ao gravar AuditLog")

    audit_logger.info(
        f"{event}.{result}",
        extra={
            "event": event,
            "result": result,
            "user_id": user.id if user else "",
            "email_hash": email_hash,
            "ip": client_ip,
            "user_agent": user_agent[:200],
        },
    )


def _hash_secret(secret: str) -> str:
    """SHA-256 hex do segredo do token de reset (Requisito 2.2)."""
    return hashlib.sha256(secret.encode()).hexdigest()


@transaction.atomic
def register_user(username: str, email: str, password: str) -> User:
    user = User.objects.create_user(username=username, email=email, password=password)
    UserProfile.objects.create(user=user, is_verified=False)

    try:
        secret = _create_token(user, "verify")
        _send_email(
            "Verifique sua conta",
            f"Bem-vindo! Use este token para verificar sua conta: {secret}",
            user.email
        )
    except Exception:
        logger.error(f"Falha ao enviar e-mail para {_hash_email(email)}", exc_info=True)

    return user


def confirm_email_verification(token_str: str) -> None:
    """Confirma e-mail validando o segredo via hash."""
    secret_hash = _hash_secret(token_str)
    from .selectors import _expiration_for

    token_obj = (
        ProfileChangeToken.objects
        .select_related("user__profile")
        .filter(change_type="verify", token_hash=secret_hash)
        .first()
    )
    if token_obj is None:
        raise ValueError("Token inválido.")

    if timezone.now() > token_obj.created_at + _expiration_for("verify"):
        token_obj.delete()
        raise ValueError("Token expirado.")

    profile = token_obj.user.profile
    profile.is_verified = True
    profile.save(update_fields=["is_verified"])
    token_obj.delete()


# ---------- 2FA ----------

def generate_2fa_token(user: User) -> str:
    secret = _create_token(user, "2fa_login")
    _send_email(
        subject="Seu código de Autenticação em Duas Etapas (2FA)",
        message=f"Olá {user.username},\n\nPara concluir seu login, utilize o token abaixo:\n\n{secret}\n\nEste token expira em 15 minutos.",
        recipient=user.email
    )
    logger.info(f"Token 2FA gerado para o usuário {user.username}.")
    return secret


def validate_2fa_and_get_jwt(token_str: str) -> dict:
    secret_hash = _hash_secret(token_str)
    from .selectors import _expiration_for

    token_obj = (
        ProfileChangeToken.objects
        .select_related("user")
        .filter(change_type="2fa_login", token_hash=secret_hash)
        .first()
    )
    if token_obj is None:
        raise ValueError("Token inválido.")

    if timezone.now() > token_obj.created_at + _expiration_for("2fa_login"):
        token_obj.delete()
        raise ValueError("Token expirado.")

    user = token_obj.user
    refresh = RefreshToken.for_user(user)
    token_obj.delete()
    logger.info(f"Login com 2FA concluído com sucesso para o usuário {user.username}.")
    return {
        "access": str(refresh.access_token),
        "refresh": str(refresh),
    }


# ---------- Recuperação de senha ----------

def _build_reset_url(request, token_id: str, secret: str) -> str:
    """Monta a URL absoluta que vai no e-mail."""
    path = reverse('frontend-password-reset-confirm')
    return request.build_absolute_uri(
        f"{path}?uid={token_id}&token={secret}"
    )


@transaction.atomic
def request_password_reset(email: str, request, *, client_ip: str = "", user_agent: str = "") -> None:
    email_hash = _hash_email(email)

    try:
        user = User.objects.get(email__iexact=email.strip())
    except User.DoesNotExist:
        _audit(
            event="password_reset_requested",
            result="no_user",
            email_hash=email_hash,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        return

    # segredo criptograficamente seguro
    secret = secrets.token_urlsafe(64)
    secret_hash = _hash_secret(secret)

    # invalida token de reset anterior do user
    ProfileChangeToken.objects.filter(user=user, change_type='password_reset').delete()

    token_id = str(uuid.uuid4())
    ProfileChangeToken.objects.create(
        user=user,
        token=token_id,
        change_type='password_reset',
        token_hash=secret_hash,
        new_value='',
    )

    reset_url = _build_reset_url(request, token_id, secret)

    try:
        _send_email(
            subject="Recuperação de senha - LIMS",
            message=(
                f"Olá {user.username},\n\n"
                f"Recebemos uma solicitação para redefinir a senha da sua conta.\n\n"
                f"Para criar uma nova senha, acesse o link abaixo (válido por 30 minutos):\n\n"
                f"{reset_url}\n\n"
                f"Se você não solicitou esta alteração, ignore este e-mail. "
                f"Sua senha atual permanecerá inalterada."
            ),
            recipient=user.email,
        )
    except Exception:
        logger.error(
            f"Falha ao enviar e-mail de reset para user_id={user.id}",
            exc_info=True,
        )
        _audit(
            event="password_reset_requested",
            result="email_send_failed",
            user=user,
            email_hash=email_hash,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        return

    _audit(
        event="password_reset_requested",
        result="email_sent",
        user=user,
        email_hash=email_hash,
        client_ip=client_ip,
        user_agent=user_agent,
    )


@transaction.atomic
def confirm_password_reset(
        token_id: str,
        secret: str,
        new_password: str,
        *,
        client_ip: str = "",
        user_agent: str = "",
) -> None:
    secret_hash = _hash_secret(secret)

    try:
        token_obj = (
            ProfileChangeToken.objects
            .select_for_update()
            .select_related('user')
            .get(token=token_id, change_type='password_reset')
        )
    except (ProfileChangeToken.DoesNotExist, DjangoValidationError):
        _audit(
            event="password_reset_confirmed",
            result="token_not_found",
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise ValueError("Link inválido ou expirado.")

    user = token_obj.user

    if token_obj.used_at is not None:
        _audit(
            event="password_reset_confirmed",
            result="token_already_used",
            user=user,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise ValueError("Link inválido ou expirado.")

    if token_obj.token_hash != secret_hash:
        _audit(
            event="password_reset_confirmed",
            result="invalid_secret",
            user=user,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise ValueError("Link inválido ou expirado.")

    # expiração
    from .selectors import _expiration_for
    if timezone.now() > token_obj.created_at + _expiration_for('password_reset'):
        _audit(
            event="password_reset_confirmed",
            result="token_expired",
            user=user,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise ValueError("Link inválido ou expirado.")

    # validators de senha
    try:
        validate_password(new_password, user=user)
    except DjangoValidationError as e:
        _audit(
            event="password_reset_confirmed",
            result="weak_password",
            user=user,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise ValueError(" ".join(e.messages))

    user.set_password(new_password)
    user.save(update_fields=['password'])

    token_obj.used_at = timezone.now()
    token_obj.save(update_fields=['used_at'])

    try:
        from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
        outstanding = OutstandingToken.objects.filter(user=user)
        for ot in outstanding:
            BlacklistedToken.objects.get_or_create(token=ot)
    except Exception:
        logger.warning(
            f"Falha ao invalidar sessões ativas após reset de senha (user_id={user.id})",
            exc_info=True,
        )

    _audit(
        event="password_reset_confirmed",
        result="success",
        user=user,
        client_ip=client_ip,
        user_agent=user_agent,
    )