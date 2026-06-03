import hashlib
import hmac
import os
import secrets
import uuid

import pyotp
import sib_api_v3_sdk
from django.conf import settings
from django.contrib.auth.models import User, update_last_login
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction, DatabaseError
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
import logging
import threading

from sib_api_v3_sdk.rest import ApiException

from .models import AuditLog, ProfileChangeToken, UserProfile
from .selectors import _expiration_for
from .crypto import encrypt_value, decrypt_value

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("users.audit")


# ---------- Helpers ----------

# Cria token de mudanca no banco
def _create_token(user: User, change_type: str, new_value: str = "") -> str:
    token_id = str(uuid.uuid4())
    secret = f"{secrets.randbelow(1_000_000):06d}"
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
    """Decifra new_value, usar sempre que precisar ler o campo em outros módulos."""
    return decrypt_value(token_obj.new_value)


# Disparo de email via Brevo
def _send_email(subject: str, message: str, recipient: str) -> None:
    def send_task():
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = os.environ.get('BREVO_API_KEY')

        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            to=[{"email": recipient}],
            sender={"email": settings.DEFAULT_FROM_EMAIL, "name": "LIMS System"},
            subject=subject,
            html_content=f"<html><body><p>{message}</p></body></html>"
        )

        try:
            api_instance.send_transac_email(send_smtp_email)
            logger.info(f"E-mail enviado via API para {recipient}")
        except ApiException as e:
            logger.error(f"Erro na API do Brevo ao enviar para {recipient}: {e}")

    threading.Thread(target=send_task).start()


def _hash_email(email: str) -> str:
    """Hash de e-mail para logs (LGPD: não logar dado pessoal em claro)."""
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()[:16]


# Checksum HMAC-SHA256 dos campos de log, detecta alteracoes diretas do banco
def _compute_audit_checksum(event: str, result: str, user_id: str, email_hash: str, ip: str, user_agent: str) -> str:
    """HMAC-SHA256 dos campos do evento."""
    payload = f"{event}|{result}|{user_id}|{email_hash}|{ip}|{user_agent}"
    return hmac.new(settings.SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()


# Registro de log estruturdo
def _audit(event: str, result: str, *, user=None, email_hash: str = "",
           client_ip: str = "", user_agent: str = "") -> None:
    user_id_str = str(user.id) if user else ""
    ua_truncated = user_agent[:200]
    checksum = _compute_audit_checksum(event, result, user_id_str, email_hash, client_ip or "", ua_truncated)

    try:
        AuditLog.objects.create(
            event=event,
            result=result,
            user=user,
            email_hash=email_hash,
            ip=client_ip or None,
            user_agent=ua_truncated,
            checksum=checksum,
        )
    except DatabaseError:
        # Log de auditoria não pode travar o fluxo principal
        logger.exception("Falha ao gravar AuditLog")

    audit_logger.info(
        f"{event}.{result}",
        extra={
            "event": event,
            "result": result,
            "user_id": user.id if user else "",
            "email_hash": email_hash,
            "ip": client_ip,
            "user_agent": ua_truncated,
        },
    )


def _hash_secret(secret: str) -> str:
    """SHA-256 hex do segredo do token (Requisito 2.2 — armazenamento seguro)."""
    return hashlib.sha256(secret.encode()).hexdigest()


@transaction.atomic
def register_user(username: str, email: str, password: str, consent: bool = False) -> User | None:
    # nao revelar se o e-mail ja existe
    if User.objects.filter(email__iexact=email.strip()).exists():
        _send_email(
            "Tentativa de cadastro - LIMS",
            (
                f"Olá,<br><br>"
                f"Recebemos uma tentativa de criar uma conta com este endereço de e-mail, "
                f"mas já existe uma conta associada a ele.<br><br>"
                f"Se você já tem uma conta, acesse normalmente. "
                f"Caso tenha esquecido sua senha, <a href=\"{settings.FRONTEND_URL}/password-reset\">clique aqui para redefini-la</a>.<br><br>"
                f"Se não foi você quem fez esta solicitação, ignore este e-mail."
            ),
            email,
        )
        return None

    user = User.objects.create_user(username=username, email=email, password=password)

    UserProfile.objects.create(
        user=user,
        is_verified=False,
        consent_accepted_at=timezone.now() if consent else None,
        consent_version='1.0' if consent else '',
    )

    try:
        secret = _create_token(user, "verify")
        _send_email(
            "Verifique sua conta",
            f"Bem-vindo! Use este código para verificar sua conta: <strong>{secret}</strong>",
            user.email
        )
    except (DatabaseError, RuntimeError):
        logger.error(f"Falha ao enviar e-mail para {_hash_email(email)}", exc_info=True)

    return user


# Verificacao de email via hash do segredo enviado
def confirm_email_verification(token_str: str) -> None:
    secret_hash = _hash_secret(token_str)

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


# ---------- TOTP (Google Authenticator) ----------

def _create_pending_token(user: User, change_type: str) -> str:
    token_id = uuid.uuid4()
    ProfileChangeToken.objects.filter(user=user, change_type=change_type).delete()
    ProfileChangeToken.objects.create(
        user=user,
        token=token_id,
        change_type=change_type,
        new_value='',
        token_hash='',
    )
    return str(token_id)


def create_totp_pending_token(user: User) -> str:
    return _create_pending_token(user, 'totp_pending')


def create_totp_setup_pending_token(user: User) -> str:
    return _create_pending_token(user, 'totp_setup_pending')


# QR Code e segredo para TOTP
def get_totp_setup_uri(pending_token_id: str) -> dict:
    try:
        token_obj = (
            ProfileChangeToken.objects
            .select_related('user')
            .get(token=pending_token_id, change_type='totp_setup_pending')
        )
    except (ProfileChangeToken.DoesNotExist, DjangoValidationError):
        raise ValueError("Token inválido.")

    if timezone.now() > token_obj.created_at + _expiration_for('totp_setup_pending'):
        token_obj.delete()
        raise ValueError("Sessão expirada. Faça login novamente.")

    secret = pyotp.random_base32()
    qr_uri = pyotp.TOTP(secret).provisioning_uri(
        name=token_obj.user.email,
        issuer_name="LIMS"
    )

    token_obj.new_value = encrypt_value(secret)
    token_obj.save(update_fields=['new_value'])

    return {'qr_uri': qr_uri, 'secret': secret}


# Confirma o TOTP com codigo do app e emite JWT
@transaction.atomic
def confirm_totp_setup_and_get_jwt(pending_token_id: str, totp_code: str) -> dict:
    try:
        token_obj = (
            ProfileChangeToken.objects
            .select_related('user__profile')
            .get(token=pending_token_id, change_type='totp_setup_pending')
        )
    except (ProfileChangeToken.DoesNotExist, DjangoValidationError):
        raise ValueError("Token inválido.")

    if timezone.now() > token_obj.created_at + _expiration_for('totp_setup_pending'):
        token_obj.delete()
        raise ValueError("Sessão expirada. Faça login novamente.")

    if not token_obj.new_value:
        raise ValueError("Inicie a configuração antes de confirmar.")

    secret = decrypt_value(token_obj.new_value)

    if not pyotp.TOTP(secret).verify(totp_code.strip(), valid_window=2):
        raise ValueError("Código inválido. Verifique o app e tente novamente.")

    profile = token_obj.user.profile
    profile.totp_secret = encrypt_value(secret)
    profile.totp_enabled = True
    profile.save(update_fields=['totp_secret', 'totp_enabled'])

    user = token_obj.user
    token_obj.delete()

    update_last_login(None, user)

    refresh = RefreshToken.for_user(user)
    refresh['username'] = user.username
    logger.info(f"TOTP ativado para o usuário {user.username}.")
    return {'access': str(refresh.access_token), 'refresh': str(refresh)}


@transaction.atomic
def validate_totp_login_and_get_jwt(
    pending_token_id: str,
    totp_code: str,
    *,
    client_ip: str = "",
    user_agent: str = "",
) -> dict:
    try:
        token_obj = (
            ProfileChangeToken.objects
            .select_related('user__profile')
            .get(token=pending_token_id, change_type='totp_pending')
        )
    except (ProfileChangeToken.DoesNotExist, DjangoValidationError):
        raise ValueError("Token inválido.")

    if timezone.now() > token_obj.created_at + _expiration_for('totp_pending'):
        token_obj.delete()
        raise ValueError("Sessão expirada. Faça login novamente.")

    profile = token_obj.user.profile
    secret = decrypt_value(profile.totp_secret)

    if not pyotp.TOTP(secret).verify(totp_code.strip(), valid_window=2):
        _audit(
            event="totp_login_failed",
            result="failed",
            user=token_obj.user,
            email_hash=_hash_email(token_obj.user.email),
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise ValueError("Código inválido ou expirado.")

    user = token_obj.user
    token_obj.delete()

    update_last_login(None, user)

    _audit(
        event="totp_login_success",
        result="success",
        user=user,
        email_hash=_hash_email(user.email),
        client_ip=client_ip,
        user_agent=user_agent,
    )

    refresh = RefreshToken.for_user(user)
    refresh['username'] = user.username
    logger.info(f"Login com TOTP concluído para o usuário {user.username}.")
    return {'access': str(refresh.access_token), 'refresh': str(refresh)}


def disable_totp(user: User) -> None:
    profile = user.profile
    profile.totp_secret = ''
    profile.totp_enabled = False
    profile.save(update_fields=['totp_secret', 'totp_enabled'])
    logger.info(f"TOTP desativado para o usuário {user.username}.")


# ---------- Recuperação de senha ----------

def _build_reset_url(request, token_id: str, secret: str) -> str:
    frontend_url = settings.FRONTEND_URL.rstrip('/')
    return f"{frontend_url}/password-reset/confirm?uid={token_id}&token={secret}"


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

    secret = secrets.token_urlsafe(64)
    secret_hash = _hash_secret(secret)

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
    except RuntimeError:
        logger.error(
            f"Falha ao iniciar thread de e-mail de reset para user_id={user.id}",
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

    if timezone.now() > token_obj.created_at + _expiration_for('password_reset'):
        _audit(
            event="password_reset_confirmed",
            result="token_expired",
            user=user,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise ValueError("Link inválido ou expirado.")

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
    except DatabaseError:
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