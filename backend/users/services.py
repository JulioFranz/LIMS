"""
LIMS — Camada de serviços / regras de negócio (services.py)

Este módulo concentra toda a lógica de segurança do sistema, isolada das Views
(padrão Clean Architecture / Hexagonal Architecture — Services Layer).

Proteções implementadas neste arquivo:
  - Hashing SHA-256 de segredos de token (nunca armazenados em texto plano)
  - Checksum HMAC-SHA256 na trilha de auditoria (anti-tampering / Non-Repudiation)
  - Pseudonimização de e-mails nos logs via SHA-256 truncado (LGPD Art. 13, §4º)
  - Proteção contra enumeração de e-mails no cadastro (resposta idêntica)
  - Verificação de e-mail via token de uso único com expiração
  - MFA/2FA completo: setup TOTP, verificação com valid_window, cifra do segredo
  - Reset de senha com token UUID + segredo hasheado + expiração + uso único
  - Invalidação de TODAS as sessões JWT após reset de senha (token blacklist)
  - Registro de consentimento LGPD (Privacy by Design) no cadastro
  - Transações atômicas em operações críticas (@transaction.atomic)
"""

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


# =============================================================================
# Helpers de segurança
# =============================================================================

def _create_token(user: User, change_type: str, new_value: str = "") -> str:
    """
    Cria um token de operação sensível (verificação de e-mail, etc.).

    Proteções:
      - UUID v4 aleatório como identificador público (não previsível).
      - Segredo numérico de 6 dígitos gerado com secrets.randbelow (CSPRNG).
      - O segredo é hasheado com SHA-256 antes de salvar no banco — o texto
        plano só é retornado ao usuário (via e-mail) e nunca fica persistido.
      - new_value é cifrado com Fernet AES (encrypt_value) quando contém
        dados sensíveis.
      - Tokens anteriores do mesmo tipo são deletados (impede acúmulo).
    """
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
    """Decifra new_value usando Fernet AES (crypto.py). Usar sempre que precisar ler o campo."""
    return decrypt_value(token_obj.new_value)


def _send_email(subject: str, message: str, recipient: str) -> None:
    """
    Disparo de e-mail transacional via Brevo (Sendinblue) em thread separada.
    A API key é carregada de variável de ambiente (Secrets Management).
    """
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
    """
    Pseudonimização de e-mail para logs (LGPD Art. 13, §4º).

    Proteção: o e-mail nunca é registrado em texto plano nos logs de auditoria.
    Em vez disso, é armazenado como hash SHA-256 truncado para 16 caracteres.
    Isso permite correlacionar eventos do mesmo titular (mesmo hash = mesmo e-mail)
    sem expor o dado pessoal. Atende ao princípio de minimização (LGPD Art. 6º, III).
    """
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()[:16]


def _compute_audit_checksum(event: str, result: str, user_id: str, email_hash: str, ip: str, user_agent: str) -> str:
    """
    Gera checksum HMAC-SHA256 para o registro de auditoria (Anti-Tampering).

    Proteção: Non-Repudiation e integridade da trilha de auditoria (ISO 27001 A.12.4).
    O checksum é calculado com HMAC usando a SECRET_KEY do Django sobre todos os
    campos do evento concatenados. Se qualquer campo for alterado diretamente no
    banco de dados (ex: atacante com acesso ao DB tentando apagar rastros), o
    checksum armazenado não corresponderá ao recalculado, denunciando a adulteração.
    Método verify_checksum() pode ser implementado para validar integridade em auditoria.
    """
    payload = f"{event}|{result}|{user_id}|{email_hash}|{ip}|{user_agent}"
    return hmac.new(settings.SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _audit(event: str, result: str, *, user=None, email_hash: str = "",
           client_ip: str = "", user_agent: str = "") -> None:
    """
    Registra evento na trilha de auditoria (banco de dados + arquivo de log).

    Proteções:
      - Checksum HMAC-SHA256 anti-tampering em cada registro.
      - User-Agent truncado a 200 chars (prevenção de payload injection nos logs).
      - Dupla persistência: banco de dados (AuditLog) + arquivo rotativo (audit.log).
      - Falha na gravação do AuditLog não interrompe o fluxo principal do sistema
        (disponibilidade > log), mas é registrada no logger de exceções.
      - Formato estruturado no arquivo permite parsing automatizado por SIEM.
    """
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
    """
    Hash SHA-256 do segredo de um token.

    Proteção: o segredo real (enviado por e-mail ao usuário) nunca é armazenado
    em texto plano no banco de dados. Apenas o hash é persistido.
    Na verificação, o hash do segredo fornecido é comparado ao armazenado.
    Mesmo padrão usado para senhas (store hash, never store plaintext).
    """
    return hashlib.sha256(secret.encode()).hexdigest()


# =============================================================================
# Cadastro de usuário
# =============================================================================

@transaction.atomic
def register_user(username: str, email: str, password: str, consent: bool = False) -> User | None:
    """
    Registra um novo usuário no sistema.

    Proteções:
      - Anti-enumeração de e-mail: se o e-mail já existe, NÃO retorna erro.
        Em vez disso, envia um e-mail ao titular informando a tentativa.
        Isso impede que atacantes descubram quais e-mails estão cadastrados.
      - Consentimento LGPD (Art. 8º): registra timestamp e versão do aceite.
      - Token de verificação de e-mail com segredo hasheado (SHA-256).
      - Transação atômica: se qualquer etapa falhar, tudo é revertido.
    """
    if User.objects.filter(email__iexact=email.strip()).exists():
        # SEGURANÇA: Anti-enumeração — resposta idêntica ao cadastro bem-sucedido.
        # Envia e-mail ao titular real para que ele saiba da tentativa.
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

    # LGPD: Privacy by Design — registra consentimento com timestamp e versão (Art. 8º)
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


# =============================================================================
# Verificação de e-mail
# =============================================================================

def confirm_email_verification(token_str: str) -> None:
    """
    Confirma a verificação de e-mail usando o segredo enviado por e-mail.

    Proteções:
      - Comparação por hash: o segredo fornecido é hasheado (SHA-256) e comparado
        ao token_hash armazenado no banco. O segredo real nunca é persistido.
      - Expiração: tokens expirados são deletados e rejeitados.
      - Uso único: o token é deletado após uso bem-sucedido.
    """
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


# =============================================================================
# TOTP / 2FA — Autenticação de Dois Fatores (RFC 6238)
# =============================================================================

def _create_pending_token(user: User, change_type: str) -> str:
    """
    Cria token pendente para fluxo de 2FA (login ou setup).

    Proteção: token UUID aleatório como identificador de sessão temporária.
    Impede que o JWT seja emitido antes da verificação do segundo fator.
    """
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
    """Cria token pendente para login com 2FA (usuário já tem TOTP configurado)."""
    return _create_pending_token(user, 'totp_pending')


def create_totp_setup_pending_token(user: User) -> str:
    """Cria token pendente para configuração inicial do 2FA (primeiro login)."""
    return _create_pending_token(user, 'totp_setup_pending')


def get_totp_setup_uri(pending_token_id: str) -> dict:
    """
    Gera o segredo TOTP e a URI para QR Code do Google Authenticator.

    Proteções:
      - Segredo TOTP gerado com pyotp.random_base32() (CSPRNG de 160 bits).
      - Segredo cifrado com Fernet AES antes de salvar no banco (encrypt_value).
      - Token pendente com expiração (impede setup tardio com token velho).
      - URI de provisionamento padrão otpauth:// (compatível com Google Auth, Authy, etc.).
    """
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

    # SEGURANÇA: Segredo TOTP cifrado com Fernet AES antes do armazenamento
    token_obj.new_value = encrypt_value(secret)
    token_obj.save(update_fields=['new_value'])

    return {'qr_uri': qr_uri, 'secret': secret}


@transaction.atomic
def confirm_totp_setup_and_get_jwt(pending_token_id: str, totp_code: str) -> dict:
    """
    Confirma a configuração do 2FA validando o código TOTP e emite JWT.

    Proteções:
      - Validação do código TOTP com valid_window=2 (aceita código atual ± 2 janelas
        de 30s, tolerando dessincronização de relógio do dispositivo do usuário).
      - Segredo TOTP decifrado da sessão pendente e re-cifrado no perfil do usuário.
      - Token pendente deletado após uso (uso único).
      - Transação atômica: garante consistência entre ativar 2FA e deletar token.
    """
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

    # SEGURANÇA: Decifra o segredo TOTP da sessão pendente (Fernet AES)
    secret = decrypt_value(token_obj.new_value)

    # SEGURANÇA: Valida código TOTP com tolerância de ±2 janelas de 30s
    if not pyotp.TOTP(secret).verify(totp_code.strip(), valid_window=2):
        raise ValueError("Código inválido. Verifique o app e tente novamente.")

    # SEGURANÇA: Armazena segredo TOTP cifrado (Fernet AES) no perfil permanente
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
    """
    Valida o código TOTP no fluxo de login e emite JWT se correto.

    Proteções:
      - Segredo TOTP decifrado do perfil (Fernet AES) apenas no momento da validação.
      - Falha na validação é registrada na trilha de auditoria (login_failed + IP + UA).
      - Sucesso também é registrado (totp_login_success) para rastreabilidade.
      - Token pendente deletado após uso (impede replay).
      - valid_window=2: tolerância de ±2 janelas de 30s para dessincronização de relógio.
      - Transação atômica para consistência.
    """
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
    # SEGURANÇA: Decifra segredo TOTP do perfil (Fernet AES) para validação
    secret = decrypt_value(profile.totp_secret)

    if not pyotp.TOTP(secret).verify(totp_code.strip(), valid_window=2):
        # SEGURANÇA: Registra tentativa de login 2FA falha na trilha de auditoria
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

    # SEGURANÇA: Registra login 2FA bem-sucedido na trilha de auditoria
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
    """
    Desativa o 2FA do usuário.
    O segredo TOTP é apagado do banco (não apenas desabilitado).
    """
    profile = user.profile
    profile.totp_secret = ''
    profile.totp_enabled = False
    profile.save(update_fields=['totp_secret', 'totp_enabled'])
    logger.info(f"TOTP desativado para o usuário {user.username}.")


# =============================================================================
# Recuperação de senha
# =============================================================================

def _build_reset_url(request, token_id: str, secret: str) -> str:
    """Constrói a URL de reset apontando para o frontend (não para o backend)."""
    frontend_url = settings.FRONTEND_URL.rstrip('/')
    return f"{frontend_url}/password-reset/confirm?uid={token_id}&token={secret}"


@transaction.atomic
def request_password_reset(email: str, request, *, client_ip: str = "", user_agent: str = "") -> None:
    """
    Solicita recuperação de senha.

    Proteções:
      - Anti-enumeração de e-mail: se o e-mail não existe, retorna silenciosamente
        (sem erro). A view retorna sempre a mesma mensagem genérica, impedindo
        que atacantes descubram quais e-mails estão cadastrados.
      - Segredo de 64 bytes (token_urlsafe) — entropia criptográfica alta.
      - Segredo hasheado com SHA-256 antes de salvar (nunca em texto plano).
      - Tokens anteriores do mesmo tipo são deletados (apenas 1 ativo por vez).
      - Todas as etapas registradas na trilha de auditoria (com IP e User-Agent).
      - Transação atômica para consistência.
    """
    email_hash = _hash_email(email)

    try:
        user = User.objects.get(email__iexact=email.strip())
    except User.DoesNotExist:
        # SEGURANÇA: Anti-enumeração — não revela se o e-mail existe ou não
        _audit(
            event="password_reset_requested",
            result="no_user",
            email_hash=email_hash,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        return

    # SEGURANÇA: Segredo de alta entropia (64 bytes / 512 bits via CSPRNG)
    secret = secrets.token_urlsafe(64)
    # SEGURANÇA: Apenas o hash SHA-256 do segredo é armazenado no banco
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
    """
    Confirma o reset de senha com o token da URL e define nova senha.

    Proteções:
      - select_for_update(): lock pessimista no token (impede race condition
        com duas requisições simultâneas usando o mesmo link).
      - Verificação de token usado (used_at) — impede reutilização do link.
      - Comparação do hash do segredo (token_hash vs SHA-256 do segredo da URL).
      - Expiração: token válido por 30 minutos (configurável em selectors.py).
      - Validação da nova senha com os 5 validadores do Django (incluindo
        complexidade customizada).
      - Mensagem de erro genérica ("Link inválido ou expirado") em TODAS as
        falhas — impede que atacantes distingam entre token inexistente, usado,
        expirado ou com segredo errado (anti-enumeração).
      - Invalidação de TODAS as sessões JWT ativas do usuário via blacklist
        após mudança de senha (impede que sessões antigas continuem válidas).
      - Cada etapa é registrada na trilha de auditoria.
      - Transação atômica para consistência.
    """
    # SEGURANÇA: Hash do segredo da URL para comparar com o armazenado
    secret_hash = _hash_secret(secret)

    try:
        # SEGURANÇA: select_for_update() previne race condition (uso paralelo do mesmo token)
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

    # SEGURANÇA: Token já foi usado — impede reutilização (replay attack)
    if token_obj.used_at is not None:
        _audit(
            event="password_reset_confirmed",
            result="token_already_used",
            user=user,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise ValueError("Link inválido ou expirado.")

    # SEGURANÇA: Comparação do hash do segredo (nunca compara texto plano)
    if token_obj.token_hash != secret_hash:
        _audit(
            event="password_reset_confirmed",
            result="invalid_secret",
            user=user,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise ValueError("Link inválido ou expirado.")

    # SEGURANÇA: Verificação de expiração (30 min, configurável em selectors.py)
    if timezone.now() > token_obj.created_at + _expiration_for('password_reset'):
        _audit(
            event="password_reset_confirmed",
            result="token_expired",
            user=user,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise ValueError("Link inválido ou expirado.")

    # SEGURANÇA: Validação da nova senha com os 5 validadores do Django
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

    # SEGURANÇA: Marca token como usado — impede reutilização
    token_obj.used_at = timezone.now()
    token_obj.save(update_fields=['used_at'])

    # SEGURANÇA: Invalida TODAS as sessões JWT ativas após mudança de senha.
    # Todos os refresh tokens são adicionados à blacklist, forçando re-login.
    # Impede que um atacante que roubou um token continue com acesso após o reset.
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
