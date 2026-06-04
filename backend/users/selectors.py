"""
LIMS — Camada de selectors / consultas de dados (selectors.py)

Este módulo implementa consultas e validações de tokens, separando a lógica
de leitura da lógica de escrita (padrão CQRS / Clean Architecture).

Proteções implementadas neste arquivo:
  - Expiração configurável por tipo de token (TTL — Time To Live)
  - Mensagens de erro genéricas (anti-enumeração — não revelam motivo exato da falha)
  - Validação de token com uso único (used_at) e hash do segredo
"""

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from datetime import timedelta
from .models import ProfileChangeToken, UserProfile

# =============================================================================
# SEGURANÇA: Expiração de tokens por tipo de operação (TTL)
# Cada tipo de token tem um tempo de vida específico. Valores baixos reduzem a
# janela de exposição se o token for interceptado (ex: e-mail comprometido).
#
#   - verify (24h): verificação de e-mail — prazo longo para UX.
#   - password_reset (30min): curto para minimizar risco de link interceptado.
#   - totp_pending (10min): sessão entre login e código 2FA.
#   - totp_setup_pending (10min): sessão de configuração do 2FA.
#   - 2fa_login / password / email (15min): operações sensíveis de curta duração.
# =============================================================================
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
    """Retorna o tempo de expiração (timedelta) para o tipo de token dado."""
    return timedelta(minutes=TOKEN_EXPIRATION_MINUTES.get(change_type, DEFAULT_EXPIRATION_MINUTES))


def get_profile(user: User) -> UserProfile | None:
    """Retorna o perfil do usuário ou None se não existir."""
    return getattr(user, "profile", None)


def get_token_info(token_str: str, change_type: str) -> ProfileChangeToken:
    """
    Busca e valida um token por UUID e tipo.

    Proteções:
      - Validação de expiração: tokens vencidos são deletados do banco.
      - Mensagem de erro genérica "Token inválido" / "Token expirado" — não
        revela se o token não existe ou é de outro tipo (anti-enumeração).
    """
    try:
        token_obj = ProfileChangeToken.objects.select_related("user").get(
            token=token_str,
            change_type=change_type,
        )

        if timezone.now() > token_obj.created_at + _expiration_for(change_type):
            token_obj.delete()
            raise ValueError("Token expirado.")

        return token_obj
    except (ProfileChangeToken.DoesNotExist, DjangoValidationError):
        raise ValueError("Token inválido.")


def get_password_reset_token(token_id: str, token_secret_hash: str) -> ProfileChangeToken:
    """
    Busca e valida token de reset de senha.

    Proteções:
      - Validação tripla: existência + hash do segredo + expiração.
      - Verificação de uso (used_at) — impede reutilização do link.
      - Mensagem GENÉRICA "Link inválido ou expirado" em TODAS as falhas
        (token inexistente, usado, expirado ou segredo errado). Isso impede
        que atacantes distingam entre os cenários (anti-enumeração).
    """
    try:
        token_obj = ProfileChangeToken.objects.select_related("user").get(
            token=token_id,
            change_type='password_reset',
        )
    except (ProfileChangeToken.DoesNotExist, DjangoValidationError):
        raise ValueError("Link inválido ou expirado.")

    # SEGURANÇA: Token já foi usado — impede replay attack
    if token_obj.used_at is not None:
        raise ValueError("Link inválido ou expirado.")

    # SEGURANÇA: Comparação do hash do segredo (nunca compara texto plano)
    if token_obj.token_hash != token_secret_hash:
        raise ValueError("Link inválido ou expirado.")

    # SEGURANÇA: Verificação de expiração (30 min por padrão)
    if timezone.now() > token_obj.created_at + _expiration_for('password_reset'):
        raise ValueError("Link inválido ou expirado.")

    return token_obj
