"""
LIMS — Modelos de dados do módulo de usuários (models.py)

Proteções implementadas neste arquivo:
  - Privacy by Design com campos de consentimento LGPD (Art. 7º, 8º e 11)
  - Armazenamento cifrado do segredo TOTP (via crypto.py / Fernet AES)
  - Tokens de uso único com hash SHA-256 (impede reutilização e leitura do segredo)
  - Trilha de auditoria com checksum HMAC-SHA256 anti-tampering (ISO 27001 A.12.4)
  - Pseudonimização de e-mails nos logs via hash truncado (LGPD Art. 13, §4º)
"""

from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    """
    Perfil estendido do usuário.

    Proteções:
      - is_verified: garante que o e-mail foi confirmado antes de permitir login
        (proteção contra cadastro com e-mail de terceiros).
      - totp_enabled / totp_secret: implementação de MFA/2FA via TOTP (RFC 6238).
        O totp_secret é armazenado CIFRADO com Fernet AES (via crypto.py),
        de modo que mesmo com acesso direto ao banco, o segredo não pode ser lido.
      - consent_accepted_at / consent_version: registro de consentimento LGPD
        (Art. 8º) com timestamp e versão, implementando Privacy by Design.
        Permite auditoria de quando e qual versão dos termos o titular aceitou.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    # SEGURANÇA: Verificação de e-mail — impede uso do sistema sem confirmação de titularidade
    is_verified = models.BooleanField(default=False)
    # SEGURANÇA: MFA/2FA — autenticação de dois fatores via TOTP (Google Authenticator)
    totp_enabled = models.BooleanField(default=False)
    # SEGURANÇA: Segredo TOTP cifrado com Fernet AES (crypto.py) — dados sensíveis em repouso
    totp_secret = models.CharField(max_length=512, blank=True, default='')
    # LGPD: Registro de consentimento com timestamp e versão (Art. 8º - Privacy by Design)
    consent_accepted_at = models.DateTimeField(null=True, blank=True)
    consent_version = models.CharField(max_length=20, blank=True, default='')

    def __str__(self):
        return f"Profile of {self.user.username}"


class ProfileChangeToken(models.Model):
    """
    Token de uso único para operações sensíveis (verificação de e-mail, reset
    de senha, login 2FA, setup TOTP).

    Proteções:
      - token (UUID): identificador público do token, usado na URL ou payload.
      - token_hash (SHA-256): o segredo real nunca é armazenado em texto plano.
        Apenas o hash é salvo no banco. Na verificação, o sistema calcula o hash
        do segredo enviado pelo usuário e compara com o armazenado (mesma lógica
        usada para senhas). Isso impede que um dump do banco revele segredos.
      - new_value: quando contém dados sensíveis (ex: segredo TOTP), é cifrado
        com Fernet AES via crypto.py antes do armazenamento.
      - used_at: marca tokens já utilizados, impedindo reutilização (replay attack).
      - created_at: usado para validar expiração (TTL variável por tipo de operação,
        configurado em selectors.py).
    """
    CHANGE_TYPES = [
        ('email', 'Email'),
        ('email_new', 'Email New'),
        ('password', 'Password'),
        ('verify', 'Verify'),
        ('2fa_login', '2FA Login'),
        ('password_reset', 'Password Reset'),
        ('totp_pending', 'TOTP Pending Login'),
        ('totp_setup_pending', 'TOTP Setup Pending'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='change_tokens')
    # SEGURANÇA: UUID aleatório como identificador público (não previsível / não sequencial)
    token = models.UUIDField(unique=True)
    change_type = models.CharField(max_length=20, choices=CHANGE_TYPES)
    # SEGURANÇA: Valor cifrado com Fernet quando contém dados sensíveis (ex: segredo TOTP)
    new_value = models.CharField(max_length=512, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # SEGURANÇA: Hash SHA-256 do segredo — o segredo real nunca fica no banco em texto plano
    token_hash = models.CharField(max_length=64, blank=True, default='')
    # SEGURANÇA: Marca token como usado — impede reutilização (replay attack prevention)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'change_type']),
        ]

    def __str__(self):
        return f"{self.user.username} — {self.change_type} token"

class AuditLog(models.Model):
    """
    Trilha de auditoria com proteção anti-tampering (ISO 27001 A.12.4).

    Proteções:
      - checksum (HMAC-SHA256): cada registro de auditoria recebe um checksum
        calculado com HMAC-SHA256 usando a SECRET_KEY do sistema. Se qualquer
        campo do log for alterado diretamente no banco de dados (ex: um atacante
        que ganhou acesso ao DB tenta apagar rastros), o checksum não baterá,
        denunciando a adulteração. Garante Non-Repudiation e imunidade a tampering.
      - email_hash: o e-mail do usuário é armazenado como hash SHA-256 truncado
        (16 chars), não em texto plano. Isso é pseudonimização conforme LGPD
        Art. 13, §4º — permite correlacionar eventos do mesmo titular sem expor
        o dado pessoal nos logs.
      - ip / user_agent: registrados para rastreabilidade de incidentes de segurança,
        conforme base legal de legítimo interesse (LGPD Art. 7º, IX).
      - user SET_NULL: se o usuário for deletado (direito ao esquecimento LGPD),
        o log mantém o registro do evento mas perde a referência ao titular.
    """
    EVENTS = [
        ('password_reset_requested', 'Password Reset Requested'),
        ('password_reset_confirmed', 'Password Reset Confirmed'),
        ('account_deleted', 'Account Deleted'),
        ('login_failed', 'Login Failed'),
        ('totp_login_success', 'TOTP Login Success'),
        ('totp_login_failed', 'TOTP Login Failed'),
        ('totp_setup_complete', 'TOTP Setup Complete'),
    ]
    RESULTS = [
        ('email_sent', 'Email Sent'),
        ('no_user', 'No User'),
        ('email_send_failed', 'Email Send Failed'),
        ('success', 'Success'),
        ('token_not_found', 'Token Not Found'),
        ('token_already_used', 'Token Already Used'),
        ('invalid_secret', 'Invalid Secret'),
        ('token_expired', 'Token Expired'),
        ('weak_password', 'Weak Password'),
        ('invalid_credentials', 'Invalid Credentials'),
        ('failed', 'Failed'),
    ]

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    event = models.CharField(max_length=64, choices=EVENTS, db_index=True)
    result = models.CharField(max_length=32, choices=RESULTS)
    # SEGURANÇA: SET_NULL — se o user for deletado (LGPD), o log mantém o evento sem PII
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='audit_logs',
    )
    # LGPD: Hash truncado do e-mail (pseudonimização) — permite correlação sem expor dado pessoal
    email_hash = models.CharField(max_length=32, blank=True, default='')
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=200, blank=True, default='')
    # SEGURANÇA: HMAC-SHA256 checksum anti-tampering — detecta adulteração direta no banco
    checksum = models.CharField(max_length=64, blank=True, default='')

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['event', 'result']),
            models.Index(fields=['-created_at']),
        ]

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} {self.event} {self.result}"
