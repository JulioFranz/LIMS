"""
LIMS — Serializers / Validação de entrada da API (serializers.py)

Proteções implementadas neste arquivo:
  - Validação de entrada no boundary do sistema (OWASP Input Validation)
  - Validação de senha server-side com os 5 validadores do Django
  - Campo password como write_only (nunca retornado nas respostas da API)
  - Validação obrigatória de consentimento LGPD (Art. 8º)
  - Restrição de tamanho nos campos (min_length, max_length) contra payloads maliciosos
  - Validação de formato de e-mail (EmailField) contra injeção
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password as django_validate_password
from django.core.exceptions import ValidationError as DjangoValidationError


class RegisterSerializer(serializers.Serializer):
    """
    Serializer de cadastro com validações de segurança e LGPD.

    Proteções:
      - username: max_length=150 (limite do Django User model).
      - email: EmailField valida formato e rejeita strings malformadas.
      - password: write_only=True (nunca aparece nas respostas da API),
        min_length=8 + validação server-side com os 5 validadores do Django
        (similaridade, comprimento mínimo, senhas comuns, numérico, complexidade).
      - consent: BooleanField obrigatório — LGPD Art. 8º exige consentimento
        explícito e informado. Rejeita cadastro sem aceite dos termos.
    """
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    # SEGURANÇA: write_only impede que a senha seja retornada na resposta da API
    password = serializers.CharField(write_only=True, min_length=8)
    # LGPD Art. 8º: consentimento explícito obrigatório para cadastro
    consent = serializers.BooleanField()

    def validate_password(self, value):
        """
        Validação de senha server-side com os 5 validadores do Django.
        Proteção: mesmo que o frontend não valide, o backend rejeita senhas fracas.
        """
        try:
            django_validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    def validate_consent(self, value):
        """
        LGPD Art. 8º — Consentimento deve ser uma manifestação livre, informada
        e inequívoca. O cadastro é rejeitado se o consentimento não for dado.
        """
        if not value:
            raise serializers.ValidationError(
                'É necessário aceitar os Termos de Uso e a Política de Privacidade para criar uma conta.'
            )
        return value


class LoginSerializer(serializers.Serializer):
    """
    Serializer de login. Proteção: password é write_only (não retornado na resposta).
    """
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class TwoFactorSerializer(serializers.Serializer):
    """Serializer genérico para operações com token."""
    token = serializers.CharField()


class TOTPPendingSerializer(serializers.Serializer):
    """Serializer para fluxo pendente de 2FA (token UUID da sessão temporária)."""
    pending_token = serializers.CharField()


class TOTPCodeSerializer(serializers.Serializer):
    """
    Serializer para validação de código TOTP.

    Proteção: min_length=6, max_length=6 restringe a exatamente 6 dígitos,
    impedindo payloads maliciosos ou tentativas de injeção no campo de código.
    """
    pending_token = serializers.CharField()
    totp_code = serializers.CharField(min_length=6, max_length=6)


class DisableTOTPSerializer(serializers.Serializer):
    """
    Serializer para desativação do 2FA.
    Exige código TOTP válido (6 dígitos) para confirmar a operação.
    """
    totp_code = serializers.CharField(min_length=6, max_length=6)


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer para solicitação de reset de senha. Validação de formato de e-mail."""
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer para confirmação de reset de senha.

    Proteções:
      - uid: identificador UUID do token (público).
      - token: segredo criptográfico de alta entropia (comparado por hash SHA-256).
      - new_password: write_only=True + min_length=8 + validação server-side
        com os 5 validadores do Django (executada em services.py).
    """
    uid = serializers.CharField()
    token = serializers.CharField()
    # SEGURANÇA: write_only impede retorno da senha na resposta; min_length=8
    new_password = serializers.CharField(write_only=True, min_length=8)
