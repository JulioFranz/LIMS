"""
LIMS — Validador de complexidade de senha (validators.py)

Proteção: Política de senha forte (OWASP Authentication Cheat Sheet / NIST SP 800-63B)

Este validador é o 5º na cadeia de AUTH_PASSWORD_VALIDATORS do Django (settings.py).
Trabalha em conjunto com os 4 validadores nativos do Django:
  1. UserAttributeSimilarityValidator — rejeita senhas parecidas com username/email.
  2. MinimumLengthValidator — exige mínimo de 8 caracteres.
  3. CommonPasswordValidator — bloqueia as 20.000 senhas mais comuns.
  4. NumericPasswordValidator — rejeita senhas puramente numéricas.
  5. PasswordComplexityValidator (este) — exige composição mínima.

Regras de complexidade:
  - Pelo menos 1 letra maiúscula (A-Z).
  - Pelo menos 1 número (0-9).
  - Pelo menos 1 caractere especial (!@#$%^&*... etc).

Essas regras garantem entropia mínima mesmo em senhas de 8 caracteres,
dificultando ataques de dicionário e força-bruta.
"""

import re
from django.core.exceptions import ValidationError


class PasswordComplexityValidator:
    """
    Validador customizado que exige maiúscula, número e caractere especial.
    Registrado em settings.py AUTH_PASSWORD_VALIDATORS.
    """
    def validate(self, password, user=None):
        errors = []
        if not re.search(r'[A-Z]', password):
            errors.append("A senha deve conter pelo menos uma letra maiúscula.")
        if not re.search(r'[0-9]', password):
            errors.append("A senha deve conter pelo menos um número.")
        if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', password):
            errors.append("A senha deve conter pelo menos um caractere especial.")
        if errors:
            raise ValidationError(errors)

    def get_help_text(self):
        return (
            "A senha deve conter pelo menos uma letra maiúscula, "
            "um número e um caractere especial."
        )
