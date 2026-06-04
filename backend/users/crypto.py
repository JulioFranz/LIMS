"""
LIMS — Módulo de criptografia simétrica (crypto.py)

Proteção: Criptografia de dados sensíveis em repouso (At-Rest Encryption)
Norma: ISO 27001 A.10.1 / LGPD Art. 46 / OWASP Cryptographic Storage

Este módulo implementa criptografia simétrica usando Fernet (da biblioteca
'cryptography') para proteger campos sensíveis armazenados no banco de dados,
como o segredo TOTP do 2FA e valores de tokens de mudança de perfil.

Algoritmo Fernet:
  - Cifra: AES-128 em modo CBC (confidencialidade).
  - Autenticação: HMAC-SHA256 (integridade — detecta adulteração do ciphertext).
  - IV aleatório por operação (impede ataques de padrão em textos iguais).
  - Timestamp embutido (permite verificar idade do ciphertext se necessário).

A chave de criptografia (FIELD_ENCRYPTION_KEY) é carregada exclusivamente de
variável de ambiente, nunca hardcoded. Ela é independente da SECRET_KEY do
Django, de modo que o comprometimento de uma não compromete a outra.
"""

import os
from cryptography.fernet import Fernet, InvalidToken


def _get_fernet() -> Fernet:
    """
    Carrega a chave Fernet da variável de ambiente FIELD_ENCRYPTION_KEY.

    Proteção: Secrets Management — a chave nunca está no código-fonte.
    A chave deve ser gerada com Fernet.generate_key() e armazenada de forma
    segura (variável de ambiente, AWS KMS, Hashicorp Vault, etc.).
    """
    key = os.environ.get("FIELD_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "FIELD_ENCRYPTION_KEY não configurada. "
            "Gere uma com: python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode())

def encrypt_value(plaintext: str) -> str:
    """
    Cifra um valor em texto plano para armazenamento seguro no banco de dados.

    Proteção: Confidencialidade de dados em repouso (LGPD Art. 46).
    Usado para cifrar: segredo TOTP (totp_secret), valores de tokens de mudança.
    Mesmo que o banco de dados seja comprometido, os dados cifrados são
    ilegíveis sem a FIELD_ENCRYPTION_KEY.
    """
    if not plaintext:
        return ""
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_value(ciphertext: str) -> str:
    """
    Decifra um valor previamente cifrado com encrypt_value().

    Proteção: Integridade — o Fernet verifica o HMAC antes de decifrar.
    Se o ciphertext foi adulterado no banco de dados, InvalidToken é levantado,
    impedindo que dados corrompidos sejam processados silenciosamente.
    """
    if not ciphertext:
        return ""
    try:
        return _get_fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken:
        raise ValueError("Falha ao decifrar: chave inválida ou dado corrompido.")
