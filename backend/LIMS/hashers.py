"""
LIMS — Hasher de senhas customizado (hashers.py)

Proteção: Hashing de senhas com Argon2id (OWASP Password Storage Cheat Sheet)

Argon2 é o algoritmo vencedor do Password Hashing Competition (PHC, 2015) e é
o padrão-ouro de resistência a ataques de força-bruta em GPUs e ASICs.
Diferente de bcrypt ou PBKDF2, o Argon2 é memory-hard: exige grande quantidade
de RAM para calcular cada hash, tornando ataques paralelos em hardware
especializado economicamente inviáveis.

Parâmetros configurados (otimizados para deploy em containers com recursos limitados):
  - time_cost=2: número de iterações do algoritmo.
  - memory_cost=19456 (19 MB): memória exigida por hash — impede paralelismo massivo.
  - parallelism=1: threads por operação de hash.

Impacto na segurança:
  - Cada tentativa de login custa ~19 MB de RAM + CPU, o que torna ataques de
    força-bruta extremamente caros.
  - ATENÇÃO: isso também significa que requisições massivas ao endpoint de login
    podem causar DoS assimétrico. Por isso, o Rate Limiting em settings.py
    limita o endpoint de auth a 3 req/min.
"""

from django.contrib.auth.hashers import Argon2PasswordHasher


class RenderArgon2Hasher(Argon2PasswordHasher):
    # Parâmetros de custo do Argon2 — tornam cada hash computacionalmente caro,
    # impedindo ataques de força-bruta e rainbow tables.
    time_cost = 2
    memory_cost = 19456
    parallelism = 1
