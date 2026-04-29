"""
seed.py — insere no banco os dados de demonstração.

Como rodar:
    python manage.py shell < seed.py
    (Windows PowerShell: Get-Content seed.py | python manage.py shell)

Cria:
- Superuser admin (admin / Admin123!)
- 3 usuários de teste, todos verificados
- 1 token de email_new pendente (demonstra cifragem AES no new_value)
- 2 entradas de auditoria (demonstra a tabela AuditLog)

"""

from django.contrib.auth.models import User
from django.utils import timezone
from users.models import UserProfile, ProfileChangeToken, AuditLog
from users.services import _create_token, _hash_email

print("=" * 60)
print("Iniciando seed do banco de dados...")
print("=" * 60)

# 1. Superuser
if not User.objects.filter(username="admin").exists():
    admin = User.objects.create_superuser(
        username="admin",
        email="admin@lims.local",
        password="Admin123!",
    )
    UserProfile.objects.create(user=admin, is_verified=True)
    print(f"  [+] Superuser criado: admin / Admin123!")
else:
    print(f"  [=] Superuser admin já existe")

# 2. users de teste
usuarios_teste = [
    ("joao_silva", "joao@exemplo.com", "Senha123!"),
    ("maria_santos", "maria@exemplo.com", "Senha123!"),
    ("carlos_oliveira", "carlos@exemplo.com", "Senha123!"),
]

for username, email, senha in usuarios_teste:
    if not User.objects.filter(username=username).exists():
        user = User.objects.create_user(
            username=username,
            email=email,
            password=senha,
        )
        UserProfile.objects.create(user=user, is_verified=True)
        print(f"  [+] Usuário criado: {username} / {senha}")
    else:
        print(f"  [=] Usuário {username} já existe")

# 3. Token de mudanca de e-mail
joao = User.objects.get(username="joao_silva")
ProfileChangeToken.objects.filter(user=joao, change_type="email_new").delete()
secret = _create_token(joao, "email_new", new_value="joao.novo@exemplo.com")
print(f"  [+] Token email_new criado para joao_silva")
print(f"      (segredo em claro: {secret} — só seria enviado por e-mail)")
print(f"      (no banco fica apenas o hash SHA-256 + new_value cifrado AES)")

# 4. Entradas de auditoria
maria = User.objects.get(username="maria_santos")

AuditLog.objects.create(
    event="password_reset_requested",
    result="email_sent",
    user=maria,
    email_hash=_hash_email("maria@exemplo.com"),
    ip="192.168.1.100",
    user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
)

AuditLog.objects.create(
    event="password_reset_confirmed",
    result="success",
    user=maria,
    ip="192.168.1.100",
    user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
)

print(f"  [+] 2 entradas de AuditLog criadas (LGPD: e-mail hasheado)")

# Resumo
print("=" * 60)
print("Seed concluído!")
print("=" * 60)
print(f"  Total de usuários: {User.objects.count()}")
print(f"  Total de tokens ativos: {ProfileChangeToken.objects.count()}")
print(f"  Total de entradas de auditoria: {AuditLog.objects.count()}")
print()
print("Credenciais de teste:")
print("  admin / Admin123!  (superuser)")
print("  joao_silva / Senha123!")
print("  maria_santos / Senha123!")
print("  carlos_oliveira / Senha123!")
print()
print("Para inspecionar dados:")
print("  python manage.py dbshell")
print("  SELECT user_id, change_type, new_value, token_hash")
print("  FROM users_profilechangetoken WHERE new_value != '';")
print("=" * 60)