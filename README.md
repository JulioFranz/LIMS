# LIMS

Sistema de autenticação com 2FA, recuperação de senha e cifragem de dados sensíveis. Projeto Integrador da disciplina de Políticas de Segurança da Informação.

**Demo:** https://lims-qvj6.onrender.com

## Configuração

Clone o repositório e crie o ambiente virtual:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Crie um arquivo `.env` na raiz do projeto:

```env
SECRET_KEY=sua-chave-secreta-aqui
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost

FIELD_ENCRYPTION_KEY=gere-com-o-comando-abaixo

EMAIL_HOST=smtp-relay.brevo.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=seu-usuario-smtp
EMAIL_HOST_PASSWORD=sua-senha-smtp
[email protected]
BREVO_API_KEY=sua-api-key-do-brevo
```

Para gerar a `FIELD_ENCRYPTION_KEY`:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Rode as migrations e inicie o servidor:

```bash
python manage.py migrate
python manage.py runserver
```

## Testes

```bash
python manage.py test users -v 2
```

## Autores

Julio Franz Moura  
Mauro Aparecido Gonçalves de Campos Junior
