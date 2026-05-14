# LIMS

Sistema de autenticação com 2FA, recuperação de senha e cifragem de dados sensíveis. Projeto Integrador da disciplina de Políticas de Segurança da Informação.

**Demo:** https://lims-front.vercel.app/
Para a hospedagem, utilizamos a Vercel no Front-End e o Render no Back-End. Devido às limitações do plano gratuito do Render, o serviço entra em modo de repouso após períodos de inatividade. Por isso, a primeira requisição pode levar alguns minutos para ser processada enquanto a instância é reiniciada automaticamente.

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
DEFAULT_FROM_EMAIL=seu-email-do-brevo
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
