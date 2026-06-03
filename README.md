# LIMS

Sistema de autenticação com TOTP (Google Authenticator), recuperação de senha e cifragem de dados sensíveis em repouso. Projeto Integrador da disciplina de Políticas de Segurança da Informação.

**Demo:** https://lims-gules.vercel.app/

> A primeira requisição pode demorar alguns minutos, o back-end hospedado no Render entra em modo de repouso por inatividade.

---

## Estrutura

```
LIMS/
├── backend/        # Django + DRF
│   ├── manage.py
│   ├── requirements.txt
│   └── .env        ← você cria este arquivo
└── frontend/       # React + Vite + Tailwind
```

---

## Back-end

### 1. Ambiente virtual e dependências

Na raiz do repositório:

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/Mac
pip install -r backend/requirements.txt
```

### 2. Arquivo `.env`

Crie o arquivo `backend/.env` com o conteúdo abaixo:

```env
SECRET_KEY=sua-chave-secreta-aqui
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost
FRONTEND_URL=http://localhost:5173

# Banco de dados 
DATABASE_URL=postgres://postgres:sua-senha@localhost:5432/lims

# Cifragem de dados sensíveis 
FIELD_ENCRYPTION_KEY=gere-com-o-comando-abaixo

# E-mail 
BREVO_API_KEY=sua-api-key-do-brevo
DEFAULT_FROM_EMAIL=seu-email@exemplo.com
```

**Gerar `SECRET_KEY`:**

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

**Gerar `FIELD_ENCRYPTION_KEY`:**

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 3. Banco de dados

#### PostgreSQL (recomendado)

Instale o PostgreSQL, crie o banco e configure o `DATABASE_URL`:

```bash
CREATE DATABASE lims;
```

```env
DATABASE_URL=postgres://postgres:sua-senha@localhost:5432/lims
```

### 4. Migrations e servidor

Entre na pasta `backend` antes de rodar os comandos do Django:

```bash
cd backend
python manage.py migrate
python manage.py runserver
```

A API ficará disponível em `http://localhost:8000`.

### 5. Testes

```bash
cd backend
python manage.py test users -v 2
```

---

## Front-end

```bash
cd frontend
npm install
npm run dev
```

O app ficará disponível em `http://localhost:5173`.

---
