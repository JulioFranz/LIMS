# LIMS

## Configuração

Clone o repositório e crie o ambiente virtual:

```bash
python -m venv .venv
.venv/Scripts/activate
pip install -r requirements.txt
```

Crie um arquivo `.env` na raiz do projeto com as seguintes variáveis:

```env
SECRET_KEY=sua-chave-secreta-aqui

DEBUG=True

ALLOWED_HOSTS=

EMAIL_HOST=smtp-relay.brevo.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=seu-usuario-smtp
EMAIL_HOST_PASSWORD=sua-senha-smtp
DEFAULT_FROM_EMAIL=seu-email@dominio.com
```

Rode as migrations e inicie o servidor:

```bash
python manage.py migrate
python manage.py runserver
```
