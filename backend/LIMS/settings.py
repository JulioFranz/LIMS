"""
LIMS — Configurações do Django (settings.py)

Este arquivo centraliza todas as configurações de segurança do projeto.
Cada bloco está documentado com a proteção que implementa, a norma/lei
correspondente e o impacto de sua remoção.

Proteções implementadas neste arquivo:
  - Secrets Management via variáveis de ambiente (ISO 27001 A.9 / OWASP)
  - Hashing de senhas com Argon2 (OWASP Password Storage)
  - Rate Limiting global e por escopo (OWASP API4:2023 - Unrestricted Resource Consumption)
  - Autenticação stateless via JWT com blacklist (OWASP API2:2023)
  - CORS restritivo com origens explícitas (OWASP - Misconfiguration)
  - HSTS, SSL redirect e headers de segurança HTTP (OWASP Transport Security)
  - Cookies seguros com HttpOnly, Secure e SameSite (OWASP Session Management)
  - Validação de senha em 5 camadas incluindo complexidade customizada
  - Trilha de auditoria estruturada com log rotativo (ISO 27001 A.12.4)
  - Proteção contra Clickjacking via X-Frame-Options DENY
  - CSRF habilitado com cookie seguro e trusted origins
"""

import os
from datetime import timedelta
from pathlib import Path
import dj_database_url


from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
os.makedirs(BASE_DIR / 'logs', exist_ok=True)

load_dotenv(BASE_DIR / '.env')

# =============================================================================
# SEGURANÇA: Secrets Management (ISO 27001 A.9 / OWASP Secrets Management)
# A SECRET_KEY é carregada exclusivamente de variável de ambiente.
# Nunca é hardcoded no código-fonte. O arquivo .env está no .gitignore.
# Impacto: a SECRET_KEY assina sessões Django, tokens JWT, checksums do
# AuditLog e cifras Fernet. Seu vazamento compromete TODO o sistema.
# =============================================================================
SECRET_KEY = os.environ['SECRET_KEY']

DEBUG = os.getenv('DEBUG', 'False') == 'True'

ALLOWED_HOSTS = [h for h in os.getenv('ALLOWED_HOSTS', '').split(',') if h]

RENDER_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
if RENDER_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_HOSTNAME)
    # SEGURANÇA: CSRF Trusted Origins — apenas o domínio de deploy é aceito
    # como origem confiável para requests POST com cookie CSRF.
    CSRF_TRUSTED_ORIGINS = [f'https://{RENDER_HOSTNAME}']

FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5173')

# =============================================================================
# SEGURANÇA: CORS — Cross-Origin Resource Sharing (OWASP - Security Misconfiguration)
# Em produção (DEBUG=False), CORS_ALLOW_ALL_ORIGINS é False.
# Apenas as origens listadas em CORS_ALLOWED_ORIGINS podem acessar a API,
# impedindo que domínios maliciosos façam requisições cross-origin.
# =============================================================================
CORS_ALLOWED_ORIGINS = list(filter(None, [
    'http://localhost:5173',
    os.getenv('FRONTEND_URL'),
]))
CORS_ALLOW_ALL_ORIGINS = DEBUG

# =============================================================================
# SEGURANÇA: Hashing de Senhas com Argon2 (OWASP Password Storage Cheat Sheet)
# Argon2 é o algoritmo vencedor do Password Hashing Competition (PHC, 2015).
# É resistente a ataques de força-bruta em GPUs e ASICs por ser memory-hard.
# Os parâmetros (time_cost, memory_cost, parallelism) estão configurados
# em LIMS/hashers.py. O fallback PBKDF2 existe para compatibilidade com
# hashes legados do Django, mas novas senhas sempre usam Argon2.
# =============================================================================
PASSWORD_HASHERS = [
    'LIMS.hashers.RenderArgon2Hasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]

# =============================================================================
# SEGURANÇA: Rate Limiting / Throttling (OWASP API4:2023 - Unrestricted Resource Consumption)
# Protege contra ataques de força-bruta, credential stuffing e DoS assimétrico.
#
# DEFAULT_THROTTLE_CLASSES: aplica throttle GLOBAL em todos os endpoints.
#   - AnonRateThrottle: limita requisições de usuários não autenticados (por IP).
#   - UserRateThrottle: limita requisições de usuários autenticados (por user ID).
#
# DEFAULT_THROTTLE_RATES:
#   - 'anon': 30 req/min — proteção global contra abuso de IPs anônimos.
#   - 'user': 120 req/min — limite para usuários autenticados.
#   - 'auth': 3 req/min — endpoints de autenticação (login, register, 2FA).
#     Valor baixo intencional: o Argon2 consome muita CPU/RAM por design,
#     então requisições massivas ao /login/ causariam DoS assimétrico.
#   - 'password_reset': 5 req/hora — impede enumeração de e-mails e spam.
# =============================================================================
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '30/minute',
        'user': '120/minute',
        'auth': '3/minute',
        'password_reset': '5/hour',
    }
}

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    # SEGURANÇA: Token Blacklist — permite invalidar refresh tokens no logout
    # e após reset de senha, impedindo reutilização de tokens comprometidos.
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'core',
    'users',
]

# =============================================================================
# SEGURANÇA: Middleware Stack — ordem importa para a cadeia de proteções
# SecurityMiddleware: força HTTPS, HSTS, X-Content-Type-Options
# CorsMiddleware: filtra origens cross-origin ANTES do processamento
# CsrfViewMiddleware: proteção contra Cross-Site Request Forgery
# XFrameOptionsMiddleware: impede embedding em iframes (Clickjacking)
# =============================================================================
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'LIMS.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates']
        ,
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'LIMS.wsgi.application'

# =============================================================================
# SEGURANÇA: Conexão com banco de dados — SSL obrigatório em produção
# ssl_require=True (quando DEBUG=False) força conexão criptografada com o
# PostgreSQL, protegendo dados em trânsito contra sniffing de rede.
# =============================================================================
DATABASES = {
    'default': dj_database_url.config(
        default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}",
        conn_max_age=600,
        ssl_require=not DEBUG,
    )
}

# =============================================================================
# SEGURANÇA: Validação de Senha em 5 Camadas (OWASP Authentication Cheat Sheet)
# 1. UserAttributeSimilarityValidator — rejeita senhas parecidas com username/email.
# 2. MinimumLengthValidator — exige mínimo de 8 caracteres.
# 3. CommonPasswordValidator — bloqueia as 20.000 senhas mais comuns (ex: "123456").
# 4. NumericPasswordValidator — rejeita senhas puramente numéricas.
# 5. PasswordComplexityValidator (customizado em users/validators.py) — exige
#    pelo menos 1 maiúscula, 1 número e 1 caractere especial.
# =============================================================================
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME': 'users.validators.PasswordComplexityValidator',
    },
]

# =============================================================================
# SEGURANÇA: JWT — Tokens de curta duração (OWASP Session Management)
# ACCESS_TOKEN_LIFETIME: 15 minutos — limita janela de exposição se roubado.
# REFRESH_TOKEN_LIFETIME: 1 dia — requer re-autenticação diária.
# BLACKLIST_AFTER_ROTATION: True — o refresh token antigo é invalidado ao
# gerar um novo, impedindo replay attacks com tokens rotacionados.
# =============================================================================
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'BLACKLIST_AFTER_ROTATION': True,
}

# =============================================================================
# SEGURANÇA: Trilha de Auditoria Estruturada (ISO 27001 A.12.4 / LGPD Art. 37)
# Dois loggers separados:
#   - 'users.audit': log de segurança com formato estruturado (evento, resultado,
#     user_id, email_hash, IP, user_agent). Grava em arquivo rotativo (5MB x 10).
#   - 'users': log operacional geral.
# O formato de auditoria permite parsing automatizado e integração com SIEM.
# Os e-mails são registrados como hash SHA-256 truncado (pseudonimização LGPD).
# =============================================================================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'audit': {
            'format': (
                '%(asctime)s %(levelname)s %(name)s '
                'event=%(event)s result=%(result)s '
                'user_id=%(user_id)s email_hash=%(email_hash)s '
                'ip=%(ip)s user_agent="%(user_agent)s"'
            ),
        },
        'simple': {
            'format': '%(asctime)s %(levelname)s %(name)s %(message)s',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'audit_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': str(BASE_DIR / 'logs' / 'audit.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 10,
            'formatter': 'audit',
        },
    },
    'loggers': {
        'users.audit': {
            'handlers': ['audit_file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
        'users': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# =============================================================================
# SEGURANÇA: Credenciais de e-mail via variáveis de ambiente
# Nenhuma credencial de e-mail é hardcoded. Todas vêm de variáveis de ambiente.
# =============================================================================
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.getenv('EMAIL_HOST', 'localhost')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True') == 'True'
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL','')
BREVO_API_KEY = os.getenv('BREVO_API_KEY')

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# =============================================================================
# SEGURANÇA: Transporte — SSL/TLS e HSTS (OWASP Transport Layer Security)
# SECURE_SSL_REDIRECT: redireciona HTTP → HTTPS em produção.
# SECURE_PROXY_SSL_HEADER: confia no header X-Forwarded-Proto do proxy reverso.
# HSTS (HTTP Strict Transport Security): força o navegador a usar HTTPS por
# 1 ano (31536000s), incluindo subdomínios, com preload no browser.
# Impede ataques de downgrade SSL e man-in-the-middle.
# =============================================================================
SECURE_SSL_REDIRECT = not DEBUG
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG

# =============================================================================
# SEGURANÇA: Cookies Seguros (OWASP Session Management Cheat Sheet)
# SESSION_COOKIE_SECURE / CSRF_COOKIE_SECURE: cookies só trafegam via HTTPS.
# SESSION_COOKIE_HTTPONLY / CSRF_COOKIE_HTTPONLY: impede acesso via JavaScript
#   (proteção contra XSS — mesmo se houver XSS, o atacante não lê o cookie).
# SESSION_COOKIE_SAMESITE='Lax': impede envio automático de cookies em
#   requisições cross-site (proteção contra CSRF).
# =============================================================================
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'

# =============================================================================
# SEGURANÇA: Headers HTTP de Proteção (OWASP Secure Headers)
# SECURE_CONTENT_TYPE_NOSNIFF: impede MIME-sniffing (X-Content-Type-Options: nosniff).
# SECURE_REFERRER_POLICY='same-origin': não vaza URLs internas em requests externos.
# X_FRAME_OPTIONS='DENY': bloqueia embedding em <iframe> (proteção contra Clickjacking).
# =============================================================================
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'
