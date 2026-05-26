# Arquitetura e Nível de Segurança (Security Posture)

Documento normativo das defesas do LIMS. Reflete o estado **após** a migração
para autenticação por cookie HttpOnly, throttling de TOTP e refresh automático
de JWT no cliente.

## 1. Nível de Segurança Atual

**Intermediário/Acadêmico (Nível 2)** — endereça as principais ameaças do
OWASP Top 10 com ênfase em **Quebra de Controle de Acesso** e **Falhas
Criptográficas**, agora com mitigação adicional contra **XSS exfiltrando
tokens** e **brute force de segundo fator**.

## 2. Camadas de Proteção

### 2.1 Armazenamento de Tokens — Cookies HttpOnly

**Antes:** `access_token` e `refresh_token` eram persistidos em
`sessionStorage`. Qualquer payload XSS (injeção de script em uma das telas)
era suficiente para exfiltrar as credenciais e clonar a sessão.

**Depois:** ambos os tokens são emitidos pelo backend como cookies
`HttpOnly`, com os seguintes atributos:

| Atributo | Valor padrão | Origem |
|---|---|---|
| `HttpOnly` | `True` | `users.views._set_auth_cookies` |
| `Secure` | `True` em produção, `False` em DEBUG | `AUTH_COOKIE_SECURE` |
| `SameSite` | `Strict` | `AUTH_COOKIE_SAMESITE` |
| `Max-Age (access)` | 15 min | `SIMPLE_JWT.ACCESS_TOKEN_LIFETIME` |
| `Max-Age (refresh)` | 1 dia | `SIMPLE_JWT.REFRESH_TOKEN_LIFETIME` |
| `Path` | `/` | hardcoded |

> **⚠️ Deploy cross-origin** (frontend em domínio diferente do backend, como
> Vercel + Render): `SameSite=Strict` impede o navegador de enviar o cookie.
> Nesse cenário, definir via env:
> ```
> AUTH_COOKIE_SAMESITE=None
> AUTH_COOKIE_SECURE=True
> ```
> e exigir HTTPS em todas as origens. Em produção same-site (subdomínio),
> manter `Strict` (default).

**Endpoints que **emitem** cookies de auth:**
- `POST /api/users/login/verify/`
- `POST /api/users/2fa/setup/confirm/`
- `POST /api/users/token/refresh/` (renovação)

**Endpoints que **limpam** cookies:**
- `POST /api/users/logout/` (também faz blacklist do refresh)

**Endpoints que **consomem** o cookie:**
- Toda view com `permission_classes = [IsAuthenticated]`. A leitura é feita
  pela classe `users.authentication.CookieJWTAuthentication`, registrada
  globalmente em `REST_FRAMEWORK.DEFAULT_AUTHENTICATION_CLASSES`.

### 2.2 Refresh Automático no Cliente — Interceptor Axios

`frontend/src/api/client.ts` configura `withCredentials: true` e um
interceptor de resposta que:

1. Detecta `401 Unauthorized`.
2. Em UMA única chamada concorrente (deduplicada pelo `Promise` cacheado em
   `refreshing`), invoca `POST /api/users/token/refresh/`.
3. Em sucesso, repete a requisição original (`original._retry`).
4. Em falha do refresh, propaga o 401 — UI redireciona para login.

Isso elimina:
- Necessidade de o frontend manipular cookies (não pode, são HttpOnly).
- Janelas de inconsistência entre access expirado e UX.
- Mais um ponto de manipulação de credenciais em código React.

**Trecho-chave:**
```ts
api.interceptors.response.use(r => r, async (error) => {
  const original = error.config as RetriableConfig
  if (error.response?.status !== 401 || original._retry) throw error
  original._retry = true
  await performRefresh()
  return api(original)
})
```

### 2.3 Throttling Anti–Brute Force

Adicionado escopo `totp` com taxa **5/min** por IP anônimo, aplicado em:

| View | Vetor mitigado |
|---|---|
| `Verify2FAView` | Brute force de 6 dígitos em sessão TOTP pendente |
| `Setup2FAView` | Esgotamento/replay de QR-setup |
| `ConfirmSetup2FAView` | Brute force durante a ativação |
| `Disable2FAView` | Brute force em sessão autenticada |

Junto aos escopos já existentes:

| Escopo | Taxa | Aplicado em |
|---|---|---|
| `auth` | 3/min | `LoginView` |
| `password_reset` | 5/hora | `PasswordResetRequest/Confirm` |
| `totp` | 5/min | TOTP/2FA |

### 2.4 CORS e Credenciais

- `CORS_ALLOW_ALL_ORIGINS = False` (sempre — cookies exigem origem explícita).
- `CORS_ALLOW_CREDENTIALS = True`.
- `CORS_ALLOWED_ORIGINS` deriva de env `FRONTEND_URL` + `localhost:5173`.

### 2.5 Endpoint `/me/`

Como JS não pode mais ler o JWT, o frontend obtém a identidade via
`GET /api/users/me/` (protegido por `IsAuthenticated`). Retorna apenas
`username` e `email` — nada que permita escalada se interceptado.

### 2.6 Logout Robusto

`POST /api/users/logout/`:
1. Lê `refresh_token` do cookie (ou do body, para compat).
2. Adiciona à blacklist do SimpleJWT (se possível).
3. Sempre limpa os cookies, mesmo se a blacklist falhar.

## 3. Diagrama do Fluxo Pós-Login

```
[Cliente]                       [Backend]
   │  POST /login/                │
   │ ───────────────────────────▶ │
   │  { pending_token, ... }      │
   │ ◀─────────────────────────── │
   │                              │
   │  POST /login/verify/         │
   │  + totp_code                 │
   │ ───────────────────────────▶ │
   │ Set-Cookie: access_token=…   │
   │ Set-Cookie: refresh_token=…  │
   │ ◀─────────────────────────── │
   │                              │
   │  GET /me/  (cookie auto)     │
   │ ───────────────────────────▶ │
   │  { username, email }         │
   │ ◀─────────────────────────── │
   │                              │
   │  ... access expira ...       │
   │                              │
   │  GET /qualquer-coisa         │
   │ ───────────────────────────▶ │
   │  401                         │
   │ ◀─────────────────────────── │
   │                              │
   │ [interceptor]                │
   │  POST /token/refresh/        │
   │ ───────────────────────────▶ │
   │ Set-Cookie: access_token=…   │
   │ ◀─────────────────────────── │
   │                              │
   │  GET /qualquer-coisa (retry) │
   │ ───────────────────────────▶ │
   │  200                         │
   │ ◀─────────────────────────── │
```

## 4. Riscos Conhecidos / Próximos Passos

- **CSRF:** com cookies em `SameSite=Strict`, risco baixo, mas para
  deployments cross-origin (`SameSite=None`) introduzir **double-submit
  cookie** ou cabeçalho `X-CSRF-Token`.
- **Rotação de refresh:** atualmente `ROTATE_REFRESH_TOKENS` está desligado.
  Ativar reduz a janela de comprometimento se o refresh vazar — exige
  `BLACKLIST_AFTER_ROTATION=True` (já presente).
- **`valid_window=2` no TOTP:** ainda aceita ±60s. Combinado com o novo
  throttle de 5/min, o espaço efetivo cai drasticamente, mas reduzir para
  `valid_window=1` é recomendado.
- **Log de TOTP em INFO** (`services.py:252`) — remover antes de produção.
- **`AuditLog` cobre apenas password_reset** — estender para `login_*`,
  `totp_*`, `register`, `logout`.
- **CSP ausente** — adicionar `django-csp` com `default-src 'self'`.
- **Sem `User.email unique=True`** — migrar para User custom.

## 5. Checklist Pré-Produção

- [ ] `AUTH_COOKIE_SECURE=True` em produção.
- [ ] `AUTH_COOKIE_SAMESITE` apropriado ao deploy.
- [ ] `DEBUG=False` em produção (força `SECURE_SSL_REDIRECT`, HSTS, cookies seguros).
- [ ] `FRONTEND_URL` setado e único.
- [ ] `FIELD_ENCRYPTION_KEY` gerada por ambiente e nunca commitada.
- [ ] `SECRET_KEY` rotacionada e armazenada em segredo.
- [ ] Log de TOTP em DEBUG-only.
- [ ] Bandit + pip-audit no CI.
- [ ] Verificar que `node_modules` não vai para a imagem e que `.env` está no `.gitignore`.
