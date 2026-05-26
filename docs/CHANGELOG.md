# Changelog

## 2026-05-26 — UX(frontend): translate and humanize backend validation errors, ensuring password length constraints are clear ("A senha precisa ter pelo menos 8 caracteres")

### Context
DRF returned raw English validation errors (e.g. `"Ensure this field has at least 8 characters."`) and the frontend forwarded them straight to `<Alert />`. Poor UX for PT-BR users.

### Changes

**New helper `frontend/src/api/errors.ts`**
- `humanizeApiError(err, fallback)` — centralizes Axios error parsing + PT-BR translation.
- Handles: 429 throttling, `{ detail }`, `{ non_field_errors: [...] }`, per-field arrays, nested objects.
- Regex map covers: password length (`at least 8 characters`, `password is too short`), common/numeric password policies, `enter a valid email`, `this field may not be blank`, `this field is required`, max-length, duplicate email/username, invalid credentials.
- Field-aware: when the offending field is `password` / `new_password` and message indicates min length, returns `"A senha precisa ter pelo menos 8 caracteres."` regardless of generic wording.

**Refactored catch blocks to a single call:**
- `frontend/src/pages/Login.tsx` — `setAlert({ message: humanizeApiError(err, 'Credenciais inválidas.'), type: 'error' })`
- `frontend/src/pages/Register.tsx` — `setAlert({ message: humanizeApiError(err, 'Erro ao criar conta.'), type: 'error' })`
- `frontend/src/pages/PasswordResetConfirm.tsx` — `setMessage(humanizeApiError(err, 'Não foi possível redefinir a senha.'))`

Removed direct `axios.isAxiosError` narrowing from these three pages — encapsulated in the helper.

### Mapping summary

| Backend (EN) | Frontend (PT-BR) |
|---|---|
| `Ensure this field has at least 8 characters.` | A senha precisa ter pelo menos 8 caracteres. |
| `This password is too short.` | A senha precisa ter pelo menos 8 caracteres. |
| `This password is too common.` | Essa senha é muito comum. Escolha outra. |
| `This password is entirely numeric.` | A senha não pode conter apenas números. |
| `Enter a valid email address.` | Informe um e-mail válido. |
| `This field may not be blank.` | Este campo não pode ficar em branco. |
| `This field is required.` | Este campo é obrigatório. |
| `User with this email already exists.` | Já existe uma conta com este e-mail. |
| `User with this username already exists.` | Este nome de usuário já está em uso. |
| HTTP 429 | Muitas tentativas. Aguarde um momento e tente novamente. |

### Verification
- `npm run lint` → exit 0.
- Raw EN strings no longer reach `<Alert />` on Login / Register / PasswordResetConfirm flows.

---

## 2026-05-26 — fix(frontend): resolve ESLint warnings and errors regarding explicit any, unused variables, and React hooks best practices

### Context
`npm run lint` reported 8 errors + 1 warning across 8 page files: explicit `any` in catch blocks, unused state setter, missing `useEffect` deps, and `setState` inside an effect.

### Changes

**Replaced `catch (err: any)` → `catch (err: unknown)` + `axios.isAxiosError` narrowing**
- `frontend/src/pages/Login.tsx`
- `frontend/src/pages/PasswordResetConfirm.tsx`
- `frontend/src/pages/PasswordResetRequest.tsx`
- `frontend/src/pages/Register.tsx`
- `frontend/src/pages/Verify2FA.tsx`
- `frontend/src/pages/VerifyEmail.tsx`

Added `import axios from 'axios'` in each of the above to access the `isAxiosError` type guard.

**`frontend/src/pages/Dashboard.tsx`** — `no-unused-vars`
- Dropped unused `setAlert` from `useState` destructure (`const [alert] = useState(...)`). Alert remains rendered as empty placeholder.

**`frontend/src/pages/Setup2FA.tsx`** — `react-hooks/exhaustive-deps`
- Added missing deps `navigate` and `pendingToken` to the `useEffect` array.

**`frontend/src/pages/VerifyEmail.tsx`** — `react-hooks/set-state-in-effect`
- Removed the `useEffect` that mirrored `searchParams` into state.
- Initialized `token` lazily from `searchParams` via `useState(() => searchParams.get('token') || '')`.
- Dropped unused `useEffect` import.

### Verification
- `npm run lint` → exit 0 (zero problems).

---

## 2026-05-26 — Fix Axios import error in Vite

### Context
Frontend crashed with white screen after HttpOnly cookie migration. Browser console:

```
Uncaught SyntaxError: The requested module '/node_modules/.vite/deps/axios.js?v=4a496ecd'
does not provide an export named 'InternalAxiosRequestConfig' (at client.ts:1:63)
```

Root cause: `InternalAxiosRequestConfig` is a type-only export. Imported as a value import, so Vite's `optimizeDeps` pre-bundle tried to resolve it at runtime and failed.

### Changes

**`frontend/src/api/client.ts`**
- Removed `InternalAxiosRequestConfig` from the value import.
- Kept `axios` default + `AxiosError` (runtime class, supported on axios `^1.16.0`).
- Added `import type { AxiosRequestConfig } from 'axios'` — type-only import, stripped at compile time, never reaches Vite runtime resolution.
- Retyped `RetriableConfig` as `AxiosRequestConfig & { _retry?: boolean }`.
- Preserved: `withCredentials: true`, refresh token flow, retry guard against refresh/login URLs.

### Diff

```diff
- import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios'
+ import axios, { AxiosError } from 'axios'
+ import type { AxiosRequestConfig } from 'axios'

  const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
    withCredentials: true,
  })

- type RetriableConfig = InternalAxiosRequestConfig & { _retry?: boolean }
+ type RetriableConfig = AxiosRequestConfig & { _retry?: boolean }
```

### Impact
- White screen resolved. Vite no longer fails to resolve the missing named export.
- Retry-on-401 logic unchanged.
- HttpOnly cookie flow (`withCredentials`) intact.
