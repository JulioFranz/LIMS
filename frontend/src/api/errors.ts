import axios from 'axios'

const MESSAGE_MAP: Array<{ match: RegExp; message: string }> = [
  { match: /at least 8 characters/i, message: 'A senha precisa ter pelo menos 8 caracteres.' },
  { match: /this password is too short/i, message: 'A senha precisa ter pelo menos 8 caracteres.' },
  { match: /this password is too common/i, message: 'Essa senha é muito comum. Escolha outra.' },
  { match: /this password is entirely numeric/i, message: 'A senha não pode conter apenas números.' },
  { match: /enter a valid email/i, message: 'Informe um e-mail válido.' },
  { match: /this field may not be blank/i, message: 'Este campo não pode ficar em branco.' },
  { match: /this field is required/i, message: 'Este campo é obrigatório.' },
  { match: /ensure this field has no more than (\d+) characters/i, message: 'Campo excede o tamanho máximo permitido.' },
  { match: /ensure this field has at least (\d+) characters/i, message: 'Campo abaixo do tamanho mínimo permitido.' },
  { match: /user with this email already exists/i, message: 'Já existe uma conta com este e-mail.' },
  { match: /user with this username already exists/i, message: 'Este nome de usuário já está em uso.' },
  { match: /invalid credentials/i, message: 'Credenciais inválidas.' },
]

function humanizeOne(raw: string, field?: string): string {
  for (const { match, message } of MESSAGE_MAP) {
    if (match.test(raw)) {
      if (field === 'password' || field === 'new_password') {
        if (/at least 8 characters|password is too short/i.test(raw)) {
          return 'A senha precisa ter pelo menos 8 caracteres.'
        }
      }
      return message
    }
  }
  return raw
}

function extractStrings(value: unknown): string[] {
  if (typeof value === 'string') return [value]
  if (Array.isArray(value)) return value.flatMap(extractStrings)
  if (value && typeof value === 'object') return Object.values(value).flatMap(extractStrings)
  return []
}

export function humanizeApiError(err: unknown, fallback = 'Ocorreu um erro. Tente novamente.'): string {
  if (!axios.isAxiosError(err)) return fallback

  if (err.response?.status === 429) {
    return 'Muitas tentativas. Aguarde um momento e tente novamente.'
  }

  const data = err.response?.data
  if (!data) return fallback

  if (typeof data === 'string') {
    return humanizeOne(data) || fallback
  }

  if (typeof data === 'object') {
    const obj = data as Record<string, unknown>

    if (typeof obj.detail === 'string') {
      return humanizeOne(obj.detail)
    }

    for (const [field, value] of Object.entries(obj)) {
      const strings = extractStrings(value)
      if (strings.length > 0) {
        return humanizeOne(strings[0], field)
      }
    }
  }

  return fallback
}
