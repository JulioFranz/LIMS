import axios, { AxiosError } from 'axios'
import type { AxiosRequestConfig } from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  withCredentials: true,
})

type RetriableConfig = AxiosRequestConfig & { _retry?: boolean }

const REFRESH_URL = '/api/users/token/refresh/'

let refreshing: Promise<void> | null = null

async function performRefresh(): Promise<void> {
  if (!refreshing) {
    refreshing = api
      .post(REFRESH_URL)
      .then(() => undefined)
      .finally(() => {
        refreshing = null
      })
  }
  return refreshing
}

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config as RetriableConfig | undefined
    const status = error.response?.status

    if (!original || status !== 401) {
      return Promise.reject(error)
    }

    // Não tenta refresh em chamadas que já são de refresh ou de login
    const url = original.url || ''
    if (original._retry || url.endsWith(REFRESH_URL) || url.includes('/login')) {
      return Promise.reject(error)
    }

    original._retry = true

    try {
      await performRefresh()
    } catch {
      // Refresh falhou — propaga o 401 original
      return Promise.reject(error)
    }

    return api(original)
  },
)

export default api
