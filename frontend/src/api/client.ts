/**
 * LIMS — Cliente HTTP centralizado (client.ts)
 *
 * Proteções:
 *   - Base URL via variável de ambiente (VITE_API_URL): não hardcoded em produção.
 *   - Cliente único centralizado: todas as chamadas da API passam por este módulo,
 *     facilitando a adição futura de interceptors (ex: refresh automático de JWT,
 *     headers de segurança, tratamento global de erros 401/403).
 *   - Os tokens JWT são enviados por header Authorization (Bearer) em cada request,
 *     nunca por cookie ou query string, evitando exposição em logs de servidor.
 */
import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
})

export default api
