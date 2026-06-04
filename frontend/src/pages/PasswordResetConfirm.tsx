/**
 * LIMS — Confirmação de reset de senha (PasswordResetConfirm.tsx)
 *
 * Proteções de segurança:
 *   - Token de reset composto por uid (UUID público) + token (segredo de alta
 *     entropia de 64 bytes) na URL. O backend compara por hash SHA-256.
 *   - Validação de link na renderização: se uid ou token estiverem ausentes na
 *     URL, exibe mensagem de erro e link para solicitar novo reset (impede uso
 *     sem credenciais válidas).
 *   - Confirmação de senha no frontend: exige digitação idêntica nos dois campos
 *     antes de enviar ao backend (UX — a validação real é server-side).
 *   - autoComplete="new-password": incentiva gerenciadores de senha do navegador.
 *   - minLength=8: validação visual consistente com o backend (5 validadores Django).
 *   - Rate Limiting: endpoint limitado a 5 req/hora. Frontend trata HTTP 429.
 *   - Após reset bem-sucedido: TODAS as sessões JWT do usuário são invalidadas
 *     no backend (blacklist), forçando novo login.
 */
import { useState } from 'react'
import { useNavigate, Link, useSearchParams } from 'react-router-dom'
import api from '../api/client'
import Layout from '../components/Layout'

export default function PasswordResetConfirm() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const uid = searchParams.get('uid') || ''
  const token = searchParams.get('token') || ''

  const [newPassword, setNewPassword] = useState('')
  const [newPasswordConfirm, setNewPasswordConfirm] = useState('')
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()

    if (newPassword !== newPasswordConfirm) {
      setMessage('As senhas não coincidem.')
      return
    }

    setLoading(true)
    setMessage('Processando...')

    try {
      const res = await api.post('/api/users/password-reset/confirm/', { uid, token, new_password: newPassword })
      setMessage(res.data?.detail + ' Redirecionando para o login...')
      setTimeout(() => navigate('/'), 2500)
    } catch (err: any) {
      // SEGURANÇA: Tratamento de Rate Limit (HTTP 429)
      if (err.response?.status === 429) {
        setMessage('Muitas tentativas. Tente novamente mais tarde.')
      } else {
        setMessage(err.response?.data?.detail || 'Não foi possível redefinir a senha.')
      }
    } finally {
      setLoading(false)
    }
  }

  // SEGURANÇA: Valida presença de uid e token na URL antes de renderizar o formulário
  if (!uid || !token) {
    return (
      <Layout>
        <div className="card">
          <h1>Definir nova senha</h1>
          <p style={{ color: '#dc2626', fontSize: '.9rem' }}>
            Link inválido ou expirado.{' '}
            <Link to="/password-reset">Solicitar novo link</Link>.
          </p>
        </div>
      </Layout>
    )
  }

  return (
    <Layout>
      <div className="card">
        <h1>Definir nova senha</h1>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Nova senha</label>
            <input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} minLength={8} autoComplete="new-password" required />
          </div>
          <div className="form-group">
            <label>Confirme a nova senha</label>
            <input type="password" value={newPasswordConfirm} onChange={e => setNewPasswordConfirm(e.target.value)} minLength={8} autoComplete="new-password" required />
          </div>
          <button type="submit" disabled={loading}>Redefinir senha</button>
        </form>
        {message && <p style={{ marginTop: '1rem', fontSize: '.9rem', color: '#374151' }}>{message}</p>}
        <p className="text-muted text-center">
          <Link to="/">Voltar ao login</Link>
        </p>
      </div>
    </Layout>
  )
}
