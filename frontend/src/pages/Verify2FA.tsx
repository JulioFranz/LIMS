import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import Alert from '../components/Alert'
import Layout from '../components/Layout'

export default function Verify2FA() {
  const navigate = useNavigate()
  const [totpCode, setTotpCode] = useState('')
  const [alert, setAlert] = useState({ message: '', type: 'error' as 'error' | 'success' })
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setAlert({ message: '', type: 'error' })

    const pending_token = sessionStorage.getItem('pending_token')

    try {
      const res = await api.post('/api/users/login/verify/', {
        pending_token,
        totp_code: totpCode.trim(),
      })
      sessionStorage.removeItem('pending_token')
      sessionStorage.setItem('access_token', res.data.access)
      sessionStorage.setItem('refresh_token', res.data.refresh)
      navigate('/dashboard')
    } catch (err: any) {
      if (err.response) {
        const data = err.response.data
        setAlert({ message: data?.detail || 'Código inválido ou expirado.', type: 'error' })
      } else {
        setAlert({ message: 'Erro de conexão. Verifique sua internet e tente novamente.', type: 'error' })
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <Layout>
      <div className="card">
        <h1>Autenticação em dois fatores</h1>
        <p style={{ color: '#6b7280', fontSize: '.9rem', marginBottom: '1.25rem' }}>
          Abra o Google Authenticator e digite o código de 6 dígitos.
        </p>
        <Alert message={alert.message} type={alert.type} />
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Código do autenticador</label>
            <input
              type="text"
              inputMode="numeric"
              value={totpCode}
              onChange={e => setTotpCode(e.target.value)}
              autoComplete="one-time-code"
              placeholder="000000"
              maxLength={6}
              required
            />
          </div>
          <button type="submit" disabled={loading}>{loading ? 'Verificando…' : 'Verificar'}</button>
        </form>
        <p className="text-muted text-center">
          <Link to="/">Voltar ao login</Link>
        </p>
      </div>
    </Layout>
  )
}
