import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import Alert from '../components/Alert'
import Layout from '../components/Layout'

export default function Verify2FA() {
  const navigate = useNavigate()
  const [token, setToken] = useState('')
  const [alert, setAlert] = useState({ message: '', type: 'error' as 'error' | 'success' })
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setAlert({ message: '', type: 'error' })

    const username = sessionStorage.getItem('2fa_username')
    const body: Record<string, string> = { token: token.trim() }
    if (username) body.username = username

    try {
      const res = await api.post('/api/users/login/verify/', body)
      sessionStorage.removeItem('2fa_username')
      sessionStorage.setItem('access_token', res.data.access)
      sessionStorage.setItem('refresh_token', res.data.refresh)
      navigate('/dashboard')
    } catch (err: any) {
      if (err.response) {
        const data = err.response.data
        setAlert({ message: data?.detail || data?.non_field_errors?.[0] || 'Código inválido ou expirado.', type: 'error' })
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
          Digite o código de 6 dígitos do seu aplicativo autenticador.
        </p>
        <Alert message={alert.message} type={alert.type} />
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Código 2FA</label>
            <input
              type="text"
              value={token}
              onChange={e => setToken(e.target.value)}
              autoComplete="one-time-code"
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
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
