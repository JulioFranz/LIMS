import { useState, useEffect } from 'react'
import { useNavigate, Link, useSearchParams } from 'react-router-dom'
import api from '../api/client'
import Alert from '../components/Alert'
import Layout from '../components/Layout'

export default function VerifyEmail() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const [token, setToken] = useState('')
  const [alert, setAlert] = useState({ message: '', type: 'error' as 'error' | 'success' })
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)

  useEffect(() => {
    const t = searchParams.get('token')
    if (t) setToken(t)
  }, [searchParams])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setAlert({ message: '', type: 'error' })

    try {
      await api.post('/api/users/verify-email/', { token: token.trim() })
      setAlert({ message: 'E-mail verificado com sucesso! Você já pode fazer login.', type: 'success' })
      setDone(true)
      setTimeout(() => navigate('/'), 2000)
    } catch (err: any) {
      const data = err.response?.data
      setAlert({ message: data?.detail || 'Token inválido ou expirado.', type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Layout>
      <div className="card">
        <h1>Verificar e-mail</h1>
        <p style={{ color: '#6b7280', fontSize: '.9rem', marginBottom: '1.25rem' }}>
          Verifique sua caixa de entrada. Você pode ter recebido o <strong>código de verificação</strong> para ativar sua conta, ou um <strong>e-mail informando que já existe uma conta</strong> cadastrada com esse endereço.
        </p>
        <Alert message={alert.message} type={alert.type} />
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Código de verificação</label>
            <input
              type="text"
              value={token}
              onChange={e => setToken(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="Cole o código aqui"
              required
            />
          </div>
          {!done && (
            <button type="submit" disabled={loading}>{loading ? 'Verificando…' : 'Verificar e-mail'}</button>
          )}
        </form>
        <p className="text-muted text-center">
          <Link to="/">Ir para o login</Link>
        </p>
      </div>
    </Layout>
  )
}
