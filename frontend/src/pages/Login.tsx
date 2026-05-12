import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import Alert from '../components/Alert'
import Layout from '../components/Layout'

export default function Login() {
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [alert, setAlert] = useState({ message: '', type: 'error' as 'error' | 'success' })
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setAlert({ message: '', type: 'error' })

    try {
      const res = await api.post('/api/users/login/', { email, password })
      const data = res.data

      if (data.totp_required) {
        sessionStorage.setItem('pending_token', data.pending_token)
        navigate('/verify-2fa')
        return
      }

      if (data.setup_required) {
        sessionStorage.setItem('pending_token', data.pending_token)
        navigate('/setup-2fa')
        return
      }
    } catch (err: any) {
      if (err.response?.status === 429) {
        setAlert({ message: 'Muitas tentativas. Aguarde um momento e tente novamente.', type: 'error' })
      } else {
        const data = err.response?.data
        setAlert({ message: data?.detail || data?.non_field_errors?.[0] || 'Credenciais inválidas.', type: 'error' })
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <Layout>
      <div className="card">
        <h1>Entrar</h1>
        <Alert message={alert.message} type={alert.type} />
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>E-mail</label>
            <input type="email" value={email} onChange={e => setEmail(e.target.value)} autoComplete="email" required />
          </div>
          <div className="form-group">
            <label>Senha</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" required />
          </div>
          <button type="submit" disabled={loading}>{loading ? 'Entrando…' : 'Entrar'}</button>
        </form>
        <p className="text-muted text-center">
          Não tem conta? <Link to="/register">Registrar</Link>
        </p>
        <p className="text-muted text-center">
          <Link to="/password-reset">Esqueci minha senha</Link>
        </p>
      </div>
    </Layout>
  )
}
