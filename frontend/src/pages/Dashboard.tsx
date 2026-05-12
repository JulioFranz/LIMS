import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'
import Alert from '../components/Alert'
import Layout from '../components/Layout'

function parseJwt(token: string) {
  try {
    const payload = token.split('.')[1]
    return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')))
  } catch {
    return null
  }
}

function formatDate(ts: number) {
  return new Date(ts * 1000).toLocaleString('pt-BR')
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [alert, setAlert] = useState({ message: '', type: 'error' as 'error' | 'success' })
  const [loading, setLoading] = useState(false)
  const [payload, setPayload] = useState<Record<string, any> | null>(null)

  useEffect(() => {
    const accessToken = sessionStorage.getItem('access_token')
    if (!accessToken) {
      navigate('/')
      return
    }
    setPayload(parseJwt(accessToken))
  }, [navigate])

  async function handleLogout() {
    setLoading(true)
    const accessToken = sessionStorage.getItem('access_token')
    const refresh = sessionStorage.getItem('refresh_token')

    try {
      await api.post('/api/users/logout/', { refresh }, {
        headers: { Authorization: `Bearer ${accessToken}` },
      })
    } catch { /* ignora erros de rede no logout */ }

    sessionStorage.removeItem('access_token')
    sessionStorage.removeItem('refresh_token')
    navigate('/')
  }

  const navUser = payload ? (payload.username || payload.user_id || 'Usuário') : ''

  return (
    <Layout nav={<span style={{ color: '#c9d1e0', fontSize: '.9rem' }}>{navUser}</span>}>
      <div className="card" style={{ maxWidth: '520px' }}>
        <h1>Dashboard</h1>
        <Alert message={alert.message} type={alert.type} />
        {payload && (
          <div style={{ margin: '1.25rem 0', padding: '1rem', background: '#f8fafc', borderRadius: '8px', fontSize: '.9rem', lineHeight: '1.8' }}>
            <strong>Usuário:</strong> {payload.username || payload.user_id || '—'}<br />
            <strong>Token expira em:</strong> {payload.exp ? formatDate(payload.exp) : '—'}<br />
            <strong>Emitido em:</strong> {payload.iat ? formatDate(payload.iat) : '—'}
          </div>
        )}
        <button
          type="button"
          className="btn btn-danger"
          onClick={handleLogout}
          disabled={loading}
        >
          {loading ? 'Saindo…' : 'Sair'}
        </button>
      </div>
    </Layout>
  )
}
