import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'
import Alert from '../components/Alert'
import Layout from '../components/Layout'

type Me = { username: string; email: string }

export default function Dashboard() {
  const navigate = useNavigate()
  const [alert] = useState({ message: '', type: 'error' as 'error' | 'success' })
  const [loading, setLoading] = useState(false)
  const [me, setMe] = useState<Me | null>(null)

  useEffect(() => {
    api.get<Me>('/api/users/me/')
      .then(res => setMe(res.data))
      .catch(() => navigate('/'))
  }, [navigate])

  async function handleLogout() {
    setLoading(true)
    try {
      await api.post('/api/users/logout/')
    } catch { /* cookie será limpo pelo backend ainda em caso de erro */ }
    navigate('/')
  }

  const navUser = me ? me.username : ''

  return (
    <Layout nav={<span style={{ color: '#c9d1e0', fontSize: '.9rem' }}>{navUser}</span>}>
      <div className="card" style={{ maxWidth: '520px' }}>
        <h1>Dashboard</h1>
        <Alert message={alert.message} type={alert.type} />
        {me && (
          <div style={{ margin: '1.25rem 0', padding: '1rem', background: '#f8fafc', borderRadius: '8px', fontSize: '.9rem', lineHeight: '1.8' }}>
            <strong>Usuário:</strong> {me.username}<br />
            <strong>E-mail:</strong> {me.email}
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
