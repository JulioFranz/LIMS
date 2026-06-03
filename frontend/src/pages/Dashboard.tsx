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
  const [alert] = useState({ message: '', type: 'error' as 'error' | 'success' })
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


  return (
    <Layout nav={<span style={{ color: '#c9d1e0', fontSize: '.9rem' }}>{}</span>}>

      <button
          type="button"
          className="btn btn-danger"
          onClick={handleLogout}
          disabled={loading}
          style={{
            position: 'fixed',
            bottom: '20px',
            left: '20px',
            zIndex: 1000,
            width: '300px',
            display: 'inline-block',
          }}
      >
        {loading ? 'Saindo…' : 'Sair'}
      </button>
    </Layout>
  )
}
