import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'
import Layout from '../components/Layout'


export default function Dashboard() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const accessToken = sessionStorage.getItem('access_token')
    if (!accessToken) {
      navigate('/')
      return
    }
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
