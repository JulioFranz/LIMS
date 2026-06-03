import { useEffect, useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import Layout from '../components/Layout'

export default function Dashboard() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [loading, setLoading] = useState(true)
  const [logoutLoading, setLogoutLoading] = useState(false)

  useEffect(() => {
    const access = sessionStorage.getItem('access_token')
    if (!access) { navigate('/'); return }

    api.get('/api/users/me/', { headers: { Authorization: `Bearer ${access}` } })
      .then(res => setUsername(res.data.titular))
      .catch(() => navigate('/'))
      .finally(() => setLoading(false))
  }, [navigate])

  async function handleLogout() {
    setLogoutLoading(true)
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

  if (loading) {
    return (
      <Layout>
        <div style={cardStyle}>
          <p style={{ color: '#94a3b8', textAlign: 'center', padding: '2rem 0' }}>Carregando…</p>
        </div>
      </Layout>
    )
  }

  const initial = username[0]?.toUpperCase() ?? '?'

  const avatarNav = (
    <Link
      to="/my-data"
      style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', textDecoration: 'none' }}
    >
      {/* Anel + círculo + badge */}
      <div style={{ position: 'relative', flexShrink: 0 }}>
        <div style={{
          width: '42px',
          height: '42px',
          borderRadius: '50%',
          background: 'rgba(99, 102, 241, 0.4)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <div style={{
            width: '34px',
            height: '34px',
            borderRadius: '50%',
            background: 'linear-gradient(135deg, #3b82f6, #6366f1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#fff',
            fontWeight: 700,
            fontSize: '.9rem',
          }}>
            {initial}
          </div>
        </div>
        <div style={{
          position: 'absolute',
          bottom: '-1px',
          right: '-2px',
          width: '15px',
          height: '15px',
          borderRadius: '50%',
          background: '#fff',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '9px',
          boxShadow: '0 1px 4px rgba(0,0,0,0.25)',
        }}>
          ⚙
        </div>
      </div>
      <span style={{ fontSize: '.85rem', fontWeight: 600, color: '#c9d1e0' }}>
        Ver perfil
      </span>
    </Link>
  )

  return (
    <Layout nav={avatarNav}>
      <div style={{ width: '100%', maxWidth: '1400px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.25rem', alignSelf: 'flex-start' }}>

        {/* Saudação */}
        <div style={{ ...cardStyle, paddingTop: '2rem', paddingBottom: '2rem' }}>
          <h1 style={{ margin: 0, fontSize: '1.6rem', fontWeight: 700, color: '#1e293b' }}>
            Bem-vindo, {username}
          </h1>
          <p style={{ margin: '0.4rem 0 0', fontSize: '.9rem', color: '#94a3b8' }}>
            Painel de segurança da sua conta
          </p>
        </div>

      </div>

      <button
        type="button"
        className="btn btn-danger"
        onClick={handleLogout}
        disabled={logoutLoading}
        style={{
          position: 'fixed',
          bottom: '20px',
          left: '20px',
          zIndex: 1000,
          width: '300px',
          display: 'inline-block',
        }}
      >
        {logoutLoading ? 'Saindo…' : 'Sair'}
      </button>
    </Layout>
  )
}

const cardStyle: React.CSSProperties = {
  background: '#fff',
  borderRadius: '12px',
  padding: '1.25rem 1.5rem',
  boxShadow: '0 1px 3px rgba(0,0,0,.08)',
  border: '1px solid #f1f5f9',
}