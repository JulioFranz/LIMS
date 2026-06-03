import { type ReactNode } from 'react'
import { Link } from 'react-router-dom'

interface LayoutProps {
  children: ReactNode
  nav?: ReactNode
}

function getUsername(): string | null {
  try {
    const token = sessionStorage.getItem('access_token')
    if (!token) return null
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')))
    return payload.username || payload.user_id || null
  } catch {
    return null
  }
}

export default function Layout({ children, nav }: LayoutProps) {
  const username = getUsername()

  return (
    <>
      <header>
        <Link to="/dashboard" className="brand">LIMS</Link>
        <nav style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          {nav}
            <Link
              to="/my-data"
              title={`Meus dados`}
              style={{
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
                textDecoration: 'none',
                flexShrink: 0,
                transition: 'opacity .15s',
              }}
              onMouseEnter={e => (e.currentTarget.style.opacity = '0.85')}
              onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
            >
              {String(username)[0].toUpperCase()}
            </Link>
        </nav>
      </header>
      <main>{children}</main>
      <footer>&copy; 2026 LIMS</footer>
    </>
  )
}
