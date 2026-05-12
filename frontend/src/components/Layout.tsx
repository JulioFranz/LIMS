import { ReactNode } from 'react'
import { Link } from 'react-router-dom'

interface LayoutProps {
  children: ReactNode
  nav?: ReactNode
}

export default function Layout({ children, nav }: LayoutProps) {
  return (
    <>
      <header>
        <Link to="/" className="brand">LIMS</Link>
        <nav>{nav}</nav>
      </header>
      <main>{children}</main>
      <footer>&copy; 2026 LIMS</footer>
    </>
  )
}
