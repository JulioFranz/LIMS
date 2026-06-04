/**
 * LIMS — Página de Cadastro (Register.tsx)
 *
 * Proteções de segurança e conformidade LGPD no frontend:
 *   - Consentimento LGPD obrigatório (Art. 8º): checkbox de aceite dos Termos de
 *     Uso e Política de Privacidade deve ser marcado antes do cadastro.
 *     Validado TANTO no frontend (UX) quanto no backend (serializer — segurança).
 *   - Links para Termos e Política em nova aba (target="_blank"): permite que
 *     o titular leia antes de consentir (consentimento informado).
 *   - autoComplete="new-password": incentiva o navegador a sugerir e salvar
 *     uma senha forte via gerenciador de senhas.
 *   - Validação de senha server-side: mesmo que o frontend não bloqueie, o
 *     backend valida com 5 validadores do Django e retorna erros detalhados.
 *   - Anti-enumeração: o backend retorna resposta idêntica se o e-mail já
 *     existe (envia e-mail ao titular real em vez de retornar erro).
 */
import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import Alert from '../components/Alert'
import Layout from '../components/Layout'

export default function Register() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [consent, setConsent] = useState(false)
  const [alert, setAlert] = useState({ message: '', type: 'error' as 'error' | 'success' })
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    // LGPD Art. 8º — Validação de consentimento no frontend (UX)
    if (!consent) {
      setAlert({ message: 'Você precisa aceitar os Termos de Uso e a Política de Privacidade para criar uma conta.', type: 'error' })
      return
    }
    setLoading(true)
    setAlert({ message: '', type: 'error' })

    try {
      await api.post('/api/users/register/', { username, email, password, consent })
      setAlert({ message: 'Conta criada! Redirecionando para verificação de e-mail…', type: 'success' })
      setTimeout(() => navigate('/verify-email'), 2000)
    } catch (err: any) {
      const data = err.response?.data
      const firstError = data ? (Object.values(data).flat()[0] as string) : null
      setAlert({ message: firstError || 'Erro ao criar conta.', type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Layout>
      <div className="card">
        <h1>Criar conta</h1>
        <Alert message={alert.message} type={alert.type} />
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Usuário</label>
            <input type="text" value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" required />
          </div>
          <div className="form-group">
            <label>E-mail</label>
            <input type="email" value={email} onChange={e => setEmail(e.target.value)} autoComplete="email" required />
          </div>
          <div className="form-group">
            <label>Senha</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="new-password" required />
          </div>

          {/* LGPD Art. 8º — Consentimento explícito com links para Termos e Política */}
          <div style={{
            display: 'flex', alignItems: 'flex-start', gap: '0.6rem',
            margin: '1rem 0 1.25rem', fontSize: '.875rem', color: '#374151',
          }}>
            <input
              id="consent"
              type="checkbox"
              checked={consent}
              onChange={e => setConsent(e.target.checked)}
              style={{ marginTop: '2px', cursor: 'pointer', flexShrink: 0 }}
              required
            />
            <label htmlFor="consent" style={{ cursor: 'pointer', lineHeight: '1.5' }}>
              Li e aceito os{' '}
              <Link to="/terms" target="_blank" style={{ color: '#3b82f6' }}>Termos de Uso</Link>
              {' '}e a{' '}
              <Link to="/privacy" target="_blank" style={{ color: '#3b82f6' }}>Política de Privacidade</Link>
            </label>
          </div>

          <button type="submit" disabled={loading}>{loading ? 'Criando…' : 'Criar conta'}</button>
        </form>
        <p className="text-muted text-center">
          Já tem conta? <Link to="/">Entrar</Link>
        </p>
      </div>
    </Layout>
  )
}
