/**
 * LIMS — Solicitação de recuperação de senha (PasswordResetRequest.tsx)
 *
 * Proteções de segurança:
 *   - Anti-enumeração de e-mail: o backend retorna SEMPRE a mesma mensagem
 *     genérica, independente de o e-mail existir ou não. Isso impede que
 *     atacantes descubram quais e-mails estão cadastrados no sistema.
 *   - Rate Limiting: endpoint limitado a 5 req/hora (PasswordResetThrottle).
 *     O frontend trata HTTP 429 com mensagem amigável.
 *   - O link de reset é enviado por e-mail, nunca exibido no frontend.
 *   - O token de reset expira em 30 minutos (configurável no backend).
 */
import { useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../api/client'
import Layout from '../components/Layout'

export default function PasswordResetRequest() {
  const [email, setEmail] = useState('')
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setMessage('Enviando...')

    try {
      const res = await api.post('/api/users/password-reset/', { email })
      setMessage(res.data?.detail || 'Solicitação recebida.')
      setEmail('')
    } catch (err: any) {
      // SEGURANÇA: Tratamento de Rate Limit (HTTP 429)
      if (err.response?.status === 429) {
        setMessage('Muitas solicitações. Tente novamente mais tarde.')
      } else {
        setMessage('Erro ao processar a solicitação. Tente novamente.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <Layout>
      <div className="card">
        <h1>Recuperar senha</h1>
        <p style={{ color: '#6b7280', fontSize: '.9rem', marginBottom: '1.25rem' }}>
          Informe o e-mail cadastrado. Se houver uma conta associada, enviaremos um link para redefinição de senha.
        </p>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>E-mail</label>
            <input type="email" value={email} onChange={e => setEmail(e.target.value)} autoComplete="email" required />
          </div>
          <button type="submit" disabled={loading}>Enviar link de recuperação</button>
        </form>
        {message && <p style={{ marginTop: '1rem', fontSize: '.9rem', color: '#374151' }}>{message}</p>}
        <p className="text-muted text-center">
          <Link to="/">Voltar ao login</Link>
        </p>
      </div>
    </Layout>
  )
}
