/**
 * LIMS — Configuração inicial do 2FA / TOTP (Setup2FA.tsx)
 *
 * Proteções de segurança:
 *   - 2FA OBRIGATÓRIO: todo usuário é redirecionado para esta página no primeiro
 *     login. O JWT só é emitido após configurar E confirmar o 2FA.
 *   - Segredo TOTP gerado no backend com CSPRNG e cifrado com Fernet AES no banco.
 *   - QR Code renderizado localmente via QRCodeSVG (não envia dados para serviço externo).
 *   - Chave manual exibida apenas sob demanda (showSecret) — minimiza exposição.
 *   - pending_token verificado no mount: se não existir, redireciona para login
 *     (impede acesso direto à página sem autenticação prévia).
 *   - Confirmação exige código TOTP válido do app autenticador (validação backend).
 *   - JWT armazenado em sessionStorage após confirmação bem-sucedida.
 */
import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { QRCodeSVG } from 'qrcode.react'
import api from '../api/client'
import Alert from '../components/Alert'
import Layout from '../components/Layout'

export default function Setup2FA() {
  const navigate = useNavigate()
  const [qrUri, setQrUri] = useState('')
  const [secret, setSecret] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [showSecret, setShowSecret] = useState(false)
  const [alert, setAlert] = useState({ message: '', type: 'error' as 'error' | 'success' })
  const [loading, setLoading] = useState(false)
  const [fetching, setFetching] = useState(true)

  const pendingToken = sessionStorage.getItem('pending_token')

  useEffect(() => {
    // SEGURANÇA: Redireciona para login se não houver pending_token
    if (!pendingToken) {
      navigate('/')
      return
    }

    // Solicita QR Code e segredo TOTP ao backend
    api.post('/api/users/2fa/setup/', { pending_token: pendingToken })
      .then(res => {
        setQrUri(res.data.qr_uri)
        setSecret(res.data.secret)
      })
      .catch(() => navigate('/'))
      .finally(() => setFetching(false))
  }, [])

  async function handleConfirm(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setAlert({ message: '', type: 'error' })

    try {
      const res = await api.post('/api/users/2fa/setup/confirm/', {
        pending_token: pendingToken,
        totp_code: totpCode.trim(),
      })
      // SEGURANÇA: Limpa pending_token e armazena JWT em sessionStorage
      sessionStorage.removeItem('pending_token')
      sessionStorage.setItem('access_token', res.data.access)
      sessionStorage.setItem('refresh_token', res.data.refresh)
      navigate('/dashboard')
    } catch (err: any) {
      const data = err.response?.data
      setAlert({ message: data?.detail || 'Código inválido. Tente novamente.', type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  if (fetching) {
    return (
      <Layout>
        <div className="card">
          <p style={{ textAlign: 'center', color: '#6b7280' }}>Carregando…</p>
        </div>
      </Layout>
    )
  }

  return (
    <Layout>
      <div className="card">
        <h1>Configurar autenticador</h1>
        <p style={{ color: '#6b7280', fontSize: '.9rem', marginBottom: '1.25rem' }}>
          Escaneie o QR code com o <strong>Google Authenticator</strong> ou outro app TOTP.
          Depois, digite o código de 6 dígitos gerado pelo app para confirmar.
        </p>

        {/* SEGURANÇA: QR Code renderizado localmente (não envia dados para serviço externo) */}
        {qrUri && (
          <div style={{ display: 'flex', justifyContent: 'center', margin: '1.5rem 0' }}>
            <QRCodeSVG value={qrUri} size={200} />
          </div>
        )}

        <p
          style={{ fontSize: '.85rem', color: '#6b7280', textAlign: 'center', cursor: 'pointer', marginBottom: '1.5rem' }}
          onClick={() => setShowSecret(s => !s)}
        >
          {showSecret ? '▲ Ocultar chave manual' : '▼ Não consigo escanear o QR code'}
        </p>

        {showSecret && (
          <div style={{
            background: '#f3f4f6', borderRadius: '8px', padding: '0.75rem 1rem',
            fontFamily: 'monospace', fontSize: '.9rem', letterSpacing: '0.1em',
            textAlign: 'center', marginBottom: '1.5rem', wordBreak: 'break-all'
          }}>
            {secret}
          </div>
        )}

        <Alert message={alert.message} type={alert.type} />

        <form onSubmit={handleConfirm}>
          <div className="form-group">
            <label>Código de verificação</label>
            <input
              type="text"
              inputMode="numeric"
              value={totpCode}
              onChange={e => setTotpCode(e.target.value)}
              autoComplete="one-time-code"
              placeholder="000000"
              maxLength={6}
              required
            />
          </div>
          <button type="submit" disabled={loading || !qrUri}>
            {loading ? 'Ativando…' : 'Ativar autenticador'}
          </button>
        </form>

        <p className="text-muted text-center" style={{ marginTop: '1rem' }}>
          <Link to="/">Cancelar e voltar ao login</Link>
        </p>
      </div>
    </Layout>
  )
}
