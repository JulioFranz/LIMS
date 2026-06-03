import { useEffect, useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import Layout from '../components/Layout'
import Alert from '../components/Alert'

interface DadoPessoal {
  dado: string
  valor: string
  finalidade: string
  base_legal: string
}

interface EventoAuditoria {
  data: string
  evento: string
  resultado: string
  ip: string
  user_agent: string
}

interface MeResponse {
  titular: string
  dados_pessoais: DadoPessoal[]
  historico_auditoria: EventoAuditoria[]
}

function getVal(dados: DadoPessoal[], nome: string) {
  return dados.find(d => d.dado === nome)?.valor ?? '—'
}

function formatDate(iso: string) {
  if (!iso || iso === 'Nunca registrado') return 'Nunca registrado'
  return new Date(iso).toLocaleString('pt-BR', {
    day: '2-digit', month: 'long', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function formatEventLabel(evento: string, resultado: string) {
  if (evento === 'password_reset_requested') {
    if (resultado === 'success' || resultado === 'email_sent') return 'Solicitou recuperação de senha'
    return 'Tentativa de recuperação de senha'
  }
  if (evento === 'password_reset_confirmed') {
    if (resultado === 'success') return 'Redefiniu a senha com sucesso'
    return 'Tentativa de redefinição de senha falhou'
  }
  return evento
}

function isSuccess(resultado: string) {
  return resultado === 'success' || resultado === 'email_sent'
}

export default function MyData() {
  const navigate = useNavigate()
  const [data, setData] = useState<MeResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(0)
  const [isDeleting, setIsDeleting] = useState(false)
  const [alert, setAlert] = useState({ message: '', type: 'error' as 'error' | 'success' })

  const PER_PAGE = 3

  useEffect(() => {
    const access = sessionStorage.getItem('access_token')
    if (!access) { navigate('/'); return }

    api.get('/api/users/me/', { headers: { Authorization: `Bearer ${access}` } })
      .then(res => setData(res.data))
      .catch(() => navigate('/'))
      .finally(() => setLoading(false))
  }, [navigate])

  async function handleDeleteAccount() {
    if (!window.confirm('Tem certeza absoluta que deseja excluir sua conta e revogar seu consentimento? Todos os seus dados pessoais serão apagados permanentemente. Esta ação não pode ser desfeita.')) {
      return
    }

    setIsDeleting(true)
    setAlert({ message: '', type: 'error' })
    const access = sessionStorage.getItem('access_token')

    try {
      await api.delete('/api/users/me/', { headers: { Authorization: `Bearer ${access}` } })
      sessionStorage.removeItem('access_token')
      sessionStorage.removeItem('refresh_token')
      window.alert('Conta excluída com sucesso. Você será redirecionado para a página inicial.')
      navigate('/')
    } catch {
      setAlert({ message: 'Ocorreu um erro ao excluir sua conta. Tente novamente mais tarde.', type: 'error' })
      setIsDeleting(false)
    }
  }

  function handleExportData() {
    if (!data) return
    const jsonStr = JSON.stringify(data, null, 2)
    const blob = new Blob([jsonStr], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `dados_pessoais_${data.titular}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
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

  const d = data!
  const eventos = d.historico_auditoria
  const totalPages = Math.ceil(eventos.length / PER_PAGE)
  const visibleEventos = eventos.slice(page * PER_PAGE, page * PER_PAGE + PER_PAGE)

  const twoFA = getVal(d.dados_pessoais, 'Autenticação de dois fatores (2FA)')
  const emailVerified = getVal(d.dados_pessoais, 'E-mail verificado')

  return (
    <Layout>
      <div style={{ width: '100%', maxWidth: '1400px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.25rem', alignSelf: 'flex-start' }}>
        {alert.message && <Alert message={alert.message} type={alert.type} />}

        {/* Cabeçalho / Avatar */}
        <div style={{ ...cardStyle, textAlign: 'center', paddingTop: '2rem', paddingBottom: '2rem' }}>
          <div style={{
            width: '72px', height: '72px', borderRadius: '50%',
            background: 'linear-gradient(135deg, #3b82f6, #6366f1)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '1.75rem', color: '#fff', margin: '0 auto 1rem',
            fontWeight: 700,
          }}>
            {d.titular[0].toUpperCase()}
          </div>
          <h1 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#1e293b', margin: 0 }}>
            {d.titular}
          </h1>
          <p style={{ color: '#64748b', fontSize: '.875rem', marginTop: '0.25rem' }}>
            {getVal(d.dados_pessoais, 'Endereço de e-mail')}
          </p>
        </div>

        {/* Conta + Segurança lado a lado */}
        <div style={{ display: 'flex', gap: '1.25rem', alignItems: 'flex-start' }}>

          {/* Informações da conta */}
          <div style={{ ...cardStyle, flex: 1 }}>
            <h2 style={sectionTitle}>Sua conta</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
              <Row label="Usuário" value={getVal(d.dados_pessoais, 'Nome de usuário')} />
              <Row label="E-mail" value={getVal(d.dados_pessoais, 'Endereço de e-mail')} />
              <Row label="Membro desde" value={formatDate(getVal(d.dados_pessoais, 'Data de cadastro'))} />
              <Row label="Último acesso" value={formatDate(getVal(d.dados_pessoais, 'Último acesso'))} last />
            </div>
          </div>

          {/* Segurança */}
          <div style={{ ...cardStyle, flex: 1 }}>
            <h2 style={sectionTitle}>Segurança</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
              <Row
                label="E-mail verificado"
                value={emailVerified}
              />
              <Row
                label="Autenticação em dois fatores"
                value={twoFA}
              />
              <Row
                label="Senha"
                value="Protegida com Argon2"
                last
              />
            </div>
          </div>

        </div>

        {/* Histórico */}
        <div style={cardStyle}>
          <h2 style={sectionTitle}>Atividade recente</h2>
          {eventos.length === 0 ? (
            <p style={{ color: '#94a3b8', fontSize: '.875rem', padding: '0.5rem 0' }}>
              Nenhuma atividade registrada.
            </p>
          ) : (
            <>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {visibleEventos.map((e, i) => (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'flex-start', gap: '0.75rem',
                    paddingBottom: i < visibleEventos.length - 1 ? '0.75rem' : 0,
                    borderBottom: i < visibleEventos.length - 1 ? '1px solid #f1f5f9' : 'none',
                  }}>
                    <span style={{
                      width: '8px', height: '8px', borderRadius: '50%', marginTop: '6px', flexShrink: 0,
                      background: isSuccess(e.resultado) ? '#16a34a' : '#f59e0b',
                    }} />
                    <div style={{ flex: 1 }}>
                      <p style={{ margin: 0, fontSize: '.875rem', color: '#1e293b', fontWeight: 500 }}>
                        {formatEventLabel(e.evento, e.resultado)}
                      </p>
                      <p style={{ margin: '0.1rem 0 0', fontSize: '.78rem', color: '#94a3b8' }}>
                        {formatDate(e.data)} · IP: {e.ip}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
              {totalPages > 1 && (
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid #f1f5f9',
                }}>
                  <button
                    onClick={() => setPage(p => p - 1)}
                    disabled={page === 0}
                    style={paginBtn}
                  >
                    Anterior
                  </button>
                  <span style={{ fontSize: '.8rem', color: '#94a3b8' }}>
                    {page + 1} de {totalPages}
                  </span>
                  <button
                    onClick={() => setPage(p => p + 1)}
                    disabled={page >= totalPages - 1}
                    style={paginBtn}
                  >
                    Próxima
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        {/* Exportação de Dados */}
        <div style={cardStyle}>
          <h2 style={sectionTitle}>Exportar Dados</h2>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
            <div>
              <p style={{ margin: '0 0 0.5rem', fontWeight: 600, color: '#1e293b' }}>Baixar uma cópia dos seus dados</p>
              <p style={{ margin: 0, fontSize: '.875rem', color: '#64748b' }}>
                De acordo com o Art. 18, II da LGPD, você pode exportar um arquivo estruturado com todos os seus dados pessoais armazenados pelo sistema.
              </p>
            </div>
            <button
              onClick={handleExportData}
              style={{
                background: '#f8fafc', color: '#3b82f6', border: '1px solid #bfdbfe', borderRadius: '6px',
                padding: '0.6rem 1.25rem', fontSize: '.875rem', fontWeight: 600, cursor: 'pointer',
                whiteSpace: 'nowrap', transition: 'background 0.2s'
              }}
              onMouseEnter={e => e.currentTarget.style.background = '#eff6ff'}
              onMouseLeave={e => e.currentTarget.style.background = '#f8fafc'}
            >
              📥 Exportar (.json)
            </button>
          </div>
        </div>

        {/* Zona de Perigo - Exclusão de Conta */}
        <div style={{ ...cardStyle, border: '1px solid #fee2e2' }}>
          <h2 style={{ ...sectionTitle, color: '#ef4444' }}>Zona de Perigo</h2>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
            <div>
              <p style={{ margin: '0 0 0.5rem', fontWeight: 600, color: '#1e293b' }}>Excluir conta (Revogar consentimento)</p>
              <p style={{ margin: 0, fontSize: '.875rem', color: '#64748b' }}>
                De acordo com o Art. 8º, § 5º da LGPD, você pode revogar seu consentimento e excluir sua conta a qualquer momento.
                Todos os seus dados pessoais serão removidos permanentemente.
              </p>
            </div>
            <button
              onClick={handleDeleteAccount}
              disabled={isDeleting}
              style={{
                background: '#ef4444', color: '#fff', border: 'none', borderRadius: '6px',
                padding: '0.6rem 1.25rem', fontSize: '.875rem', fontWeight: 600, cursor: 'pointer',
                whiteSpace: 'nowrap'
              }}
            >
              {isDeleting ? 'Excluindo...' : 'Excluir minha conta'}
            </button>
          </div>
        </div>

        <p style={{ textAlign: 'center' }}>
          <Link to="/dashboard" style={{ color: '#64748b', fontSize: '.875rem', textDecoration: 'none' }}>
            Voltar ao início
          </Link>
        </p>
      </div>
    </Layout>
  )
}

/* ---------- Sub-componentes ---------- */

function Row({ label, value, badge, last }: {
  label: string
  value: string
  badge?: 'ok' | 'warn'
  last?: boolean
}) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0.75rem 0',
      borderBottom: last ? 'none' : '1px solid #f1f5f9',
      gap: '0.5rem',
    }}>
      <span style={{ color: '#64748b', fontSize: '.875rem' }}>{label}</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        {badge && (
          <span style={{
            padding: '0.15rem 0.55rem',
            borderRadius: '999px',
            fontSize: '.75rem',
            fontWeight: 600,
            background: badge === 'ok' ? '#dcfce7' : '#fef9c3',
            color: badge === 'ok' ? '#16a34a' : '#a16207',
          }}>
            {badge === 'ok' ? 'Ativo' : 'Atenção'}
          </span>
        )}
        <span style={{ fontSize: '.875rem', color: '#1e293b', fontWeight: 500, textAlign: 'right' }}>
          {value}
        </span>
      </div>
    </div>
  )
}

/* ---------- Estilos ---------- */

const cardStyle: React.CSSProperties = {
  background: '#fff',
  borderRadius: '12px',
  padding: '1.25rem 1.5rem',
  boxShadow: '0 1px 3px rgba(0,0,0,.08)',
  border: '1px solid #f1f5f9',
}

const sectionTitle: React.CSSProperties = {
  fontSize: '.7rem',
  fontWeight: 700,
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
  color: '#94a3b8',
  margin: '0 0 0.75rem',
}

const paginBtn: React.CSSProperties = {
  background: 'none',
  border: '1px solid #e2e8f0',
  borderRadius: '6px',
  padding: '0.3rem 0.85rem',
  fontSize: '.8rem',
  color: '#374151',
  cursor: 'pointer',
}
