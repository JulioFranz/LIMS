import Layout from '../components/Layout'
import { Link } from 'react-router-dom'

export default function PrivacyPolicy() {
  return (
    <Layout>
      <div className="card" style={{ maxWidth: '640px', fontSize: '.9rem', lineHeight: '1.7', color: '#374151' }}>
        <h1 style={{ fontSize: '1.25rem', marginBottom: '0.25rem' }}>Política de Privacidade</h1>
        <p style={{ color: '#94a3b8', fontSize: '.8rem', marginBottom: '1.5rem' }}>Versão 1.0 — Junho de 2026 · Em conformidade com a LGPD (Lei 13.709/2018)</p>

        <h2 style={h2}>1. Responsável pelo tratamento</h2>
        <p>O sistema LIMS é operado para fins acadêmicos. Dúvidas sobre privacidade podem ser direcionadas ao responsável pelo projeto.</p>

        <h2 style={h2}>2. Dados pessoais coletados</h2>
        <p>Coletamos apenas os dados estritamente necessários:</p>
        <ul style={{ paddingLeft: '1.25rem', marginTop: '0.5rem' }}>
          <li><strong>Nome de usuário e e-mail</strong> — identificação e comunicação</li>
          <li><strong>Senha</strong> — armazenada como hash Argon2, não recuperável</li>
          <li><strong>Endereço IP e agente de usuário</strong> — apenas em eventos de segurança</li>
          <li><strong>Data de cadastro e último acesso</strong> — rastreabilidade da conta</li>
        </ul>

        <h2 style={h2}>3. Base legal (Art. 7º, LGPD)</h2>
        <p>Os dados são tratados com base em <strong>execução de contrato</strong> (Art. 7º, V) para os dados essenciais da conta, e <strong>legítimo interesse</strong> (Art. 7º, IX) para os dados de auditoria de segurança.</p>

        <h2 style={h2}>4. Compartilhamento</h2>
        <p>Nenhum dado pessoal é compartilhado com terceiros. O sistema utiliza o serviço Brevo apenas para envio de e-mails transacionais.</p>

        <h2 style={h2}>5. Retenção</h2>
        <p>Os dados são mantidos enquanto a conta estiver ativa. Após a exclusão da conta, os dados pessoais são removidos do banco de dados.</p>

        <h2 style={h2}>6. Seus direitos (Art. 18, LGPD)</h2>
        <p>Você tem direito a consultar, corrigir, exportar e solicitar a exclusão dos seus dados a qualquer momento. Acesse a página <strong>Meus dados</strong> após o login para exercer esses direitos.</p>

        <h2 style={h2}>7. Segurança</h2>
        <p>Comunicação protegida por TLS/HTTPS. Senhas com hash Argon2. Dados sensíveis cifrados com AES-128-CBC + HMAC-SHA256 (Fernet/cryptography). Chaves criptográficas em variáveis de ambiente, fora do código.</p>

        <p style={{ marginTop: '2rem' }}>
          <Link to="/register" style={{ color: '#3b82f6', fontSize: '.875rem' }}>← Voltar ao cadastro</Link>
        </p>
      </div>
    </Layout>
  )
}

const h2: React.CSSProperties = {
  fontSize: '.95rem', fontWeight: 600, color: '#1e293b', marginTop: '1.5rem', marginBottom: '0.25rem',
}
