import Layout from '../components/Layout'
import { Link } from 'react-router-dom'

export default function Terms() {
  return (
    <Layout>
      <div className="card" style={{ maxWidth: '640px', fontSize: '.9rem', lineHeight: '1.7', color: '#374151' }}>
        <h1 style={{ fontSize: '1.25rem', marginBottom: '0.25rem' }}>Termos de Uso</h1>
        <p style={{ color: '#94a3b8', fontSize: '.8rem', marginBottom: '1.5rem' }}>Versão 1.0 — Junho de 2026</p>

        <h2 style={h2}>1. Sobre o sistema</h2>
        <p>O LIMS é um sistema de autenticação desenvolvido como projeto acadêmico. Seu uso é restrito a fins de demonstração e avaliação.</p>

        <h2 style={h2}>2. Dados coletados</h2>
        <p>Para criar e manter sua conta, coletamos: nome de usuário, endereço de e-mail e senha (armazenada exclusivamente como hash criptográfico irreversível). Também registramos, em logs de segurança, o endereço IP e o agente de usuário das operações sensíveis.</p>

        <h2 style={h2}>3. Uso dos dados</h2>
        <p>Os dados são utilizados exclusivamente para: autenticação no sistema, envio de códigos de verificação e recuperação de senha, e registro de auditoria de segurança.</p>

        <h2 style={h2}>4. Seus direitos</h2>
        <p>Você pode consultar, exportar ou solicitar a exclusão dos seus dados a qualquer momento pela página <strong>Meus dados</strong>, acessível após o login.</p>

        <h2 style={h2}>5. Segurança</h2>
        <p>Toda a comunicação é protegida por TLS/HTTPS. Senhas são armazenadas com hash Argon2. Dados sensíveis são cifrados com AES-256.</p>

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
