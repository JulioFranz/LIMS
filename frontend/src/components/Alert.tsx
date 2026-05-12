type AlertType = 'error' | 'success' | 'info'

interface AlertProps {
  message: string
  type: AlertType
}

export default function Alert({ message, type }: AlertProps) {
  if (!message) return null
  return <div className={`alert alert-${type}`}>{message}</div>
}
