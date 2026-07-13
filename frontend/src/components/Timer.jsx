import { useEffect, useState } from 'react'
import { Clock } from 'lucide-react'

export default function Timer({ startedAt, frozen }) {
  const [now, setNow] = useState(Date.now())

  useEffect(() => {
    if (frozen) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [frozen])

  const elapsedSeconds = Math.floor((now - startedAt) / 1000)
  const mins = Math.floor(elapsedSeconds / 60)
  const secs = elapsedSeconds % 60

  return (
    <div className="flex items-center gap-1.5 font-mono text-sm text-bone-muted">
      <Clock size={14} />
      {String(mins).padStart(2, '0')}:{String(secs).padStart(2, '0')}
    </div>
  )
}

export function getElapsedSeconds(startedAt) {
  return Math.floor((Date.now() - startedAt) / 1000)
}
