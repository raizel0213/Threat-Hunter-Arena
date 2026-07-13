import { useEffect, useState } from 'react'
import { Folder, Loader2, AlertTriangle } from 'lucide-react'
import { api } from '../api/client'
import Stamp from '../components/Stamp'

const TIER_VARIANT = { 1: 'terminal', 2: 'dossier', 3: 'alert' }
const TIER_LOG_SOURCES = {
  auth_log: 'auth',
  dns_log: 'dns',
  process_log: 'process',
  firewall_log: 'firewall',
}

export default function CaseList({ onOpenCase }) {
  const [cases, setCases] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    api
      .listCases()
      .then(setCases)
      .catch((e) => setError(e.message))
  }, [])

  if (error) {
    return (
      <div className="flex items-center gap-2 text-alert text-sm font-mono p-6">
        <AlertTriangle size={16} />
        Could not reach the backend: {error}. Is uvicorn running on port 8000?
      </div>
    )
  }

  if (!cases) {
    return (
      <div className="flex items-center gap-2 text-bone-muted text-sm font-mono p-6">
        <Loader2 size={16} className="animate-spin" />
        loading case files...
      </div>
    )
  }

  return (
    <div className="max-w-6xl mx-auto px-6 py-10">
      <div className="mb-8">
        <h1 className="stamp text-3xl text-dossier mb-2">Open Case Files</h1>
        <p className="text-sm text-bone-muted font-body max-w-2xl">
          Each case is a synthetic intrusion built from real, schema-accurate logs.
          Find the indicators, reconstruct the attack chain, and write a detection
          rule that would have caught it.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {cases.map((c) => (
          <button
            key={c.case_id}
            onClick={() => onOpenCase(c.case_id)}
            className="text-left border border-ink-line bg-ink-panel rounded-lg p-5 hover:border-dossier/60 transition-colors group"
          >
            <div className="flex items-start justify-between mb-4">
              <Folder size={20} className="text-dossier-dim group-hover:text-dossier transition-colors" />
              <Stamp variant={TIER_VARIANT[c.difficulty]} size="sm">
                Tier {c.difficulty}
              </Stamp>
            </div>
            <h2 className="font-mono text-bone text-base mb-2">{c.title}</h2>
            <p className="text-[11px] font-mono text-bone-muted">
              {c.log_sources.map((s) => TIER_LOG_SOURCES[s] || s).join(' · ')}
            </p>
          </button>
        ))}
      </div>
    </div>
  )
}
