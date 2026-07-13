import { useEffect, useState } from 'react'
import { Loader2, AlertTriangle, Target } from 'lucide-react'
import { api } from '../api/client'

export default function MitreHeatmap({ playerName }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    setData(null)
    api
      .mitreHeatmap(playerName)
      .then(setData)
      .catch((e) => setError(e.message))
  }, [playerName])

  return (
    <div className="max-w-4xl mx-auto px-6 py-10">
      <div className="flex items-center justify-between mb-2">
        <h1 className="stamp text-3xl text-dossier">ATT&CK Coverage</h1>
      </div>
      <p className="text-sm text-bone-muted font-mono mb-8">analyst: {playerName}</p>

      {error && (
        <div className="flex items-center gap-2 text-alert text-sm font-mono">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}

      {!data && !error && (
        <div className="flex items-center gap-2 text-bone-muted text-sm font-mono">
          <Loader2 size={16} className="animate-spin" />
          loading coverage...
        </div>
      )}

      {data && (
        <>
          <div className="flex items-center gap-4 mb-8 border border-ink-line rounded-lg bg-ink-panel px-5 py-4">
            <Target size={28} className="text-terminal" />
            <div>
              <p className="text-2xl font-mono text-bone">
                {data.identified_count} / {data.total_techniques}
                <span className="text-sm text-bone-muted ml-2">techniques identified</span>
              </p>
              <div className="h-1.5 w-64 bg-ink-line rounded-full overflow-hidden mt-2">
                <div className="h-full bg-terminal rounded-full" style={{ width: `${data.coverage_pct}%` }} />
              </div>
            </div>
          </div>

          <div className="space-y-5">
            {Object.entries(data.tactics).map(([tactic, techniques]) => (
              <div key={tactic}>
                <p className="text-xs font-mono text-bone-muted uppercase tracking-wide mb-2">{tactic}</p>
                <div className="flex flex-wrap gap-2">
                  {techniques.map((t) => (
                    <div
                      key={t.technique_id}
                      title={t.cases.join(', ')}
                      className={`px-3 py-2 rounded border text-xs font-mono ${
                        t.identified
                          ? 'border-terminal/60 bg-terminal/10 text-terminal'
                          : 'border-ink-line bg-ink-panel text-bone-muted'
                      }`}
                    >
                      <p className="font-semibold">{t.technique_id}</p>
                      <p className="text-[10px] opacity-80">{t.name}</p>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
