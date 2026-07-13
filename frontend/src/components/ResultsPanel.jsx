import Stamp from './Stamp'

function outcome(score) {
  if (score >= 85) return { label: 'CASE CLOSED', variant: 'terminal' }
  if (score >= 50) return { label: 'CASE REOPENED', variant: 'dossier' }
  return { label: 'CASE COLD', variant: 'alert' }
}

function BreakdownBar({ label, value, max }) {
  const pct = max ? (value / max) * 100 : 0
  return (
    <div>
      <div className="flex justify-between text-xs font-mono text-bone-muted mb-1">
        <span>{label}</span>
        <span>{value.toFixed(1)} / {max}</span>
      </div>
      <div className="h-1.5 bg-ink-line rounded-full overflow-hidden">
        <div className="h-full bg-terminal rounded-full" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

export default function ResultsPanel({ result, onRetry }) {
  const { label, variant } = outcome(result.score_total)

  return (
    <div className="border border-ink-line rounded-lg bg-ink-panel p-6 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs font-mono text-bone-muted mb-1">final score</p>
          <p className="text-4xl font-mono text-bone">{result.score_total.toFixed(1)}<span className="text-lg text-bone-muted">/100</span></p>
        </div>
        <Stamp variant={variant} size="lg" rotate={-6}>{label}</Stamp>
      </div>

      <div className="space-y-3">
        <BreakdownBar label="IOC accuracy" value={result.breakdown.ioc} max={30} />
        <BreakdownBar label="MITRE mapping" value={result.breakdown.mitre} max={20} />
        <BreakdownBar label="Detection rule(s)" value={result.breakdown.detection} max={40} />
        <BreakdownBar label="Speed bonus" value={result.breakdown.speed_bonus} max={10} />
      </div>

      {result.notes?.length > 0 && (
        <div>
          <p className="text-xs font-mono text-bone-muted mb-2">analyst notes</p>
          <ul className="space-y-1.5">
            {result.notes.map((n, i) => (
              <li key={i} className="text-xs font-mono text-bone bg-ink-DEFAULT border border-ink-line rounded px-2.5 py-1.5">
                {n}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="border-t border-ink-line pt-4">
        <p className="text-xs font-mono text-dossier mb-2">ground truth — case file reveal</p>
        <div className="text-xs font-mono text-bone-muted space-y-1">
          <p>IPs: {result.correct_answer.ips.join(', ') || '—'}</p>
          <p>Usernames: {result.correct_answer.usernames.join(', ') || '—'}</p>
          <p>
            ATT&CK chain:{' '}
            {result.correct_answer.mitre_chain.map((t) => t.id).join(' → ')}
          </p>
        </div>
      </div>

      <button
        onClick={onRetry}
        className="text-xs font-mono text-bone-muted hover:text-terminal transition-colors"
      >
        ← back to case files
      </button>
    </div>
  )
}
