import { useEffect, useState } from 'react'
import { Loader2, AlertTriangle, Trophy } from 'lucide-react'
import { api } from '../api/client'

export default function Leaderboard() {
  const [rows, setRows] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    api
      .leaderboard()
      .then(setRows)
      .catch((e) => setError(e.message))
  }, [])

  return (
    <div className="max-w-3xl mx-auto px-6 py-10">
      <h1 className="stamp text-3xl text-dossier mb-6">Leaderboard</h1>

      {error && (
        <div className="flex items-center gap-2 text-alert text-sm font-mono">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}

      {!rows && !error && (
        <div className="flex items-center gap-2 text-bone-muted text-sm font-mono">
          <Loader2 size={16} className="animate-spin" />
          loading scores...
        </div>
      )}

      {rows && rows.length === 0 && (
        <p className="text-sm font-mono text-bone-muted">No submissions yet. Be the first to close a case.</p>
      )}

      {rows && rows.length > 0 && (
        <div className="border border-ink-line rounded-lg overflow-hidden">
          <table className="w-full text-sm font-mono">
            <thead>
              <tr className="bg-ink-panel text-bone-muted text-left text-xs">
                <th className="px-4 py-2.5 w-10">#</th>
                <th className="px-4 py-2.5">analyst</th>
                <th className="px-4 py-2.5">case</th>
                <th className="px-4 py-2.5 text-right">score</th>
                <th className="px-4 py-2.5 text-right">time</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} className="border-t border-ink-line">
                  <td className="px-4 py-2.5 text-bone-muted">
                    {i === 0 ? <Trophy size={14} className="text-dossier" /> : i + 1}
                  </td>
                  <td className="px-4 py-2.5 text-bone">{r.player_name}</td>
                  <td className="px-4 py-2.5 text-bone-muted">{r.case_id}</td>
                  <td className="px-4 py-2.5 text-right text-terminal">{r.score_total.toFixed(1)}</td>
                  <td className="px-4 py-2.5 text-right text-bone-muted">
                    {Math.floor(r.elapsed_seconds / 60)}m {Math.round(r.elapsed_seconds % 60)}s
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
