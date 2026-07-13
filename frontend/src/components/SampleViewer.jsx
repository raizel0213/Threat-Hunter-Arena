import { useState } from 'react'
import { FileCode } from 'lucide-react'

export default function SampleViewer({ samples }) {
  const names = Object.keys(samples || {})
  const [active, setActive] = useState(names[0])

  if (names.length === 0) return null

  return (
    <div className="border border-ink-line rounded-lg overflow-hidden bg-ink-DEFAULT">
      <div className="flex items-center justify-between border-b border-ink-line bg-ink-panel px-3 py-2.5">
        <span className="text-xs font-mono text-bone-muted">recovered artifacts — IR triage pull</span>
      </div>
      <div className="flex border-b border-ink-line bg-ink-panel/40">
        {names.map((n) => (
          <button
            key={n}
            onClick={() => setActive(n)}
            className={`flex items-center gap-1.5 px-3 py-2 text-[11px] font-mono border-r border-ink-line transition-colors ${
              active === n ? 'text-dossier bg-ink-DEFAULT' : 'text-bone-muted hover:text-bone'
            }`}
          >
            <FileCode size={11} />
            {n}
          </button>
        ))}
      </div>
      <pre className="terminal-scroll overflow-y-auto max-h-56 px-3 py-2 text-[11px] font-mono text-bone whitespace-pre-wrap">
        {samples[active]}
      </pre>
    </div>
  )
}
