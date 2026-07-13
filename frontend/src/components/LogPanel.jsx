import { useMemo, useState } from 'react'
import { Search, Terminal } from 'lucide-react'

const SOURCE_LABELS = {
  auth_log: 'auth.log',
  dns_log: 'dns-query.log',
  process_log: 'sysmon-process.log',
  firewall_log: 'fw-edge01.log',
}

export default function LogPanel({ rawLogs }) {
  const sources = Object.keys(rawLogs)
  const [activeSource, setActiveSource] = useState(sources[0])
  const [query, setQuery] = useState('')

  const lines = useMemo(() => {
    const text = rawLogs[activeSource] || ''
    const all = text.split('\n').filter(Boolean)
    if (!query.trim()) return all
    const q = query.toLowerCase()
    return all.filter((l) => l.toLowerCase().includes(q))
  }, [rawLogs, activeSource, query])

  return (
    <div className="border border-ink-line rounded-lg overflow-hidden bg-ink-DEFAULT">
      <div className="flex items-center justify-between border-b border-ink-line bg-ink-panel px-3">
        <div className="flex">
          {sources.map((s) => (
            <button
              key={s}
              onClick={() => setActiveSource(s)}
              className={`flex items-center gap-1.5 px-3 py-2.5 text-xs font-mono border-r border-ink-line transition-colors ${
                activeSource === s
                  ? 'bg-ink-DEFAULT text-terminal'
                  : 'text-bone-muted hover:text-bone'
              }`}
            >
              <Terminal size={12} />
              {SOURCE_LABELS[s] || s}
            </button>
          ))}
        </div>
      </div>

      <div className="flex items-center gap-2 px-3 py-2 border-b border-ink-line bg-ink-panel/50">
        <Search size={13} className="text-bone-muted shrink-0" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="filter log lines..."
          className="bg-transparent text-xs font-mono text-bone placeholder:text-bone-muted/60 focus:outline-none w-full"
        />
        <span className="text-[10px] font-mono text-bone-muted shrink-0">
          {lines.length} lines
        </span>
      </div>

      <div className="terminal-scroll overflow-y-auto max-h-80 px-3 py-2">
        {lines.length === 0 ? (
          <p className="text-xs font-mono text-bone-muted py-4 text-center">
            no lines match your filter
          </p>
        ) : (
          lines.map((line, i) => (
            <div
              key={i}
              className="text-[11px] leading-relaxed font-mono text-terminal/90 whitespace-pre-wrap break-all hover:bg-ink-panel/40 px-1 -mx-1 rounded"
            >
              {line}
            </div>
          ))
        )}
      </div>
    </div>
  )
}
