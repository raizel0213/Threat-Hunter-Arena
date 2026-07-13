import { useState } from 'react'
import { FileSearch, Trophy, Target, Pencil } from 'lucide-react'

const NAV_ITEMS = [
  { key: 'cases', label: 'Cases', icon: FileSearch },
  { key: 'leaderboard', label: 'Leaderboard', icon: Trophy },
  { key: 'heatmap', label: 'ATT&CK Coverage', icon: Target },
]

export default function Navbar({ view, setView, playerName, setPlayerName }) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(playerName)

  function saveName() {
    const trimmed = draft.trim()
    if (trimmed) setPlayerName(trimmed)
    setEditing(false)
  }

  return (
    <header className="border-b border-ink-line bg-ink/95 backdrop-blur sticky top-0 z-20">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-4 flex items-center justify-between gap-3 sm:gap-6">
        <div className="flex items-center gap-2 shrink-0">
          <span className="stamp text-dossier text-sm sm:text-lg whitespace-nowrap">
            <span className="hidden sm:inline">Threat Hunter Arena</span>
            <span className="sm:hidden">THA</span>
          </span>
        </div>

        <nav className="flex items-center gap-1">
          {NAV_ITEMS.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setView(key)}
              title={label}
              className={`flex items-center gap-2 px-2.5 sm:px-3 py-2 text-sm font-medium rounded transition-colors ${
                view === key
                  ? 'text-terminal bg-ink-panel'
                  : 'text-bone-muted hover:text-bone hover:bg-ink-panel/60'
              }`}
            >
              <Icon size={15} />
              <span className="hidden md:inline">{label}</span>
            </button>
          ))}
        </nav>

        <div className="flex items-center gap-2 text-sm shrink-0">
          {editing ? (
            <input
              autoFocus
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onBlur={saveName}
              onKeyDown={(e) => {
                if (e.key === 'Enter') saveName()
                if (e.key === 'Escape') setEditing(false)
              }}
              className="bg-ink-panel border border-ink-line rounded px-2 py-1 text-bone w-24 sm:w-32 focus:outline-none focus:border-terminal"
              placeholder="analyst name"
            />
          ) : (
            <button
              onClick={() => {
                setDraft(playerName)
                setEditing(true)
              }}
              className="flex items-center gap-1.5 text-bone-muted hover:text-bone transition-colors"
            >
              <span className="font-mono truncate max-w-[80px] sm:max-w-none">{playerName}</span>
              <Pencil size={12} className="shrink-0" />
            </button>
          )}
        </div>
      </div>
    </header>
  )
}
