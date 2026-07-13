import { useState } from 'react'
import { Send, Loader2 } from 'lucide-react'

function splitList(value) {
  return value
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
}

export default function SubmissionForm({ hasSamples, submitting, onSubmit }) {
  const [ips, setIps] = useState('')
  const [usernames, setUsernames] = useState('')
  const [mitreIds, setMitreIds] = useState('')
  const [sigmaRule, setSigmaRule] = useState(
    'title: \nlogsource:\n  category: \ndetection:\n  selection:\n    \n  condition: selection\n'
  )
  const [yaraRule, setYaraRule] = useState(
    'rule SuspiciousArtifact\n{\n    strings:\n        $a = ""\n    condition:\n        $a\n}'
  )

  function handleSubmit(e) {
    e.preventDefault()
    onSubmit({
      submitted_ips: splitList(ips),
      submitted_usernames: splitList(usernames),
      submitted_mitre_ids: splitList(mitreIds),
      sigma_rule_yaml: sigmaRule,
      yara_rule_text: hasSamples ? yaraRule : '',
    })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-mono text-bone-muted mb-1.5">
            suspicious IPs (comma-separated)
          </label>
          <input
            value={ips}
            onChange={(e) => setIps(e.target.value)}
            placeholder="198.51.100.23, 10.42.91"
            className="w-full bg-ink-DEFAULT border border-ink-line rounded px-3 py-2 text-sm font-mono text-bone focus:outline-none focus:border-terminal"
          />
        </div>
        <div>
          <label className="block text-xs font-mono text-bone-muted mb-1.5">
            compromised usernames (comma-separated)
          </label>
          <input
            value={usernames}
            onChange={(e) => setUsernames(e.target.value)}
            placeholder="admin, ltorres"
            className="w-full bg-ink-DEFAULT border border-ink-line rounded px-3 py-2 text-sm font-mono text-bone focus:outline-none focus:border-terminal"
          />
        </div>
      </div>

      <div>
        <label className="block text-xs font-mono text-bone-muted mb-1.5">
          MITRE ATT&CK technique IDs (comma-separated)
        </label>
        <input
          value={mitreIds}
          onChange={(e) => setMitreIds(e.target.value)}
          placeholder="T1110, T1110.001, T1078"
          className="w-full bg-ink-DEFAULT border border-ink-line rounded px-3 py-2 text-sm font-mono text-bone focus:outline-none focus:border-terminal"
        />
      </div>

      <div>
        <label className="block text-xs font-mono text-bone-muted mb-1.5">sigma detection rule (YAML)</label>
        <textarea
          value={sigmaRule}
          onChange={(e) => setSigmaRule(e.target.value)}
          rows={9}
          spellCheck={false}
          className="w-full bg-ink-DEFAULT border border-ink-line rounded px-3 py-2 text-xs font-mono text-terminal focus:outline-none focus:border-terminal resize-y"
        />
      </div>

      {hasSamples && (
        <div>
          <label className="block text-xs font-mono text-bone-muted mb-1.5">yara detection rule</label>
          <textarea
            value={yaraRule}
            onChange={(e) => setYaraRule(e.target.value)}
            rows={9}
            spellCheck={false}
            className="w-full bg-ink-DEFAULT border border-ink-line rounded px-3 py-2 text-xs font-mono text-dossier focus:outline-none focus:border-dossier resize-y"
          />
        </div>
      )}

      <button
        type="submit"
        disabled={submitting}
        className="w-full flex items-center justify-center gap-2 bg-terminal text-ink font-semibold text-sm py-2.5 rounded hover:bg-terminal/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
      >
        {submitting ? <Loader2 size={15} className="animate-spin" /> : <Send size={15} />}
        {submitting ? 'Scoring submission...' : 'Submit findings'}
      </button>
    </form>
  )
}
