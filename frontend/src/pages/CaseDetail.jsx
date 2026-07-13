import { useEffect, useState } from 'react'
import { ArrowLeft, Loader2, AlertTriangle } from 'lucide-react'
import { api } from '../api/client'
import { getElapsedSeconds } from '../components/Timer'
import Timer from '../components/Timer'
import LogPanel from '../components/LogPanel'
import SampleViewer from '../components/SampleViewer'
import SubmissionForm from '../components/SubmissionForm'
import ResultsPanel from '../components/ResultsPanel'

export default function CaseDetail({ caseId, playerName, onBack }) {
  const [caseData, setCaseData] = useState(null)
  const [error, setError] = useState(null)
  const [startedAt] = useState(Date.now())
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState(null)

  useEffect(() => {
    setCaseData(null)
    setResult(null)
    api
      .getCase(caseId)
      .then(setCaseData)
      .catch((e) => setError(e.message))
  }, [caseId])

  async function handleSubmit(payload) {
    setSubmitting(true)
    try {
      const res = await api.submitCase(caseId, {
        player_name: playerName,
        elapsed_seconds: getElapsedSeconds(startedAt),
        ...payload,
      })
      setResult(res)
    } catch (e) {
      setError(e.message)
    } finally {
      setSubmitting(false)
    }
  }

  if (error) {
    return (
      <div className="max-w-6xl mx-auto px-6 py-10">
        <div className="flex items-center gap-2 text-alert text-sm font-mono mb-4">
          <AlertTriangle size={16} />
          {error}
        </div>
        <button onClick={onBack} className="text-xs font-mono text-bone-muted hover:text-terminal">
          ← back to case files
        </button>
      </div>
    )
  }

  if (!caseData) {
    return (
      <div className="flex items-center gap-2 text-bone-muted text-sm font-mono p-10">
        <Loader2 size={16} className="animate-spin" />
        pulling case file...
      </div>
    )
  }

  const hasSamples = Object.keys(caseData.samples || {}).length > 0

  return (
    <div className="max-w-6xl mx-auto px-6 py-8">
      <button
        onClick={onBack}
        className="flex items-center gap-1.5 text-xs font-mono text-bone-muted hover:text-terminal transition-colors mb-6"
      >
        <ArrowLeft size={13} />
        all case files
      </button>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Left: briefing + evidence */}
        <div className="lg:col-span-3 space-y-5">
          <div className="border-l-2 border-dossier bg-dossier-paper/40 rounded-r-lg px-5 py-4">
            <p className="stamp text-dossier text-xl mb-2">{caseData.title}</p>
            <p className="text-sm text-bone font-body leading-relaxed">{caseData.briefing}</p>
            <div className="mt-3">
              <Timer startedAt={startedAt} frozen={!!result} />
            </div>
          </div>

          <LogPanel rawLogs={caseData.raw_logs} />
          {hasSamples && <SampleViewer samples={caseData.samples} />}
        </div>

        {/* Right: submission / results */}
        <div className="lg:col-span-2">
          {result ? (
            <ResultsPanel result={result} onRetry={onBack} />
          ) : (
            <div className="border border-ink-line rounded-lg bg-ink-panel p-5 lg:sticky lg:top-24">
              <p className="text-xs font-mono text-bone-muted mb-4">submit findings</p>
              <SubmissionForm hasSamples={hasSamples} submitting={submitting} onSubmit={handleSubmit} />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
