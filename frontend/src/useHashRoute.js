import { useEffect, useState, useCallback } from 'react'

function parseHash() {
  const hash = window.location.hash.replace(/^#\/?/, '')
  const [view, param] = hash.split('/')
  if (view === 'case' && param) return { view: 'case-detail', caseId: param }
  if (['cases', 'leaderboard', 'heatmap'].includes(view)) return { view, caseId: null }
  return { view: 'cases', caseId: null }
}

export function useHashRoute() {
  const [route, setRoute] = useState(parseHash)

  useEffect(() => {
    const onHashChange = () => setRoute(parseHash())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  const navigate = useCallback((view, caseId = null) => {
    window.location.hash = view === 'case-detail' ? `/case/${caseId}` : `/${view}`
  }, [])

  return { route, navigate }
}
