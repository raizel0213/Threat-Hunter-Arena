const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail || detail
    } catch {
      // ignore
    }
    throw new Error(`${res.status}: ${detail}`)
  }
  return res.json()
}

export const api = {
  listCases: () => request('/cases'),
  getCase: (caseId) => request(`/cases/${caseId}`),
  submitCase: (caseId, payload) =>
    request(`/cases/${caseId}/submit`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  leaderboard: (caseId) =>
    request(`/leaderboard${caseId ? `?case_id=${caseId}` : ''}`),
  mitreHeatmap: (playerName) =>
    request(`/mitre/heatmap/${encodeURIComponent(playerName)}`),
}
