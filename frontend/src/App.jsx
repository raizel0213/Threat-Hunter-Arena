import Navbar from './components/Navbar'
import CaseList from './pages/CaseList'
import CaseDetail from './pages/CaseDetail'
import Leaderboard from './pages/Leaderboard'
import MitreHeatmap from './pages/MitreHeatmap'
import { useHashRoute } from './useHashRoute'
import { useState } from 'react'

function loadPlayerName() {
  return localStorage.getItem('tha_player_name') || 'analyst'
}

export default function App() {
  const { route, navigate } = useHashRoute()
  const [playerName, setPlayerNameState] = useState(loadPlayerName)

  function setPlayerName(name) {
    localStorage.setItem('tha_player_name', name)
    setPlayerNameState(name)
  }

  return (
    <div className="min-h-screen bg-ink">
      <Navbar
        view={route.view === 'case-detail' ? 'cases' : route.view}
        setView={(v) => navigate(v)}
        playerName={playerName}
        setPlayerName={setPlayerName}
      />

      {route.view === 'cases' && <CaseList onOpenCase={(id) => navigate('case-detail', id)} />}
      {route.view === 'case-detail' && route.caseId && (
        <CaseDetail
          caseId={route.caseId}
          playerName={playerName}
          onBack={() => navigate('cases')}
        />
      )}
      {route.view === 'leaderboard' && <Leaderboard />}
      {route.view === 'heatmap' && <MitreHeatmap playerName={playerName} />}
    </div>
  )
}
