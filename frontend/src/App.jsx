import { useEffect, useState } from 'react'
import { getHealth } from './api.js'
import EvaluationView from './views/EvaluationView.jsx'
import IncidentDetailView from './views/IncidentDetailView.jsx'
import IncidentsView from './views/IncidentsView.jsx'
import UploadView from './views/UploadView.jsx'

const NAV = [
  { key: 'upload', label: 'Upload' },
  { key: 'incidents', label: 'Incidents' },
  { key: 'evaluation', label: 'Evaluation' },
]

function App() {
  const [view, setView] = useState('upload')
  const [selectedId, setSelectedId] = useState(null)
  const [health, setHealth] = useState(null)

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() => setHealth({ status: 'unreachable' }))
  }, [])

  function selectIncident(id) {
    setSelectedId(id)
    setView('detail')
  }

  const activeKey = view === 'detail' ? 'incidents' : view

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-950/90">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
          <div className="flex items-baseline gap-4">
            <h1 className="text-lg font-semibold tracking-tight">
              CyberSentry <span className="text-emerald-400">AI</span>
            </h1>
            <span className="hidden text-xs text-slate-500 sm:inline">
              Evidence-first security incident triage copilot
            </span>
          </div>
          <nav className="flex items-center gap-1">
            {NAV.map((item) => (
              <button
                key={item.key}
                type="button"
                onClick={() => setView(item.key)}
                className={`rounded-md px-3 py-1.5 text-sm font-medium ${
                  activeKey === item.key
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                }`}
              >
                {item.label}
              </button>
            ))}
            <span
              className={`ml-3 hidden rounded-full border px-2.5 py-0.5 text-xs sm:inline ${
                health?.status === 'ok'
                  ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
                  : 'border-slate-600 bg-slate-800 text-slate-400'
              }`}
              title={`API at localhost:8000 — LLM ${health?.llm_available ? 'configured' : 'not configured (rules-only mode)'}`}
            >
              {health?.status === 'ok'
                ? `API ok · ${health.llm_available ? 'LLM' : 'rules-only'}`
                : 'API unreachable'}
            </span>
          </nav>
        </div>
      </header>

      <div className="mx-auto max-w-6xl px-6 py-6">
        {view === 'upload' && (
          <UploadView onUploaded={() => setView('upload')} onGoToIncidents={() => setView('incidents')} />
        )}
        {view === 'incidents' && <IncidentsView onSelect={selectIncident} />}
        {view === 'detail' && (
          <IncidentDetailView
            key={selectedId}
            incidentId={selectedId}
            onBack={() => setView('incidents')}
          />
        )}
        {view === 'evaluation' && <EvaluationView />}
      </div>
    </main>
  )
}

export default App