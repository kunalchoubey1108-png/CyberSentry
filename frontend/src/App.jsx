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
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

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
  const apiReady = health?.status === 'ok'
  const connectionLabel = apiReady
    ? `API ok · ${health.llm_available ? 'LLM' : 'rules-only'}`
    : 'API unreachable'

  function navigateTo(key) {
    setView(key)
    setMobileMenuOpen(false)
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <header className="sticky top-3 z-50 px-4 pt-3">
        <div
          className={`relative mx-auto max-w-4xl border border-slate-700/70 bg-slate-900/85 shadow-lg shadow-black/20 backdrop-blur-xl transition-[border-radius] ${
            mobileMenuOpen
              ? 'rounded-[1.75rem] md:rounded-full'
              : 'rounded-full'
          }`}
        >
          <div className="flex min-h-14 items-center justify-between gap-2 px-3 sm:px-4 md:px-5">
            <a
              href="#top"
              onClick={(event) => {
                event.preventDefault()
                navigateTo('upload')
              }}
              className="flex min-w-0 items-center gap-2.5 rounded-full outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
              aria-label="CyberSentry AI home"
            >
              <span className="grid size-8 shrink-0 place-items-center rounded-full border border-emerald-400/20 bg-emerald-400/10 text-emerald-300">
                <svg viewBox="0 0 24 24" fill="none" className="size-[18px]" aria-hidden="true">
                  <path
                    d="M12 3.5 19 6v5.3c0 4.4-2.8 7.7-7 9.2-4.2-1.5-7-4.8-7-9.2V6l7-2.5Z"
                    stroke="currentColor"
                    strokeWidth="1.6"
                    strokeLinejoin="round"
                  />
                  <path d="m9 12 2 2 4-4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </span>
              <span className="truncate text-sm font-semibold tracking-tight text-slate-100 sm:text-[15px]">
                CyberSentry <span className="text-emerald-400">AI</span>
              </span>
            </a>

            <nav aria-label="Main navigation" className="hidden items-center gap-1 md:flex">
              {NAV.map((item) => (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => navigateTo(item.key)}
                  aria-current={activeKey === item.key ? 'page' : undefined}
                  className={`rounded-full px-3 py-2 text-[13px] font-medium transition-colors lg:px-3.5 ${
                    activeKey === item.key
                      ? 'bg-slate-700/70 text-white shadow-sm'
                      : 'text-slate-400 hover:bg-slate-800/80 hover:text-slate-100'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </nav>

            <span
              className={`hidden items-center gap-2 rounded-full border px-3 py-1.5 text-[11px] font-medium lg:inline-flex ${
                apiReady
                  ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300'
                  : 'border-slate-600/70 bg-slate-800/80 text-slate-400'
              }`}
              title={`API at localhost:8000 — LLM ${health?.llm_available ? 'configured' : 'not configured (rules-only mode)'}`}
            >
              <span className={`size-1.5 rounded-full ${apiReady ? 'bg-emerald-400' : 'bg-slate-500'}`} />
              {connectionLabel}
            </span>

            <button
              type="button"
              className="grid size-9 shrink-0 place-items-center rounded-full text-slate-300 transition-colors hover:bg-slate-800 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 md:hidden"
              aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
              aria-expanded={mobileMenuOpen}
              aria-controls="mobile-navigation"
              onClick={() => setMobileMenuOpen((open) => !open)}
            >
              {mobileMenuOpen ? (
                <svg viewBox="0 0 24 24" fill="none" className="size-5" aria-hidden="true">
                  <path d="m6 6 12 12M18 6 6 18" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
                </svg>
              ) : (
                <svg viewBox="0 0 24 24" fill="none" className="size-5" aria-hidden="true">
                  <path d="M4 7h16M4 12h16M4 17h16" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
                </svg>
              )}
            </button>
          </div>

          {mobileMenuOpen && (
            <nav id="mobile-navigation" aria-label="Mobile navigation" className="border-t border-slate-800/80 px-3 pb-3 pt-2 md:hidden">
              <div className="grid gap-1">
                {NAV.map((item) => (
                  <button
                    key={item.key}
                    type="button"
                    onClick={() => navigateTo(item.key)}
                    aria-current={activeKey === item.key ? 'page' : undefined}
                    className={`rounded-xl px-3.5 py-2.5 text-left text-sm font-medium transition-colors ${
                      activeKey === item.key
                        ? 'bg-slate-700/70 text-white'
                        : 'text-slate-400 hover:bg-slate-800/80 hover:text-slate-100'
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
              <div
                className={`mt-2 flex items-center gap-2 rounded-xl border px-3.5 py-2.5 text-xs ${
                  apiReady
                    ? 'border-emerald-500/20 bg-emerald-500/5 text-emerald-300'
                    : 'border-slate-700 bg-slate-800/50 text-slate-400'
                }`}
                title={`API at localhost:8000 — LLM ${health?.llm_available ? 'configured' : 'not configured (rules-only mode)'}`}
              >
                <span className={`size-1.5 rounded-full ${apiReady ? 'bg-emerald-400' : 'bg-slate-500'}`} />
                {connectionLabel}
              </div>
            </nav>
          )}
        </div>
      </header>

      <div id="top" className="mx-auto max-w-6xl px-6 py-6">
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