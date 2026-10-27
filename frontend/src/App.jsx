import { useEffect, useState } from 'react'
import { AnimatePresence, MotionConfig, motion } from 'motion/react'
import { getHealth } from './api.js'
import EvaluationView from './views/EvaluationView.jsx'
import IncidentDetailView from './views/IncidentDetailView.jsx'
import IncidentsView from './views/IncidentsView.jsx'
import UploadView from './views/UploadView.jsx'

const NAV = [
  { key: 'upload', label: 'ingest', index: '01' },
  { key: 'incidents', label: 'incidents', index: '02' },
  { key: 'evaluation', label: 'eval', index: '03' },
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

  // A new view starts at the top instead of inheriting the old scroll offset.
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [view, selectedId])

  function selectIncident(id) {
    setSelectedId(id)
    setView('detail')
  }

  const activeKey = view === 'detail' ? 'incidents' : view
  const apiReady = health?.status === 'ok'

  return (
    // reducedMotion="user": the OS "reduce motion" setting drops movement, keeps fades.
    <MotionConfig reducedMotion="user">
    <div className="min-h-screen">
      <header className="sticky top-0 z-50 border-b border-line bg-ink/95 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3 sm:px-6">
          <a
            href="#top"
            onClick={(event) => {
              event.preventDefault()
              setView('upload')
            }}
            className="glow flex items-center gap-2 font-bold tracking-tight text-neon"
            aria-label="CyberSentry AI home"
          >
            <svg viewBox="0 0 24 24" fill="none" className="size-5" aria-hidden="true">
              <path
                d="M12 3.5 19 6v5.3c0 4.4-2.8 7.7-7 9.2-4.2-1.5-7-4.8-7-9.2V6l7-2.5Z"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinejoin="round"
              />
              <path d="m9 12 2 2 4-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            CYBERSENTRY<span className="text-mute">//AI</span>
          </a>

          <nav aria-label="Main navigation" className="order-3 flex w-full gap-1 sm:order-none sm:w-auto">
            {NAV.map((item) => (
              <button
                key={item.key}
                type="button"
                onClick={() => setView(item.key)}
                aria-current={activeKey === item.key ? 'page' : undefined}
                className={`relative min-h-10 cursor-pointer px-3 text-[13px] transition-colors ${
                  activeKey === item.key ? 'font-bold text-ink' : 'text-mute hover:bg-line hover:text-fg'
                }`}
              >
                {activeKey === item.key && (
                  <motion.span
                    layoutId="nav-active"
                    aria-hidden="true"
                    className="absolute inset-0 bg-neon"
                    transition={{ type: 'spring', stiffness: 500, damping: 40 }}
                  />
                )}
                <span className="relative">
                  <span className={activeKey === item.key ? 'text-ink/70' : 'text-faint'}>{item.index}</span>{' '}
                  {item.label}
                </span>
              </button>
            ))}
          </nav>

          <span
            className={`ml-auto flex items-center gap-2 text-xs ${apiReady ? 'text-neon' : 'text-crit'}`}
            title={`API at localhost:8000 — LLM ${health?.llm_available ? 'configured' : 'not configured (rules-only mode)'}`}
          >
            <span aria-hidden="true" className={`size-2 ${apiReady ? 'bg-neon shadow-[0_0_8px] shadow-neon' : 'bg-crit'}`} />
            {apiReady ? `api:ok · mode:${health.llm_available ? 'llm' : 'rules-only'}` : 'api:unreachable'}
          </span>
        </div>
      </header>

      <main id="top" className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
        <AnimatePresence mode="wait">
          <motion.div
            key={view === 'detail' ? `detail-${selectedId}` : view}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
          >
            {view === 'upload' && (
              <UploadView onUploaded={() => setView('upload')} onGoToIncidents={() => setView('incidents')} />
            )}
            {view === 'incidents' && <IncidentsView onSelect={selectIncident} />}
            {view === 'detail' && <IncidentDetailView incidentId={selectedId} onBack={() => setView('incidents')} />}
            {view === 'evaluation' && <EvaluationView />}
          </motion.div>
        </AnimatePresence>
      </main>

      <footer className="mx-auto max-w-6xl px-4 pb-8 text-xs text-faint sm:px-6">
        {'// triage copilot · detects, correlates, scores, reports · never blocks or changes anything'}
      </footer>
    </div>
    </MotionConfig>
  )
}

export default App
