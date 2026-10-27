import { useState } from 'react'
import { motion } from 'motion/react'
import { uploadFile, fetchSample } from '../api.js'
import { PageHeader, Panel } from '../ui.jsx'

const PIPELINE = ['logs', 'validate', 'detect', 'correlate', 'score', 'evidence', 'report']

// Each log line "prints" a beat after the previous one, like terminal output.
function LogLine({ step, status, tone, children }) {
  return (
    <motion.li
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.12, delay: step * 0.15 }}
      className="flex gap-3"
    >
      <span className={`w-14 shrink-0 ${tone}`}>[{status}]</span>
      <span className="text-fg">{children}</span>
    </motion.li>
  )
}

export default function UploadView({ onUploaded, onGoToIncidents }) {
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [counts, setCounts] = useState(null)
  const [dragging, setDragging] = useState(false)

  async function submit(produceFile) {
    setBusy(true)
    setError('')
    setCounts(null)
    try {
      const target = await produceFile()
      const result = await uploadFile(target)
      setCounts(result)
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="max-w-3xl">
      <PageHeader command="cybersentry ingest --file <logs>" title="Ingest security logs">
        CSV or JSON logs. Rows are validated, then deterministic rules detect, correlate, and score.
        Nothing is blocked or changed.
      </PageHeader>

      <ol aria-label="Pipeline" className="mb-6 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
        {PIPELINE.map((step, index) => (
          <li key={step} className="flex items-center gap-2">
            <span className={step === 'report' ? 'text-cyan' : 'text-neon'}>{step}</span>
            {index < PIPELINE.length - 1 && <span aria-hidden="true" className="text-faint">→</span>}
          </li>
        ))}
        <li className="w-full text-faint">{'// the LLM sits only at the end: it explains, never decides'}</li>
      </ol>

      <Panel title="upload" meta=".csv .json .jsonl .ndjson">
        <label
          onDragOver={(event) => {
            event.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault()
            setDragging(false)
            setFile(event.dataTransfer.files?.[0] || null)
          }}
          className={`flex min-h-32 cursor-pointer flex-col items-center justify-center gap-1 border border-dashed px-4 py-6 text-center transition-colors focus-within:outline-2 focus-within:outline-neon ${
            dragging ? 'border-neon bg-neon/10' : 'border-line hover:border-mute'
          }`}
        >
          <input
            type="file"
            accept=".csv,.json,.jsonl,.ndjson"
            onChange={(event) => setFile(event.target.files?.[0] || null)}
            className="sr-only"
          />
          {file ? (
            <>
              <span className="text-neon">{file.name}</span>
              <span className="text-xs text-mute">{(file.size / 1024).toFixed(1)} KB · ready</span>
            </>
          ) : (
            <>
              <span className="text-fg">Drop a log file here</span>
              <span className="text-xs text-mute">or click to browse</span>
            </>
          )}
        </label>

        <div className="mt-4 flex flex-wrap gap-3">
          <button type="button" disabled={!file || busy} onClick={() => submit(async () => file)} className="btn">
            {busy ? 'running…' : '> run pipeline'}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => submit(() => fetchSample('sample_attacks.csv'))}
            className="btn btn-ghost"
          >
            use sample dataset
          </button>
        </div>

        {error && (
          <p role="alert" className="mt-4 border border-crit/60 px-3 py-2 text-sm text-crit">
            [ERR] {error}
          </p>
        )}
      </Panel>

      {counts && (
        <Panel title="pipeline output" meta={counts.filename} className="mt-5">
          <ul className="space-y-1 text-sm" aria-live="polite">
            <LogLine step={0} status=" OK " tone="text-neon">{counts.filename} parsed</LogLine>
            <LogLine step={1} status=" OK " tone="text-neon">{counts.events} events accepted</LogLine>
            <LogLine step={2} status={counts.rejected > 0 ? 'WARN' : ' OK '} tone={counts.rejected > 0 ? 'text-med' : 'text-neon'}>
              {counts.rejected} rows rejected
            </LogLine>
            <LogLine step={3} status={counts.incidents > 0 ? 'ALRT' : ' OK '} tone={counts.incidents > 0 ? 'text-crit' : 'text-neon'}>
              {counts.incidents} incidents correlated
            </LogLine>
          </ul>
          {counts.rejected > 0 && (
            <p className="mt-3 text-xs text-mute">
              Rejected rows failed validation and were kept server-side with a reason, never silently dropped.
            </p>
          )}
          <button
            type="button"
            onClick={() => (counts.incidents > 0 ? onGoToIncidents() : onUploaded())}
            className="btn mt-4"
          >
            {counts.incidents > 0 ? '> view incidents' : '> upload another file'}
          </button>
        </Panel>
      )}
    </div>
  )
}
