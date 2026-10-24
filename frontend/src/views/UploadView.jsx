import { useState } from 'react'
import { uploadFile, fetchSample } from '../api.js'

function Count({ label, value, tone }) {
  const tones = {
    slate: 'text-slate-100',
    red: 'text-red-400',
    amber: 'text-amber-400',
  }
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 px-4 py-3">
      <div className={`text-2xl font-semibold ${tones[tone]}`}>{value}</div>
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
    </div>
  )
}

export default function UploadView({ onUploaded, onGoToIncidents }) {
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [counts, setCounts] = useState(null)

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
    <section className="max-w-2xl">
      <h2 className="text-xl font-semibold text-slate-100">Upload logs</h2>
      <p className="mt-1 text-sm text-slate-400">
        CSV or JSON security logs. Rows are validated, then rules detect, correlate, and
        score — nothing is blocked or changed.
      </p>

      <div className="mt-4 flex flex-col gap-3 rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <input
          type="file"
          accept=".csv,.json,.jsonl,.ndjson"
          onChange={(event) => setFile(event.target.files?.[0] || null)}
          className="text-sm text-slate-300 file:mr-3 file:rounded-md file:border-0 file:bg-slate-700 file:px-3 file:py-1.5 file:text-slate-100 hover:file:bg-slate-600"
        />
        <div className="flex gap-3">
          <button
            type="button"
            disabled={!file || busy}
            onClick={() => submit(async () => file)}
            className="rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy ? 'Uploading…' : 'Upload'}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => submit(() => fetchSample('sample_attacks.csv'))}
            className="rounded-md border border-slate-600 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Use sample dataset
          </button>
        </div>
        {error && (
          <p className="rounded-md border border-red-900/60 bg-red-950/40 px-3 py-2 text-sm text-red-300">
            {error}
          </p>
        )}
      </div>

      {counts && (
        <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="text-sm font-medium text-slate-200">{counts.filename}</div>
          <div className="mt-3 grid grid-cols-3 gap-3">
            <Count label="Accepted" value={counts.events} tone="slate" />
            <Count label="Rejected" value={counts.rejected} tone="amber" />
            <Count label="Incidents" value={counts.incidents} tone="red" />
          </div>
          {counts.rejected > 0 && (
            <p className="mt-3 text-xs text-slate-500">
              Rejected rows failed validation and were kept server-side with a reason —
              never silently dropped.
            </p>
          )}
          <button
            type="button"
            onClick={() => (counts.incidents > 0 ? onGoToIncidents() : onUploaded())}
            className="mt-3 text-sm text-emerald-400 hover:text-emerald-300 hover:underline"
          >
            {counts.incidents > 0 ? 'View incidents →' : 'Upload another file'}
          </button>
        </div>
      )}
    </section>
  )
}