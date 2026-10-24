import { useEffect, useState } from 'react'
import { getIncidents } from '../api.js'
import { BandBadge } from './RiskBand.jsx'

function Entities({ entities }) {
  const parts = [
    ...(entities?.users || []),
    ...(entities?.hosts || []),
    ...(entities?.src_ips || []),
  ]
  if (parts.length === 0) return <span className="text-slate-600">—</span>
  return (
    <span className="text-xs text-slate-400" title={parts.join(', ')}>
      {parts.slice(0, 3).join(', ')}
      {parts.length > 3 ? ` +${parts.length - 3}` : ''}
    </span>
  )
}

function formatWindow(start, end) {
  const day = (iso) => iso.slice(0, 10)
  const hm = (iso) => iso.slice(11, 16)
  return `${day(start)} ${hm(start)}–${day(start) === day(end) ? '' : day(end)}${hm(end)} UTC`
}

export default function IncidentsView({ onSelect }) {
  const [incidents, setIncidents] = useState(null)
  const [error, setError] = useState('')
  const [sortDesc, setSortDesc] = useState(true)

  useEffect(() => {
    let cancelled = false
    getIncidents()
      .then((list) => {
        if (!cancelled) setIncidents(list)
      })
      .catch((err) => {
        if (!cancelled) setError(String(err.message || err))
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (error) {
    return (
      <section className="text-sm text-red-400">
        Could not reach the API at localhost:8000 — {error}
      </section>
    )
  }
  if (!incidents) return <section className="text-sm text-slate-500">Loading…</section>
  if (incidents.length === 0) {
    return (
      <section className="text-sm text-slate-400">
        No incidents yet — upload a log file first.
      </section>
    )
  }

  const sorted = [...incidents].sort((a, b) =>
    sortDesc ? b.score - a.score : a.score - b.score,
  )

  return (
    <section>
      <div className="flex items-baseline gap-3">
        <h2 className="text-xl font-semibold text-slate-100">Incidents</h2>
        <span className="text-sm text-slate-500">{incidents.length} total</span>
      </div>

      <div className="mt-3 overflow-x-auto rounded-xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-2.5">
                <button
                  type="button"
                  onClick={() => setSortDesc((value) => !value)}
                  className="flex items-center gap-1 font-medium text-slate-400 hover:text-slate-200"
                  title="Sort by score"
                >
                  Score {sortDesc ? '▼' : '▲'}
                </button>
              </th>
              <th className="px-4 py-2.5">Band</th>
              <th className="px-4 py-2.5">Rules</th>
              <th className="px-4 py-2.5">Entities</th>
              <th className="px-4 py-2.5 text-right">Events</th>
              <th className="px-4 py-2.5">Window</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {sorted.map((incident) => (
              <tr
                key={incident.incident_id}
                onClick={() => onSelect(incident.incident_id)}
                className="cursor-pointer bg-slate-950/40 hover:bg-slate-900/70"
              >
                <td className="px-4 py-2.5 font-semibold text-slate-100">{incident.score}</td>
                <td className="px-4 py-2.5">
                  <BandBadge band={incident.band} />
                </td>
                <td className="px-4 py-2.5">
                  <span className="space-x-1">
                    {incident.rules.map((rule) => (
                      <span
                        key={rule}
                        className="inline-block rounded bg-slate-800 px-1.5 py-0.5 font-mono text-xs text-slate-300"
                      >
                        {rule}
                      </span>
                    ))}
                  </span>
                </td>
                <td className="max-w-xs px-4 py-2.5">
                  <Entities entities={incident.entities} />
                </td>
                <td className="px-4 py-2.5 text-right text-slate-300">{incident.event_count}</td>
                <td className="px-4 py-2.5 text-xs text-slate-500">
                  {formatWindow(incident.start_time, incident.end_time)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-xs text-slate-500">
        Click a row for the evidence bundle, score breakdown, and triage report.
      </p>
    </section>
  )
}