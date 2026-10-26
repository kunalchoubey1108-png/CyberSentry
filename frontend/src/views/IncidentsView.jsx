import { useEffect, useState } from 'react'
import { getIncidents } from '../api.js'
import { Meter, PageHeader, StatusLine } from '../ui.jsx'
import { BAND_TEXT, BandBadge } from './RiskBand.jsx'

function Entities({ entities }) {
  const parts = [...(entities?.users || []), ...(entities?.hosts || []), ...(entities?.src_ips || [])]
  if (parts.length === 0) return <span className="text-faint">—</span>
  return (
    <span className="text-mute" title={parts.join(', ')}>
      {parts.slice(0, 3).join(' · ')}
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

  const header = (
    <PageHeader command="cybersentry incidents --sort score" title="Incidents">
      Correlated incidents, scored by transparent rules. Select one for its evidence, score breakdown, and
      triage report.
    </PageHeader>
  )

  if (error) {
    return (
      <>
        {header}
        <p role="alert" className="text-sm text-crit">
          [ERR] could not reach the API at localhost:8000: {error}
        </p>
      </>
    )
  }
  if (!incidents) {
    return (
      <>
        {header}
        <StatusLine>loading incidents</StatusLine>
      </>
    )
  }
  if (incidents.length === 0) {
    return (
      <>
        {header}
        <StatusLine>no incidents yet. run the ingest pipeline first</StatusLine>
      </>
    )
  }

  const sorted = [...incidents].sort((a, b) => (sortDesc ? b.score - a.score : a.score - b.score))

  return (
    <>
      {header}
      <p className="mb-3 text-xs text-mute">
        <span className="text-neon">{incidents.length}</span> incidents ·{' '}
        <span className="text-crit">{incidents.filter((i) => i.band === 'Critical').length}</span> critical
      </p>
      <div className="panel overflow-x-auto">
        <table className="term-table">
          <thead>
            <tr>
              <th>
                <button
                  type="button"
                  onClick={() => setSortDesc((value) => !value)}
                  className="cursor-pointer uppercase hover:text-fg"
                  aria-label={`Sort by score, currently ${sortDesc ? 'highest' : 'lowest'} first`}
                >
                  Score {sortDesc ? '▼' : '▲'}
                </button>
              </th>
              <th>Band</th>
              <th>Incident</th>
              <th>Rules</th>
              <th>Entities</th>
              <th className="text-right">Events</th>
              <th>Window</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((incident) => (
              <tr
                key={incident.incident_id}
                tabIndex={0}
                onClick={() => onSelect(incident.incident_id)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault()
                    onSelect(incident.incident_id)
                  }
                }}
                aria-label={`Open incident ${incident.incident_id}, score ${incident.score}, ${incident.band}`}
                className="cursor-pointer"
              >
                <td className="whitespace-nowrap">
                  <Meter value={incident.score} max={100} className={BAND_TEXT[incident.band] || 'text-mute'} />{' '}
                  <span className="font-bold text-fg">{incident.score}</span>
                </td>
                <td>
                  <BandBadge band={incident.band} />
                </td>
                <td className="whitespace-nowrap text-cyan">{incident.incident_id}</td>
                <td className="whitespace-nowrap">
                  {incident.rules.map((rule) => (
                    <span key={rule} className="tag mr-1 text-med">
                      {rule}
                    </span>
                  ))}
                </td>
                <td className="max-w-xs">
                  <Entities entities={incident.entities} />
                </td>
                <td className="text-right text-fg">{incident.event_count}</td>
                <td className="whitespace-nowrap text-mute">{formatWindow(incident.start_time, incident.end_time)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
