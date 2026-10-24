import { useCallback, useEffect, useState } from 'react'
import { createReport, getIncident } from '../api.js'
import { BandBadge } from './RiskBand.jsx'

// Score component caps (docs/scoring.md): the bars show each named
// contribution against its maximum, so the score is auditable at a glance.
const SCORE_COMPONENTS = [
  { key: 'rule_component', label: 'Rule', cap: 40 },
  { key: 'corroboration', label: 'Corroboration', cap: 15 },
  { key: 'event_volume', label: 'Event volume', cap: 10 },
  { key: 'asset_component', label: 'Asset', cap: 20 },
  { key: 'privilege_component', label: 'Privilege', cap: 10 },
  { key: 'sequence_bonus', label: 'Sequence', cap: 5 },
]

const CONFIDENCE_CLASSES = {
  low: 'bg-slate-500/15 text-slate-300',
  medium: 'bg-amber-500/15 text-amber-300',
  high: 'bg-orange-500/15 text-orange-300',
}

function formatTime(iso) {
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)}`
}

function EvidenceChip({ eventId, onJump }) {
  return (
    <button
      type="button"
      onClick={() => onJump(eventId)}
      title={`Show ${eventId} in the evidence timeline`}
      className="rounded bg-sky-500/15 px-1.5 py-0.5 font-mono text-xs text-sky-300 hover:bg-sky-500/30 hover:text-sky-200"
    >
      {eventId}
    </button>
  )
}

function Panel({ title, children, count }) {
  return (
    <div className="flex flex-col rounded-xl border border-slate-800 bg-slate-900/60">
      <div className="flex items-baseline justify-between border-b border-slate-800 px-4 py-2.5">
        <h4 className="text-sm font-semibold uppercase tracking-wide text-slate-300">{title}</h4>
        {count !== undefined && <span className="text-xs text-slate-500">{count}</span>}
      </div>
      <div className="flex-1 px-4 py-3 text-sm">{children}</div>
    </div>
  )
}

function ScoreBreakdown({ score }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="flex items-baseline justify-between">
        <h4 className="text-sm font-semibold uppercase tracking-wide text-slate-300">
          Score breakdown
        </h4>
        <span className="text-xs text-slate-500">sum of named contributions</span>
      </div>
      <div className="mt-3 space-y-2">
        {SCORE_COMPONENTS.map(({ key, label, cap }) => {
          const value = score[key] ?? 0
          return (
            <div key={key} className="flex items-center gap-3">
              <span className="w-32 shrink-0 text-xs text-slate-400">{label}</span>
              <div className="h-2 flex-1 rounded-full bg-slate-800">
                <div
                  className="h-2 rounded-full bg-emerald-500/80"
                  style={{ width: `${Math.round((value / cap) * 100)}%` }}
                />
              </div>
              <span className="w-16 text-right font-mono text-xs text-slate-300">
                {value}/{cap}
              </span>
            </div>
          )
        })}
      </div>
      <div className="mt-3 flex items-baseline justify-between border-t border-slate-800 pt-3">
        <span className="text-sm text-slate-400">
          Total <span className="font-semibold text-slate-100">{score.score}</span>/100
          {typeof score.matched_event_count === 'number' && (
            <span className="text-slate-500"> · {score.matched_event_count} matched events</span>
          )}
        </span>
        <BandBadge band={score.band} />
      </div>
    </div>
  )
}

export default function IncidentDetailView({ incidentId, onBack }) {
  const [detail, setDetail] = useState(null)
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')
  const [reportError, setReportError] = useState('')
  const [reportLoading, setReportLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    getIncident(incidentId)
      .then((value) => {
        if (!cancelled) setDetail(value)
      })
      .catch((err) => {
        if (!cancelled) setError(String(err.message || err))
      })
    createReport(incidentId)
      .then((value) => {
        if (!cancelled) setReport(value)
      })
      .catch((err) => {
        if (!cancelled) setReportError(String(err.message || err))
      })
      .finally(() => {
        if (!cancelled) setReportLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [incidentId])

  // Scroll the evidence table to a row and flash it — the report's
  // evidence IDs must be traceable to concrete timeline rows.
  const jumpToEvidence = useCallback((eventId) => {
    const row = document.getElementById(`ev-${eventId}`)
    if (!row) return
    row.scrollIntoView({ behavior: 'smooth', block: 'center' })
    row.classList.remove('flash-evidence')
    void row.offsetWidth // restart the animation if already flashing
    row.classList.add('flash-evidence')
    window.setTimeout(() => row.classList.remove('flash-evidence'), 1600)
  }, [])

  if (error) {
    return (
      <section>
        <button type="button" onClick={onBack} className="text-sm text-slate-400 hover:text-slate-200">
          ← Incidents
        </button>
        <p className="mt-3 text-sm text-red-400">{error}</p>
      </section>
    )
  }
  if (!detail) return <section className="text-sm text-slate-500">Loading…</section>

  const injectionCount = detail.injection_flags?.length || 0

  return (
    <section>
      <button
        type="button"
        onClick={onBack}
        className="text-sm text-slate-400 hover:text-slate-200"
      >
        ← Incidents
      </button>

      {/* Header: score, band, mode + injection badges, and the standing note. */}
      <div className="mt-2 flex flex-wrap items-center gap-3">
        <span className="text-3xl font-bold text-slate-100">{detail.score.score}</span>
        <BandBadge band={detail.band} />
        <span className="font-mono text-xs text-slate-500">{detail.incident_id}</span>
        {report?.fallback && (
          <span className="rounded-full border border-amber-500/40 bg-amber-500/15 px-2.5 py-0.5 text-xs font-medium text-amber-300">
            Rules-only fallback
          </span>
        )}
        {report && !report.fallback && (
          <span className="rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-0.5 text-xs font-medium text-emerald-300">
            LLM report (validated)
          </span>
        )}
        {injectionCount > 0 && (
          <span className="rounded-full border border-red-500/40 bg-red-500/15 px-2.5 py-0.5 text-xs font-medium text-red-300">
            Injection detected ({injectionCount})
          </span>
        )}
      </div>
      <p className="mt-2 max-w-3xl text-xs text-slate-500">
        ⚠ Rule matches are a pattern, not proof of compromise — scores and reports are
        triage aids for analyst review, never verdicts, and nothing here blocks or changes
        anything automatically.
      </p>
      {detail.review_notices?.length > 0 && (
        <div className="mt-2 max-w-3xl rounded-md border border-red-900/60 bg-red-950/40 px-3 py-2 text-xs text-red-300">
          {detail.review_notices.map((notice) => (
            <p key={notice}>{notice}</p>
          ))}
        </div>
      )}

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <ScoreBreakdown score={detail.score} />

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h4 className="text-sm font-semibold uppercase tracking-wide text-slate-300">
            Rule findings
          </h4>
          <div className="mt-3 space-y-3">
            {detail.findings.map((finding) => (
              <div key={finding.rule_id}>
                <div className="flex items-center gap-2">
                  <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-xs text-slate-200">
                    {finding.rule_id}
                  </span>
                  <span className="text-xs text-slate-500">severity {finding.severity}</span>
                </div>
                <ul className="mt-1 space-y-0.5">
                  {finding.reasons.map((reason) => (
                    <li key={reason} className="text-xs text-slate-400">
                      {reason}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* AI triage report — four panels; evidence IDs link to the timeline. */}
      <div className="mt-6 flex items-baseline gap-3">
        <h3 className="text-lg font-semibold text-slate-100">Triage report</h3>
        <span className="text-xs text-slate-500">
          every claim cites event IDs — click one to jump to the row
        </span>
      </div>

      {reportLoading && <p className="mt-2 text-sm text-slate-500">Generating report…</p>}
      {reportError && (
        <p className="mt-2 text-sm text-red-400">Report failed: {reportError}</p>
      )}

      {report && (
        <>
          <p className="mt-2 max-w-4xl text-sm text-slate-300">{report.summary}</p>
          {!report.evidence_sufficient && (
            <p className="mt-1 text-xs text-amber-400">
              The report marks the supplied evidence as insufficient to support its claims.
            </p>
          )}
          <div className="mt-3 grid gap-4 md:grid-cols-2">
            <Panel title="Observed facts" count={report.observed_facts.length}>
              <ul className="space-y-2.5">
                {report.observed_facts.map((fact) => (
                  <li key={fact.text} className="text-slate-300">
                    {fact.text}{' '}
                    <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
                      {fact.evidence_ids.map((id) => (
                        <EvidenceChip key={id} eventId={id} onJump={jumpToEvidence} />
                      ))}
                    </span>
                  </li>
                ))}
              </ul>
            </Panel>

            <Panel title="Hypotheses" count={report.hypotheses.length}>
              <ul className="space-y-2.5">
                {report.hypotheses.map((hypothesis) => (
                  <li key={hypothesis.text} className="text-slate-300">
                    <span
                      className={`mr-1.5 rounded px-1.5 py-0.5 text-[10px] font-medium uppercase ${CONFIDENCE_CLASSES[hypothesis.confidence] || CONFIDENCE_CLASSES.low}`}
                    >
                      {hypothesis.confidence}
                    </span>
                    {hypothesis.text}{' '}
                    <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
                      {hypothesis.evidence_ids.map((id) => (
                        <EvidenceChip key={id} eventId={id} onJump={jumpToEvidence} />
                      ))}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="mt-3 border-t border-slate-800 pt-2 text-xs text-slate-500">
                Benign readings:{' '}
                {report.alternative_explanations.join(' · ') || 'none stated'}
              </p>
            </Panel>

            <Panel title="Unknowns" count={report.unknowns.length}>
              <ul className="list-disc space-y-1.5 pl-4 text-slate-400">
                {report.unknowns.map((text) => (
                  <li key={text}>{text}</li>
                ))}
              </ul>
            </Panel>

            <Panel title="Next steps" count={report.recommended_checks.length}>
              <ul className="list-disc space-y-1.5 pl-4 text-slate-400">
                {report.recommended_checks.map((check) => (
                  <li key={check}>{check}</li>
                ))}
              </ul>
            </Panel>
          </div>
        </>
      )}

      {/* Evidence timeline: every report claim resolves to a row here. */}
      <h3 className="mt-6 text-lg font-semibold text-slate-100">
        Evidence timeline{' '}
        <span className="text-xs font-normal text-slate-500">
          ({detail.timeline.length} events · rule-matched rows highlighted)
        </span>
      </h3>
      <div className="mt-2 overflow-x-auto rounded-xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-3 py-2.5">Time</th>
              <th className="px-3 py-2.5">Event ID</th>
              <th className="px-3 py-2.5">Type</th>
              <th className="px-3 py-2.5">User</th>
              <th className="px-3 py-2.5">Host</th>
              <th className="px-3 py-2.5">Src IP</th>
              <th className="px-3 py-2.5 text-right">Sev</th>
              <th className="px-3 py-2.5">Rules</th>
              <th className="px-3 py-2.5">Message (untrusted)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {detail.timeline.map((entry) => (
              <tr
                key={entry.event_id}
                id={`ev-${entry.event_id}`}
                className={
                  entry.matched
                    ? 'border-l-2 border-amber-400 bg-amber-500/10'
                    : 'border-l-2 border-transparent bg-slate-950/40'
                }
              >
                <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-400">
                  {formatTime(entry.timestamp)}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-slate-200">{entry.event_id}</td>
                <td className="px-3 py-2 text-xs text-slate-400">{entry.event_type}</td>
                <td className="px-3 py-2 text-xs text-slate-300">{entry.user}</td>
                <td className="px-3 py-2 text-xs text-slate-300">{entry.host}</td>
                <td className="px-3 py-2 font-mono text-xs text-slate-400">{entry.src_ip}</td>
                <td className="px-3 py-2 text-right text-xs text-slate-300">{entry.severity}</td>
                <td className="px-3 py-2">
                  {entry.rule_ids.length > 0
                    ? entry.rule_ids.map((rule) => (
                        <span
                          key={rule}
                          className="mr-1 inline-block rounded bg-amber-500/20 px-1.5 py-0.5 font-mono text-xs text-amber-300"
                        >
                          {rule}
                        </span>
                      ))
                    : <span className="text-xs text-slate-600">—</span>}
                </td>
                <td
                  className="max-w-sm truncate px-3 py-2 text-xs text-slate-500"
                  title={entry.untrusted_text}
                >
                  {entry.untrusted_text}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-xs text-slate-500">
        Contextual (non-matched) events are shown for completeness; only the highlighted
        rows carry rule matches — every finding below traces to them by event ID.
      </p>
    </section>
  )
}