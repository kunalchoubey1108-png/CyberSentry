import { useCallback, useEffect, useState } from 'react'
import { createReport, getIncident } from '../api.js'
import { Meter, PageHeader, Panel, StatusLine } from '../ui.jsx'
import { BAND_TEXT, BandBadge } from './RiskBand.jsx'

// Score component caps (docs/scoring.md): the bars show each named
// contribution against its maximum, so the score is auditable at a glance.
const SCORE_COMPONENTS = [
  { key: 'rule_component', label: 'rule', cap: 40 },
  { key: 'corroboration', label: 'corroboration', cap: 15 },
  { key: 'event_volume', label: 'event_volume', cap: 10 },
  { key: 'asset_component', label: 'asset', cap: 20 },
  { key: 'privilege_component', label: 'privilege', cap: 10 },
  { key: 'sequence_bonus', label: 'sequence', cap: 5 },
]

const CONFIDENCE_TEXT = {
  low: 'text-mute',
  medium: 'text-med',
  high: 'text-high',
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
      className="cursor-pointer border border-cyan/40 px-1.5 text-xs text-cyan transition-colors hover:bg-cyan hover:text-ink"
    >
      #{eventId}
    </button>
  )
}

function Chips({ ids, onJump }) {
  return (
    <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
      {ids.map((id) => (
        <EvidenceChip key={id} eventId={id} onJump={onJump} />
      ))}
    </span>
  )
}

function ScoreBreakdown({ score }) {
  return (
    <Panel title="score.breakdown" meta="sum of named contributions">
      <ul className="space-y-1.5 text-xs">
        {SCORE_COMPONENTS.map(({ key, label, cap }) => {
          const value = score[key] ?? 0
          return (
            <li key={key} className="flex items-center gap-3">
              <span className="w-28 shrink-0 text-mute">{label}</span>
              <Meter value={value} max={cap} />
              <span className="ml-auto text-fg">
                {value}/{cap}
              </span>
            </li>
          )
        })}
      </ul>
      <p className="mt-3 flex items-center justify-between border-t border-line pt-3 text-sm">
        <span className="text-mute">
          total <span className={`glow font-bold ${BAND_TEXT[score.band] || 'text-fg'}`}>{score.score}</span>/100
          {typeof score.matched_event_count === 'number' && <> · {score.matched_event_count} matched events</>}
        </span>
        <BandBadge band={score.band} />
      </p>
    </Panel>
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

  const back = (
    <button type="button" onClick={onBack} className="mb-4 cursor-pointer text-sm text-mute hover:text-neon">
      ← cd ../incidents
    </button>
  )

  if (error) {
    return (
      <>
        {back}
        <p role="alert" className="text-sm text-crit">
          [ERR] {error}
        </p>
      </>
    )
  }
  if (!detail) {
    return (
      <>
        {back}
        <StatusLine>loading incident {incidentId}</StatusLine>
      </>
    )
  }

  const injectionCount = detail.injection_flags?.length || 0
  const bandText = BAND_TEXT[detail.band] || 'text-fg'

  return (
    <>
      {back}
      <PageHeader command={`cybersentry triage ${detail.incident_id}`} title={`Incident ${detail.incident_id}`} />

      {/* Score, band, mode + injection tags. */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <span className={`glow text-5xl font-bold ${bandText}`}>{detail.score.score}</span>
        <div className="flex flex-col gap-1.5">
          <Meter value={detail.score.score} max={100} cells={20} className={bandText} />
          <div className="flex flex-wrap gap-2">
            <BandBadge band={detail.band} />
            {report?.fallback && <span className="tag text-med">RULES-ONLY REPORT</span>}
            {report && !report.fallback && <span className="tag text-neon">LLM REPORT · VALIDATED</span>}
            {injectionCount > 0 && <span className="tag glow text-crit">INJECTION ×{injectionCount}</span>}
          </div>
        </div>
      </div>
      <p className="mt-4 max-w-3xl text-xs text-mute">
        <span className="text-med">[!]</span> Rule matches are a pattern, not proof of compromise. Scores and
        reports are triage aids for analyst review, never verdicts, and nothing here blocks or changes anything.
      </p>
      {detail.review_notices?.length > 0 && (
        <div role="alert" className="mt-3 max-w-3xl border border-crit/60 bg-crit/5 px-3 py-2 text-xs text-crit">
          {detail.review_notices.map((notice) => (
            <p key={notice}>[INJECTION] {notice}</p>
          ))}
        </div>
      )}

      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <ScoreBreakdown score={detail.score} />

        <Panel title="rule.findings" meta={detail.findings.length}>
          <ul className="space-y-3">
            {detail.findings.map((finding) => (
              <li key={finding.rule_id}>
                <div className="flex items-center gap-2">
                  <span className="tag text-med">{finding.rule_id}</span>
                  <span className="text-xs text-mute">severity {finding.severity}</span>
                </div>
                <ul className="mt-1 space-y-0.5">
                  {finding.reasons.map((reason) => (
                    <li key={reason} className="text-xs text-fg">
                      <span className="text-faint">└ </span>
                      {reason}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      {/* Triage report: every claim cites event IDs that jump to the timeline. */}
      <h2 className="mt-10 text-lg font-bold text-neon">
        <span className="text-faint">## </span>triage.report
      </h2>
      <p className="text-xs text-mute">every claim cites event IDs. Select one to jump to its timeline row.</p>

      {reportLoading && <StatusLine>generating report</StatusLine>}
      {reportError && (
        <p role="alert" className="mt-2 text-sm text-crit">
          [ERR] report failed: {reportError}
        </p>
      )}

      {report && (
        <>
          <p className="mt-3 max-w-4xl border-l-2 border-neon pl-3 text-sm text-fg">{report.summary}</p>
          {!report.evidence_sufficient && (
            <p className="mt-2 text-xs text-med">
              [WARN] the report marks the supplied evidence as insufficient to support its claims.
            </p>
          )}
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <Panel title="observed.facts" meta={report.observed_facts.length}>
              <ul className="space-y-2.5 text-sm">
                {report.observed_facts.map((fact) => (
                  <li key={fact.text} className="text-fg">
                    <span className="text-neon">› </span>
                    {fact.text} <Chips ids={fact.evidence_ids} onJump={jumpToEvidence} />
                  </li>
                ))}
              </ul>
            </Panel>

            <Panel title="hypotheses" meta={report.hypotheses.length}>
              <ul className="space-y-2.5 text-sm">
                {report.hypotheses.map((hypothesis) => (
                  <li key={hypothesis.text} className="text-fg">
                    <span className={`tag mr-1.5 ${CONFIDENCE_TEXT[hypothesis.confidence] || CONFIDENCE_TEXT.low}`}>
                      {hypothesis.confidence.toUpperCase()}
                    </span>
                    {hypothesis.text} <Chips ids={hypothesis.evidence_ids} onJump={jumpToEvidence} />
                  </li>
                ))}
              </ul>
              <p className="mt-3 border-t border-line pt-2 text-xs text-mute">
                benign readings: {report.alternative_explanations.join(' · ') || 'none stated'}
              </p>
            </Panel>

            <Panel title="unknowns" meta={report.unknowns.length}>
              <ul className="space-y-1.5 text-sm text-mute">
                {report.unknowns.map((text) => (
                  <li key={text}>
                    <span className="text-med">? </span>
                    {text}
                  </li>
                ))}
              </ul>
            </Panel>

            <Panel title="next.steps" meta={report.recommended_checks.length}>
              <ul className="space-y-1.5 text-sm text-mute">
                {report.recommended_checks.map((check) => (
                  <li key={check}>
                    <span className="text-neon">□ </span>
                    {check}
                  </li>
                ))}
              </ul>
            </Panel>
          </div>
        </>
      )}

      {/* Evidence timeline: every report claim resolves to a row here. */}
      <h2 className="mt-10 text-lg font-bold text-neon">
        <span className="text-faint">## </span>evidence.timeline
      </h2>
      <p className="text-xs text-mute">
        {detail.timeline.length} events · rule-matched rows marked in amber · message text is untrusted log data
      </p>
      <div className="panel mt-3 overflow-x-auto">
        <table className="term-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Event ID</th>
              <th>Type</th>
              <th>User</th>
              <th>Host</th>
              <th>Src IP</th>
              <th className="text-right">Sev</th>
              <th>Rules</th>
              <th>Message (untrusted)</th>
            </tr>
          </thead>
          <tbody>
            {detail.timeline.map((entry) => (
              <tr
                key={entry.event_id}
                id={`ev-${entry.event_id}`}
                className={entry.matched ? 'border-l-2 border-med bg-med/5' : 'border-l-2 border-transparent'}
              >
                <td className="whitespace-nowrap text-mute">{formatTime(entry.timestamp)}</td>
                <td className="whitespace-nowrap text-cyan">{entry.event_id}</td>
                <td className="text-mute">{entry.event_type}</td>
                <td className="whitespace-nowrap text-fg">{entry.user}</td>
                <td className="whitespace-nowrap text-fg">{entry.host}</td>
                <td className="text-mute">{entry.src_ip}</td>
                <td className="text-right text-fg">{entry.severity}</td>
                <td className="whitespace-nowrap">
                  {entry.rule_ids.length > 0 ? (
                    entry.rule_ids.map((rule) => (
                      <span key={rule} className="tag mr-1 text-med">
                        {rule}
                      </span>
                    ))
                  ) : (
                    <span className="text-faint">—</span>
                  )}
                </td>
                <td className="max-w-sm truncate text-faint" title={entry.untrusted_text}>
                  {entry.untrusted_text}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-xs text-mute">
        Contextual (non-matched) events are shown for completeness. Only the marked rows carry rule matches, and
        every finding above traces to them by event ID.
      </p>
    </>
  )
}
