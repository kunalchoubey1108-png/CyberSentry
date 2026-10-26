// The Evaluation view reads the evaluator's output files directly:
//   eval/results/results.csv        — flat section,metric,value,detail table
//   eval/results/failures.csv       — failure-case list
//   eval/results/claims_sample.csv  — claims for manual review
// Regenerate them with `make eval`. Nothing here computes or hardcodes a
// metric — every number below is parsed from those files.

import claimsCsv from '../../../eval/results/claims_sample.csv?raw'
import failuresCsv from '../../../eval/results/failures.csv?raw'
import resultsCsv from '../../../eval/results/results.csv?raw'
import { PageHeader, Panel } from '../ui.jsx'

// Minimal CSV parser (handles quoted fields with commas/newlines).
function parseCsv(text) {
  const rows = []
  let row = []
  let field = ''
  let quoted = false
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        field += '"'
        i += 1
      } else if (ch === '"') {
        quoted = false
      } else {
        field += ch
      }
    } else if (ch === '"') {
      quoted = true
    } else if (ch === ',') {
      row.push(field)
      field = ''
    } else if (ch === '\n') {
      row.push(field)
      rows.push(row)
      row = []
      field = ''
    } else if (ch !== '\r') {
      field += ch
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field)
    rows.push(row)
  }
  const [header, ...body] = rows
  return body
    .filter((cells) => cells.some((cell) => cell !== ''))
    .map((cells) => Object.fromEntries(header.map((h, i) => [h, cells[i] ?? ''])))
}

const TABLE_SECTIONS = [
  'pipeline',
  'incident',
  'correlation',
  'grounding',
  'report_baseline',
  'report_full',
  'injection',
  'latency',
]

// Only exact metric names are rendered as percentages — never substring
// matches (e.g. "scenarios_recalled" is a count, not a rate).
const RATE_METRICS = new Set([
  'precision',
  'recall',
  'f1',
  'false_positive_rate',
  'pairwise_accuracy',
  'pairwise_precision',
  'pairwise_recall',
  'pairwise_f1',
  'grounding_rate',
  'flag_coverage',
])

function formatValue(metric, value) {
  const number = Number(value)
  if (Number.isNaN(number)) return value
  if (metric.endsWith('_ms')) return `${number.toFixed(2)} ms`
  if (RATE_METRICS.has(metric)) return `${(number * 100).toFixed(1)}%`
  return String(number)
}

const results = parseCsv(resultsCsv)
const failures = parseCsv(failuresCsv)
const claims = parseCsv(claimsCsv)

const otherRows = results.filter((row) => TABLE_SECTIONS.includes(row.section))
const scenarioRows = results.filter((row) => row.section === 'scenario')

function findMetric(section, metric) {
  return results.find(
    (row) => row.section === section && row.metric === metric,
  )
}

function Stat({ section, metric, text }) {
  const row = findMetric(section, metric)
  if (!row) return null
  return (
    <div className="panel px-4 py-3">
      <div className="glow text-xl font-bold text-neon">{formatValue(row.metric, row.value)}</div>
      <div className="mt-0.5 text-[11px] uppercase tracking-wider text-mute">{text}</div>
    </div>
  )
}

function labelTone(detail) {
  if (detail.includes('label=suspicious')) return 'text-crit'
  if (detail.includes('label=mixed')) return 'text-med'
  return 'text-mute'
}

export default function EvaluationView() {
  return (
    <>
      <PageHeader command="make eval && cat eval/results/*.csv" title="Evaluation">
        Deterministic rules-only <span className="text-fg">baseline</span> (template report) vs the{' '}
        <span className="text-fg">full pipeline</span> report path, scored against the labels in{' '}
        <code className="text-cyan">data/labelled/labels.json</code>. Every number is parsed from the evaluator
        output, nothing here is hardcoded. Synthetic labelled fixtures only.
      </PageHeader>

      {/* Headline metrics, all parsed from results.csv */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        <Stat section="incident" metric="precision" text="Incident precision" />
        <Stat section="incident" metric="recall" text="Incident recall" />
        <Stat section="incident" metric="f1" text="F1" />
        <Stat section="incident" metric="false_positive_rate" text="False-positive rate" />
        <Stat section="correlation" metric="pairwise_accuracy" text="Pairwise accuracy" />
        <Stat section="grounding" metric="grounding_rate" text="Evidence grounding" />
        <Stat section="injection" metric="flag_coverage" text="Injection flag coverage" />
      </div>

      <Panel title="metrics" meta={`${otherRows.length} rows`} className="mt-6">
        <div className="-mx-4 -my-3 overflow-x-auto">
          <table className="term-table">
            <thead>
              <tr>
                <th>Section</th>
                <th>Metric</th>
                <th className="text-right">Value</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {otherRows.map((row) => (
                <tr key={`${row.section}.${row.metric}`}>
                  <td className="text-mute">{row.section}</td>
                  <td className="text-fg">{row.metric}</td>
                  <td className="whitespace-nowrap text-right text-neon">{formatValue(row.metric, row.value)}</td>
                  <td className="text-mute">{row.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="scenario.results" meta={`${scenarioRows.length} scenarios`} className="mt-6">
        <div className="-mx-4 -my-3 overflow-x-auto">
          <table className="term-table">
            <thead>
              <tr>
                <th>Scenario</th>
                <th className="text-right">Matched</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {scenarioRows.map((row) => {
                const parts = row.detail.split(';')
                const description = parts.slice(2).join(';').replace(/^ */, '')
                return (
                  <tr key={row.metric}>
                    <td className="text-fg">{row.metric}</td>
                    <td className="text-right text-neon">{formatValue(row.metric, row.value)}</td>
                    <td className="text-mute">
                      <span className={`tag mr-2 ${labelTone(row.detail)}`}>
                        {(parts[0] || '').replace('label=', '').toUpperCase()}
                      </span>
                      {description}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="failure.cases" meta={failures.length} className="mt-6">
        {failures.length === 0 ? (
          <p className="text-sm text-neon">[ OK ] none detected</p>
        ) : (
          <div className="-mx-4 -my-3 overflow-x-auto">
            <table className="term-table">
              <thead>
                <tr>
                  <th>Kind</th>
                  <th>Ref</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {failures.map((failure, index) => (
                  <tr key={`${failure.kind}-${failure.ref}-${index}`}>
                    <td className="whitespace-nowrap text-med">{failure.kind}</td>
                    <td className="whitespace-nowrap text-cyan">{failure.ref}</td>
                    <td className="text-mute">{failure.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="claims.sample" meta={`${claims.length} rows for manual review`} className="mt-6">
        <div className="-mx-4 -my-3 overflow-x-auto">
          <table className="term-table">
            <thead>
              <tr>
                <th>Path</th>
                <th>Incident</th>
                <th>Kind</th>
                <th>Claim</th>
                <th>Evidence IDs</th>
                <th className="text-right">Exist/cited</th>
                <th className="text-right">Grounded</th>
              </tr>
            </thead>
            <tbody>
              {claims.map((claim, index) => (
                <tr key={`${claim.path}-${claim.incident_id}-${index}`}>
                  <td className="text-mute">{claim.path}</td>
                  <td className="text-faint">{claim.incident_id}</td>
                  <td className="text-mute">{claim.kind}</td>
                  <td className="max-w-md truncate text-fg" title={claim.claim}>
                    {claim.claim}
                  </td>
                  <td className="text-cyan">{claim.evidence_ids.split(';').join(', ')}</td>
                  <td className="text-right text-mute">
                    {claim.existing}/{claim.cited}
                  </td>
                  <td className="text-right">
                    <span className={`tag ${claim.grounded === '1' ? 'text-neon' : 'text-crit'}`}>
                      {claim.grounded === '1' ? 'YES' : 'NO'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </>
  )
}
