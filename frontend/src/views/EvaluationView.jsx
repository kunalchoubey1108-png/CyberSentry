// The Evaluation view reads the evaluator's output files directly:
//   eval/results/results.csv        — flat section,metric,value,detail table
//   eval/results/failures.csv       — failure-case list
//   eval/results/claims_sample.csv  — claims for manual review
// Regenerate them with `make eval`. Nothing here computes or hardcodes a
// metric — every number below is parsed from those files.

import claimsCsv from '../../../eval/results/claims_sample.csv?raw'
import failuresCsv from '../../../eval/results/failures.csv?raw'
import resultsCsv from '../../../eval/results/results.csv?raw'

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
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 px-4 py-3">
      <div className="text-xl font-semibold text-slate-100">
        {formatValue(row.metric, row.value)}
      </div>
      <div className="text-xs uppercase tracking-wide text-slate-500">{text}</div>
    </div>
  )
}

function labelTone(detail) {
  if (detail.includes('label=suspicious')) return 'border-red-500/40 text-red-300'
  if (detail.includes('label=mixed')) return 'border-amber-500/40 text-amber-300'
  return 'border-slate-500/40 text-slate-300'
}

export default function EvaluationView() {
  return (
    <section>
      <div className="flex items-baseline gap-3">
        <h2 className="text-xl font-semibold text-slate-100">Evaluation</h2>
        <span className="text-xs text-slate-500">
          reads eval/results/*.csv · regenerate with <code>make eval</code> · synthetic
          labelled fixtures only
        </span>
      </div>
      <p className="mt-1 max-w-3xl text-sm text-slate-400">
        Deterministic rules-only <strong>baseline</strong> (template report) vs the{' '}
        <strong>full pipeline</strong> report path, scored against the labels in{' '}
        <code className="mx-1">data/labelled/labels.json</code>. Every number is parsed
        from the evaluator output — nothing on this page is hardcoded.
      </p>

      {/* Headline metrics, all parsed from results.csv */}
      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        <Stat section="incident" metric="precision" text="Incident precision" />
        <Stat section="incident" metric="recall" text="Incident recall" />
        <Stat section="incident" metric="f1" text="F1" />
        <Stat section="incident" metric="false_positive_rate" text="False-positive rate" />
        <Stat section="correlation" metric="pairwise_accuracy" text="Pairwise accuracy" />
        <Stat section="grounding" metric="grounding_rate" text="Evidence grounding" />
        <Stat section="injection" metric="flag_coverage" text="Injection flag coverage" />
      </div>

      {/* Full metric table (section, metric, value, detail) */}
      <div className="mt-4 overflow-x-auto rounded-xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-2.5">Section</th>
              <th className="px-4 py-2.5">Metric</th>
              <th className="px-4 py-2.5 text-right">Value</th>
              <th className="px-4 py-2.5">Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {otherRows.map((row) => (
              <tr key={`${row.section}.${row.metric}`} className="bg-slate-950/40">
                <td className="px-4 py-1.5 text-xs text-slate-500">{row.section}</td>
                <td className="px-4 py-1.5 font-mono text-xs text-slate-300">
                  {row.metric}
                </td>
                <td className="px-4 py-1.5 text-right text-slate-200">
                  {formatValue(row.metric, row.value)}
                </td>
                <td className="px-4 py-1.5 text-xs text-slate-500">{row.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Scenario results */}
      <section className="mt-6">
        <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
          Scenario results
        </h3>
        <div className="mt-2 overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-2.5">Scenario</th>
                <th className="px-4 py-2.5 text-right">Matched</th>
                <th className="px-4 py-2.5">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {scenarioRows.map((row) => {
                const parts = row.detail.split(';')
                const description = parts.slice(2).join(';').replace(/^ */, '')
                return (
                  <tr key={row.metric} className="bg-slate-950/40">
                    <td className="px-4 py-2 font-mono text-xs text-slate-200">
                      {row.metric}
                    </td>
                    <td className="px-4 py-2 text-right text-slate-300">
                      {formatValue(row.metric, row.value)}
                    </td>
                    <td className="px-4 py-2 text-xs text-slate-500">
                      <span
                        className={`mr-2 rounded border px-1.5 py-0.5 ${labelTone(row.detail)}`}
                      >
                        {(parts[0] || '').replace('label=', '')}
                      </span>
                      {description}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* Failure cases */}
      <section className="mt-6">
        <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
          Failure cases <span className="text-slate-600">({failures.length})</span>
        </h3>
        {failures.length === 0 ? (
          <p className="mt-2 text-sm text-slate-500">None detected.</p>
        ) : (
          <div className="mt-2 overflow-x-auto rounded-xl border border-slate-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-2.5">Kind</th>
                  <th className="px-4 py-2.5">Ref</th>
                  <th className="px-4 py-2.5">Detail</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {failures.map((failure, index) => (
                  <tr
                    key={`${failure.kind}-${failure.ref}-${index}`}
                    className="bg-slate-950/40"
                  >
                    <td className="whitespace-nowrap px-4 py-2 text-xs text-amber-300">
                      {failure.kind}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-slate-300">
                      {failure.ref}
                    </td>
                    <td className="px-4 py-2 text-xs text-slate-500">{failure.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Claims sample for manual review */}
      <section className="mt-6">
        <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
          Claims sample for manual review{' '}
          <span className="text-slate-600">({claims.length} rows)</span>
        </h3>
        <div className="mt-2 overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-2.5">Path</th>
                <th className="px-4 py-2.5">Incident</th>
                <th className="px-4 py-2.5">Kind</th>
                <th className="px-4 py-2.5">Claim</th>
                <th className="px-4 py-2.5">Evidence IDs</th>
                <th className="px-4 py-2.5 text-right">Exist/cited</th>
                <th className="px-4 py-2.5 text-right">Grounded</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {claims.map((claim, index) => (
                <tr
                  key={`${claim.path}-${claim.incident_id}-${index}`}
                  className="bg-slate-950/40"
                >
                  <td className="px-4 py-2 text-xs text-slate-400">{claim.path}</td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-500">
                    {claim.incident_id}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-400">{claim.kind}</td>
                  <td className="max-w-md truncate px-4 py-2 text-xs text-slate-300">
                    {claim.claim}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-sky-400">
                    {claim.evidence_ids.split(';').join(', ')}
                  </td>
                  <td className="px-4 py-2 text-right font-mono text-xs text-slate-400">
                    {claim.existing}/{claim.cited}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <span
                      className={`rounded px-1.5 py-0.5 text-xs ${
                        claim.grounded === '1'
                          ? 'bg-emerald-500/15 text-emerald-300'
                          : 'bg-red-500/15 text-red-300'
                      }`}
                    >
                      {claim.grounded === '1' ? 'yes' : 'NO'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  )
}