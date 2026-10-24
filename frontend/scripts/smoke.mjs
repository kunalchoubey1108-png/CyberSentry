// Browser smoke test for the four-view frontend against the live API.
// Run with the backend (:8000) and `npm run dev` (:5173) already up:
//
//   node scripts/smoke.mjs
//
// Exits non-zero on any failed check or uncaught page error.

import { chromium } from 'playwright'

const WEB = 'http://127.0.0.1:5173'
const API = 'http://127.0.0.1:8000'

const failures = []
const pageErrors = []

function check(cond, message) {
  if (cond) {
    console.log(`  ok   - ${message}`)
  } else {
    failures.push(message)
    console.log(`  FAIL - ${message}`)
  }
}

const browser = await chromium.launch()
const page = await browser.newPage()
page.on('pageerror', (error) => pageErrors.push(`pageerror: ${error.message}`))
page.on('console', (message) => {
  if (message.type() === 'error') pageErrors.push(`console.error: ${message.text()}`)
})

try {
  // ---- shell + health badge -------------------------------------------------
  console.log('1. app shell')
  await page.goto(WEB, { waitUntil: 'networkidle' })
  check(await page.getByText('CyberSentry').isVisible(), 'header renders')
  const badge = page.locator('header span[title]')
  await badge.waitFor()
  const badgeText = await badge.textContent()
  check(/API ok/.test(badgeText), `health badge shows API ok (${badgeText})`)
  check(/rules-only/.test(badgeText), 'health badge shows rules-only mode')

  // ---- view 1: upload -------------------------------------------------------
  console.log('2. upload view: use sample dataset')
  await page.getByRole('button', { name: 'Use sample dataset' }).click()
  await page.getByText('sample_attacks.csv').waitFor({ timeout: 30_000 })
  const uploadText = await page.locator('text=Accepted').locator('..').textContent()
  check(/Accepted/.test(uploadText), 'accepted count shown')
  check(await page.getByText('Accepted').first().isVisible(), 'accepted row visible')
  const statValues = await page.locator('main div.grid div').allTextContents()
  check(statValues.some((v) => /^359/.test(v)), `accepted events = 359 (${statValues.join(' | ')})`)
  check(statValues.some((v) => /^0/.test(v)), 'rejected count shows 0')

  // ---- view 2: incident list ----------------------------------------------
  console.log('3. incident list')
  await page.getByRole('button', { name: 'View incidents →' }).click()
  const rows = page.locator('tbody tr')
  await rows.first().waitFor()
  const rowCount = await rows.count()
  const incidents = await (await fetch(`${API}/incidents`)).json()
  check(rowCount === incidents.length, `table shows all ${incidents.length} incidents (${rowCount})`)
  check(await page.getByRole('button', { name: /Score/ }).isVisible(), 'score column is sortable')

  const scoresOf = async () =>
    (await rows.all()).map(async (row) => Number((await row.locator('td').first().textContent()) ?? '0'))
  // default: descending
  let values = await Promise.all(await scoresOf())
  check(values.every((v, i) => i === 0 || values[i - 1] >= v), `sorted by score desc (${values})`)
  await page.getByRole('button', { name: /Score/ }).click()
  values = await Promise.all(await scoresOf())
  check(values.every((v, i) => i === 0 || values[i - 1] <= v), `click flips to score asc (${values})`)
  await page.getByRole('button', { name: /Score/ }).click() // back to desc

  // ---- view 3: incident detail --------------------------------------------
  console.log('4. incident detail')
  const top = incidents.slice().sort((a, b) => b.score - a.score)[0]
  await rows.first().click()
  await page.getByText('Evidence timeline').waitFor({ timeout: 30_000 })

  const detail = await (await fetch(`${API}/incidents/${top.incident_id}`)).json()
  const report = await (await fetch(`${API}/incidents/${top.incident_id}/report`, { method: 'POST' })).json()

  check(await page.getByText(String(detail.score.score)).first().isVisible(), `score ${detail.score.score} shown`)
  check(await page.getByText(detail.band, { exact: true }).first().isVisible(), `band ${detail.band} badge shown`)
  check(await page.getByText('Rule matches are a pattern, not proof of compromise').isVisible(), 'not-proof-of-compromise note shown')

  const fallbackBadge = page.getByText('Rules-only fallback')
  check(
    report.fallback ? await fallbackBadge.isVisible() : true,
    report.fallback ? 'fallback badge shown for rules-only report' : 'fallback badge absent for LLM report',
  )
  const injectionBadge = page.getByText(/^Injection detected/)
  const expectedFlags = detail.injection_flags.length
  if (expectedFlags > 0) {
    check(await injectionBadge.isVisible(), `injection badge shown (${expectedFlags} flags)`)
    check(await page.getByText(/prompt-injection-like/).first().isVisible(), 'review notice shown')
  } else {
    check(!(await injectionBadge.count()), 'no injection badge on clean incident')
  }

  for (const panel of ['Observed facts', 'Hypotheses', 'Unknowns', 'Next steps']) {
    check(await page.getByRole('heading', { name: panel }).isVisible(), `panel "${panel}" rendered`)
  }

  // evidence timeline: DOM rows == API timeline, matched rows highlighted
  const timelineRows = page.locator('tbody tr[id^="ev-"]')
  const timelineCount = await timelineRows.count()
  check(
    timelineCount === detail.timeline.length,
    `timeline rows match API (${timelineCount}/${detail.timeline.length})`,
  )
  const highlighted = await page.locator('tbody tr.border-amber-400, tbody tr.bg-amber-500\\/10').count()
  check(
    highlighted === detail.timeline.filter((t) => t.matched).length,
    `rule-matched rows highlighted (${highlighted})`,
  )

  // clickable evidence ID in the report jumps to + flashes its row
  const chip = page.locator('button.font-mono').first()
  const chipCount = await page.locator('button.font-mono').count()
  check(chipCount > 0, `report shows ${chipCount} clickable evidence IDs`)
  const chipId = await chip.textContent()
  await chip.click()
  const jumped = await page.evaluate((id) => {
    const row = document.getElementById(`ev-${id}`)
    return { exists: Boolean(row), flashing: Boolean(row?.classList.contains('flash-evidence')) }
  }, chipId)
  check(jumped.exists, `evidence ID ${chipId} resolves to a timeline row`)
  check(jumped.flashing, `evidence row ${chipId} is highlighted after click`)

  // ---- view 4: evaluation ---------------------------------------------------
  console.log('5. evaluation view')
  await page.getByRole('button', { name: 'Evaluation' }).click()
  await page.getByText('reads eval/results/*.csv').waitFor()
  check(await page.getByText('Incident precision').isVisible(), 'precision stat shown')
  check(await page.getByText('Pairwise accuracy').isVisible(), 'pairwise accuracy stat shown')
  check(await page.getByText('Evidence grounding').isVisible(), 'grounding stat shown')
  check(await page.getByText('Injection flag coverage').isVisible(), 'injection coverage stat shown')
  const scenarioTable = page.locator(
    'section:has(> h3:has-text("Scenario results"))',
  )
  const scenarioRows = await scenarioTable.locator('tbody tr').count()
  check(scenarioRows >= 22, `scenario results table rendered (${scenarioRows} rows)`)
  const failureHeading = page.getByRole('heading', { name: /Failure cases/ })
  check(await failureHeading.isVisible(), 'failure-case list shown')
  const claimsTable = page.locator(
    'section:has(> h3:has-text("Claims sample for manual review"))',
  )
  const claimRows = await claimsTable.locator('tbody tr').count()
  check(claimRows === 20, `claims sample shows 20 rows for manual review (${claimRows})`)
} finally {
  await browser.close()
}

if (pageErrors.length > 0) {
  console.log('\npage errors:')
  for (const error of pageErrors) console.log(`  ${error}`)
}
const fatal = failures.length > 0 || pageErrors.length > 0
console.log(fatal ? `\nSMOKE FAILED (${failures.length} failed checks)` : '\nSMOKE PASSED')
process.exit(fatal ? 1 : 0)