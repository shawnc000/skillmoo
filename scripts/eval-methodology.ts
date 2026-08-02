/**
 * The public method must describe the engine that actually grades.
 *
 * This intentionally checks only grade-deciding facts. Editors can rewrite the prose,
 * but a stale rubric version, formula, risk semantics, or grade cut fails CI.
 */
import { readFileSync } from 'node:fs'
import {
  AXIS_WEIGHTS,
  GRADE_CUTS,
  RUBRIC_VERSION,
  recomputeScore,
  type AxisKey,
} from '../src/lib/analyzeSkill'

const markdown = readFileSync(new URL('../docs/how-we-rate.md', import.meta.url), 'utf8')
const contract = markdown.match(/```text\s*([\s\S]*?)```/)?.[1] ?? ''
const rows = new Map(
  contract
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const i = line.indexOf('=')
      return i < 0 ? [line, ''] : [line.slice(0, i).trim(), line.slice(i + 1).trim()]
    }),
)

const failures: string[] = []
const check = (condition: boolean, message: string) => {
  if (!condition) failures.push(message)
}

check(rows.get('rubric') === RUBRIC_VERSION, `rubric must be ${RUBRIC_VERSION}`)

const compact = (value: string | undefined) => (value ?? '')
  .replace(/\s+/g, '')
  // Markdown may prefer `0.30` while JavaScript serializes the same number as `0.3`.
  // Compare arithmetic, not typography.
  .replace(/\d+(?:\.\d+)?/g, (n) => String(Number(n)))
const expectedQuality = compact(
  `structure*${AXIS_WEIGHTS.structure} + trigger*${AXIS_WEIGHTS.trigger} + tokens*${AXIS_WEIGHTS.tokens}`,
)
check(compact(rows.get('quality')) === expectedQuality, `quality formula must be ${expectedQuality}`)
check(
  compact(rows.get('overall')) === 'clamp(quality-(100-risk),0,100)',
  'overall formula must subtract the full risk deficit',
)

const expectedCuts = GRADE_CUTS.map(([cut, grade]) => `${grade}>=${cut}`).join(',')
check(compact(rows.get('grades')) === expectedCuts, `grade cuts must be ${expectedCuts}`)
check(/subtractive, not averaged/i.test(markdown), 'method must explain subtractive risk semantics')
check(/capability[\s\S]{0,300}does not lower craft quality/i.test(markdown), 'method must preserve capability != defect')

// Guard the checker with a concrete vector. A formula that merely contains the right
// numerals in the wrong arrangement must not pass as reproducible.
const sample: Record<AxisKey, number> = { structure: 92, trigger: 78, tokens: 88, risk: 100 }
check(recomputeScore(sample) === 85, 'sample vector must recompute to 85 under rubric 2.0')

if (failures.length) {
  console.error(`\n✗ eval:methodology — ${failures.length} failure(s)`)
  for (const failure of failures) console.error(`  ✗ ${failure}`)
  process.exit(1)
}

console.log(`\n✓ eval:methodology — public method matches ${RUBRIC_VERSION} (${expectedCuts})\n`)
