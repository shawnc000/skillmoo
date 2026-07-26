/**
 * eval-provenance — you cannot quietly invent a threshold.
 *
 *   npm run eval:provenance
 *
 * WHY THIS EXISTS. canon.ts made every RULE cite a first-party source, and eval-canon
 * enforced it. The NUMBERS those rules fire at were never covered, and that is the softer
 * place for a rating authority to rot: a rule with a bad source is obvious, a threshold
 * with no source at all looks exactly like a threshold with a good one. The 2026-07-26
 * audit that prompted this file found two live instances of the failure mode —
 *
 *   1. canon declared `description ≤ 1024 chars` a universal-spec MUST from day one and
 *      the engine never checked it. A published rule we did not enforce.
 *   2. /how-we-rate stated the grade cuts as hardcoded prose ("A ≥ 85, B ≥ 72…") rather
 *      than rendering GRADE_CUTS, so the engine could move and the published rubric
 *      would keep confidently reporting the old numbers.
 *
 * — and neither was catchable by reading the code, because both LOOKED right.
 *
 * The assertions below encode one operating rule: BORROW BEFORE YOU INVENT. A borrowed
 * constant must name the authority it was borrowed from. An invented one must admit it
 * is invented and point at the measurement that set it. And section D is the ratchet:
 * every exported scoring constant in the engine must appear in the registry, so adding a
 * new number without declaring where it came from fails the build.
 */
import { readFileSync } from 'node:fs'
import {
  AXIS_WEIGHTS, GRADE_CUTS, SEV_WEIGHT, TOKEN_CURVE,
  SPEC_BODY_TOKENS, SPEC_BODY_LINES, SPEC_NAME_CHARS, SPEC_DESC_CHARS,
  analyzeSkill,
} from '../src/lib/analyzeSkill'
import { JACCARD } from '../src/lib/conflictScan'
import { THRESHOLDS, BORROWED, ORIGINAL, borrowedShare } from '../src/lib/provenance'

let pass = 0
const fails: string[] = []
const ok = (name: string, cond: boolean) => { if (cond) pass++; else fails.push(name) }
const src = (f: string) => readFileSync(new URL(`../src/lib/${f}`, import.meta.url), 'utf8')
const byId = (id: string) => THRESHOLDS.find((t) => t.id === id)

console.log('\nA. EVERY ENTRY IS WELL-FORMED AND BILINGUAL:')
for (const t of THRESHOLDS) {
  ok(`${t.id}: id is unique`, THRESHOLDS.filter((x) => x.id === t.id).length === 1)
  ok(`${t.id}: value is non-empty`, t.value.trim().length > 0)
  // Both languages are load-bearing: the zh column is what a Chinese reader audits us
  // with, so an untranslated entry is an unauditable entry, not a cosmetic gap.
  for (const [lang, pair] of [['decides', t.decides], ['basis', t.basis]] as const) {
    ok(`${t.id}: ${lang}.en is substantive`, pair.en.length > 30)
    ok(`${t.id}: ${lang}.zh is substantive`, pair.zh.length > 10)
    ok(`${t.id}: ${lang}.zh is actually Chinese`, /[一-鿿]/.test(pair.zh))
  }
}

console.log('B. ORIGIN DICTATES THE BURDEN OF PROOF:')
for (const t of BORROWED) {
  ok(`${t.id}: borrowed ⇒ cites a first-party https source`, /^https:\/\//.test(t.source ?? ''))
}
for (const t of ORIGINAL) {
  // A SkillMOO-original number must SAY it is ours — a reader skimming the table has to
  // be able to see, without reading the prose, which numbers carry no outside authority.
  ok(`${t.id}: original ⇒ admits it is ours`, /\bours\b/i.test(t.basis.en) && /我们(自己)?的/.test(t.basis.zh))
  // …and must point at evidence. "It felt about right" cannot pass this line. The one
  // way out is to be ADVISORY — a number that cannot move a grade or a gate owes the
  // reader disclosure instead of calibration, and must state plainly that it is
  // uncalibrated rather than leaving the reader to assume it was measured.
  ok(
    t.advisory
      ? `${t.id}: advisory ⇒ basis discloses that it is uncalibrated`
      : `${t.id}: original ⇒ basis names a measurement, not a preference`,
    t.advisory
      ? /not calibrated|uncalibrated/i.test(t.basis.en) && /没有校准|未校准/.test(t.basis.zh)
      : /gold set|κ|kappa|corpus|measured|verified|audit/i.test(t.basis.en),
  )
  // Claiming a source for something we invented would be the worst outcome of all.
  ok(`${t.id}: original ⇒ claims no outside authority`, !t.source)
}
// "Advisory" has to be structural, not a promise in prose: the grading module must not
// be able to reach the conflict cutoffs at all. If analyzeSkill ever imports conflictScan,
// an uncalibrated number has gained the power to move a grade — and this line fails.
ok(
  'advisory ⇒ the grading module cannot even import the conflict cutoffs',
  !/from\s+['"]\.\/conflictScan['"]/.test(src('analyzeSkill.ts')),
)
ok('the registry is majority-borrowed', borrowedShare() >= 50)
ok('some constants are honestly labelled ours', ORIGINAL.length > 0)

console.log('C. VALUES ARE THE LIVE ONES (a registry that can drift is decoration):')
const has = (id: string, needle: string | number) => {
  const t = byId(id)
  return !!t && t.value.includes(String(needle))
}
ok('spec.body-tokens carries the live SPEC_BODY_TOKENS', has('spec.body-tokens', SPEC_BODY_TOKENS))
ok('spec.body-lines carries the live SPEC_BODY_LINES', has('spec.body-lines', SPEC_BODY_LINES))
ok('spec.name-chars carries the live SPEC_NAME_CHARS', has('spec.name-chars', SPEC_NAME_CHARS))
ok('spec.description-chars carries the live SPEC_DESC_CHARS', has('spec.description-chars', SPEC_DESC_CHARS))
ok('skillmoo.axis-weights carries every live non-zero weight',
  Object.values(AXIS_WEIGHTS).filter((w) => w > 0).every((w) => has('skillmoo.axis-weights', w)))
ok('skillmoo.grade-cuts carries every live cut', GRADE_CUTS.every(([n, g]) => has('skillmoo.grade-cuts', `${g}≥${n}`)))
ok('skillmoo.severity-cost carries every live severity weight',
  Object.values(SEV_WEIGHT).every((w) => has('skillmoo.severity-cost', w)))
ok('skillmoo.token-curve carries the live curve',
  has('skillmoo.token-curve', TOKEN_CURVE.intercept) && has('skillmoo.token-curve', TOKEN_CURVE.perDoubling))
ok('skillmoo.conflict-jaccard carries the live cutoffs',
  has('skillmoo.conflict-jaccard', JACCARD.shadow) && has('skillmoo.conflict-jaccard', JACCARD.overlap))

console.log('D. THE RATCHET — no scoring constant may exist undeclared:')
// Every exported SCREAMING_CASE constant in the scoring modules must be accounted for:
// either mapped to a registry entry, or exempted here BY NAME with a stated reason. A
// new threshold added without provenance lands in neither list and fails.
const DECLARED: Record<string, string> = {
  SPEC_BODY_TOKENS: 'spec.body-tokens',
  SPEC_BODY_LINES: 'spec.body-lines',
  SPEC_NAME_CHARS: 'spec.name-chars',
  SPEC_DESC_CHARS: 'spec.description-chars',
  AXIS_WEIGHTS: 'skillmoo.axis-weights',
  GRADE_CUTS: 'skillmoo.grade-cuts',
  SEV_WEIGHT: 'skillmoo.severity-cost',
  TOKEN_CURVE: 'skillmoo.token-curve',
  JACCARD: 'skillmoo.conflict-jaccard',
  HARNESS_LISTINGS: 'harness.claude-code.listing-budget',
}
// Not thresholds: a version label decides nothing, it only pins what decided.
const EXEMPT = new Set(['RUBRIC_VERSION'])
const exported = new Set<string>()
for (const f of ['analyzeSkill.ts', 'conflictScan.ts', 'listingBudget.ts']) {
  for (const m of src(f).matchAll(/^export const ([A-Z][A-Z0-9_]*)\s*(?::|=)/gm)) exported.add(m[1])
}
for (const name of exported) {
  if (EXEMPT.has(name)) { pass++; continue }
  const id = DECLARED[name]
  ok(`${name}: declared in the provenance registry`, !!id && !!byId(id))
}
// And the reverse: a mapping pointing at a constant that no longer exists is stale.
for (const [name, id] of Object.entries(DECLARED)) {
  ok(`${name}: mapping is not stale (constant still exported)`, exported.has(name))
  ok(`${name} → ${id}: target entry exists`, !!byId(id))
}

console.log('E. THE GAP THIS AUDIT FOUND IS ACTUALLY CLOSED:')
// canon declared description ≤1024 a MUST and the engine never checked it. It does now.
const s = (...l: string[]) => l.join('\n')
const long = s('---', 'name: verbose-skill', `description: ${'Use this when generating a report. '.repeat(40)}`, '---', '# Body', 'Do the thing when asked.')
const fine = s('---', 'name: terse-skill', 'description: Generates a weekly report when the user asks for a status summary.', '---', '# Body', 'Do the thing when asked.')
const longFindings = analyzeSkill(long).findings
ok('an over-1024-char description is now flagged', longFindings.some((f) => /over the spec limit/i.test(f.title)))
ok('a normal description is NOT flagged', !analyzeSkill(fine).findings.some((f) => /over the spec limit/i.test(f.title)))
// A spec violation is a quality deduction, never a safety block (the no-false-block rule).
ok('an over-long description never blocks', analyzeSkill(long).overall.gate !== 'block')

console.log(`\n${fails.length ? '✗' : '✓'} eval:provenance — ${pass} passed, ${fails.length} failed`)
if (fails.length) {
  for (const f of fails) console.log('  ✗ ' + f)
  process.exit(1)
}
const advisory = ORIGINAL.filter((t) => t.advisory).length
console.log(
  `  ${BORROWED.length}/${THRESHOLDS.length} grade-deciding constants borrowed from a published authority (${borrowedShare()}%); ` +
  `${ORIGINAL.length - advisory} are ours and calibrated against the gold set; ${advisory} ${advisory === 1 ? 'is' : 'are'} ours, uncalibrated, and barred from affecting a grade.\n`,
)
