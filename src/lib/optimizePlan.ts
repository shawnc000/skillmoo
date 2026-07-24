/**
 * optimizePlan — the honest state machine behind "one-click optimize".
 * Baseline spec: docs/optimize-logic.md. Pure + framework-free (site/CLI/tests reuse).
 *
 * The free rule-based optimize can only safely trim tokens; empirically it raises the
 * grade of ~0% of real non-A skills (their deficit is triggering / length / capability,
 * none of which a safe mechanical edit can touch). So instead of a dead "already lean"
 * button, we tell the user the TRUTH: what the free tier did, what still stands between
 * the skill and a higher grade (as concrete fixes), and which non-A factors are honest
 * CAPABILITIES (reads a key, calls the network) that are disclosure, not defects to fix.
 */
import {
  analyzeSkill, findingKind, gradeFromScore, overallFrom, AXIS_WEIGHTS, SEV_WEIGHT, type SkillAnalysis,
} from './analyzeSkill'
import { optimizeSkill, type OptimizeResult } from './optimizeSkill'
import { splitProgressive, type SplitResult } from './progressiveDisclosure'

export type FixTier = 'pro' | 'manual'
export interface PlanFix { text: string; tier: FixTier }
export type AxisKey = 'structure' | 'trigger' | 'tokens' | 'risk'

export interface OptimizePlan {
  /** optimal = already best (no button); auto = free win to apply (button + process/result);
   *  plan = non-A with no free win → show the improvement path directly (no dead button). */
  state: 'optimal' | 'auto' | 'plan'
  savedPct: number
  tokensBefore: number
  tokensAfter: number
  gradeBefore: string
  gradeAfter: string
  /** the deterministic rewrite itself — the artifact the user downloads. */
  optimized: string
  /** the free tier's applied edits — the visible "process". */
  changes: string[]
  /** detection findings the free optimize actually CLEARED. */
  resolved: string[]
  /** fixable defects that would raise the grade but need judgment (Pro/manual). */
  fixes: PlanFix[]
  /** inherent capabilities — HONEST disclosure, never framed as defects to fix. */
  capabilities: { cap: string; label?: string; severity: string }[]
  /** the axis dragging the grade down most (for the "why not A" line); null if none. */
  limiter: AxisKey | null
  /** how far a rewrite can honestly take this skill — the "one optimization lands"
   *  contract: we state the target up front, then close on it or say exactly why not. */
  ceiling: Ceiling
  /** true once the skill has ARRIVED — it is at its honest ceiling and nothing further
   *  is worth doing. This is what replaces an open-ended "还能怎么提升". */
  atCeiling: boolean
  /** a deterministic progressive-disclosure restructure we already produced for the
   *  user (lean SKILL.md + references/), or null when none applies. The "give the
   *  result, not homework" fix for the biggest token lever. */
  split: SplitResult | null
}

// How many points of OVERALL one point of an axis is worth — imported, never
// re-declared, so it can't drift from the engine (a stale local copy here silently
// named the wrong limiting axis). Risk is 1 because it is SUBTRACTIVE in
// `overallFrom`: one risk point costs one full point of the overall score.
const AXIS_W: Record<AxisKey, number> = { ...AXIS_WEIGHTS, risk: 1 }
// An axis at/above the A cutoff isn't meaningfully holding the grade back.
const AXIS_OK = 85
// Best → worst, so "have we reached the ceiling?" is an index comparison.
const GRADE_RANK = ['A', 'B', 'C', 'D', 'F']

const tierFor = (s: string): FixTier =>
  /allowed-tools|Add Bash|Ship the missing|references|progressive disclosure|move the detail|split|heading|frontmatter/i.test(s) ? 'manual' : 'pro'

export function optimizePlan(a: SkillAnalysis, o: OptimizeResult, split?: SplitResult): OptimizePlan {
  const ax = Object.fromEntries(a.axes.map((x) => [x.key, x.score])) as Record<AxisKey, number>
  const grade = a.overall.grade
  // A deterministic progressive-disclosure restructure is a REAL deliverable result
  // (not a suggestion) → it counts as a free win we hand the user.
  const canSplit = !!split?.applied
  // A MEANINGFUL free win — not a cosmetic 1% filler swap ("in order to" → "to" on a small
  // skill) that flips an already-clean skill into a "here's your optimized version" flow and
  // presents a rounding-error edit as a real improvement. Require a real token saving
  // (≥3% or ≥25 tokens), a genuinely cleared finding, or a split; otherwise it's optimal/plan.
  const meaningfulSave = o.savedPct >= 3 || o.tokensBefore - o.tokensAfter >= 25
  const hasFreeWin = meaningfulSave || o.resolved.length > 0 || canSplit

  // limiting axis = biggest weighted deficit among the axes that are actually below par.
  const deficits = (['structure', 'trigger', 'tokens', 'risk'] as AxisKey[])
    .map((k) => ({ k, d: AXIS_W[k] * Math.max(0, AXIS_OK - ax[k]) }))
    .filter((x) => x.d > 0)
    .sort((x, y) => y.d - x.d)
  const limiter = deficits[0]?.k ?? null

  // fixes: the fixable-but-not-auto set (Pro/manual). Start from the engine's suggestions,
  // then backfill a synth for any deficient axis the suggestions didn't already cover, so a
  // non-A skill never shows an empty plan.
  const fixes: PlanFix[] = []
  const push = (text: string, tier: FixTier) => { if (text && !fixes.some((f) => f.text === text)) fixes.push({ text, tier }) }
  for (const s of o.suggestions) push(s, tierFor(s))
  const covers = (re: RegExp) => o.suggestions.some((s) => re.test(s))
  // Only SUGGEST the progressive-disclosure fix when we couldn't just DO it (canSplit).
  if (ax.tokens < AXIS_OK && !canSplit && !covers(/progressive disclosure|move the detail|references\//i) && o.savedPct < 5)
    push(`~${a.tokens.total.toLocaleString()} tokens load on every call — trim examples, or move detail into on-demand \`references/\` files (progressive disclosure).`, 'pro')
  if (ax.trigger < AXIS_OK && !covers(/trigger|description/i))
    push('Sharpen the description — say exactly WHEN to use it and narrow the scope so it fires on the right task.', 'pro')
  if (ax.structure < AXIS_OK && !covers(/allowed-tools|Bash|references|Ship the missing|heading|frontmatter/i))
    push('Tighten structure — add section headings, valid frontmatter, and make sure referenced files exist.', 'manual')

  // Capabilities are DISCLOSURE, not a defect — so they show whenever the skill has
  // them, INDEPENDENT of the grade. They used to be gated on `grade !== 'A' && risk <
  // 85`, which only made sense while capability dragged the score down: now that an
  // honest API client can legitimately reach A, that gate would silently hide "this
  // reads your key and calls the network" from precisely the skills whose users most
  // need to see it — disclosure must not be a consolation prize for a bad grade.
  // A proven threat is not a "capability" (it's handled as a block/drop), so the list
  // still yields to a critical finding.
  const critical = a.findings.some((f) => f.severity === 'critical')
  const capabilities = critical ? [] : a.capabilities

  // A non-A skill must never show an empty improvement path.
  if (grade !== 'A' && !hasFreeWin && fixes.length === 0 && capabilities.length === 0)
    push('Close to A — mostly tighter wording / sharper focus. The semantic rewrite (Pro) can take it the last step.', 'pro')

  const state: OptimizePlan['state'] = hasFreeWin ? 'auto' : grade === 'A' ? 'optimal' : 'plan'

  // ARRIVED: the skill sits at its honest ceiling, so there is nothing left worth
  // doing. Saying "还能怎么提升" here would be inventing homework — the whole reason
  // one optimization never felt like it landed.
  const ceiling = achievableCeiling(a)
  const atCeiling = GRADE_RANK.indexOf(grade) <= GRADE_RANK.indexOf(ceiling.grade) && fixes.length === 0

  return {
    state,
    // Prefer the split's lean SKILL.md; else the rule-based trim. Both are verified.
    optimized: canSplit ? split!.skillMd : o.optimized,
    // …and the TOKENS must come from the same place as the artifact. Reporting the
    // rule-based count while shipping the split's file made the card contradict itself
    // ("moved 2 sections" + "saved 1 token" — the split's real number was 352).
    tokensAfter: canSplit ? split!.tokensAfter : o.tokensAfter,
    savedPct: canSplit ? split!.savedPct : o.savedPct,
    ceiling,
    atCeiling,
    tokensBefore: o.tokensBefore,
    gradeBefore: o.gradeBefore,
    gradeAfter: o.gradeAfter,
    changes: o.changes,
    resolved: o.resolved,
    fixes,
    capabilities,
    limiter,
    split: canSplit ? split! : null,
  }
}

/**
 * DETECTION-time (read-only) verdict: is this skill worth offering a "one-click
 * optimize" button? Pure analysis — runs NO optimization. "Optimal" = a clean, lean
 * A with nothing a safe optimize could improve. This keeps the DETECTION phase free
 * of any optimization action (the product's core logic); the real optimize runs
 * ONLY on the user's click, via optimizeNow().
 */
/** The honest ceiling: how far a rewrite can take this skill, and what pins it. */
export interface Ceiling {
  grade: string
  score: number
  /** true when nothing inherent stands in the way of an A. */
  clean: boolean
  /** why it can go no higher, in plain words. Empty ⇒ A is reachable. */
  blockedBy: { axis: AxisKey; reason: string }[]
}

/**
 * ACHIEVABLE CEILING — the best grade a text-only rewrite can HONESTLY reach, holding
 * constant the two things we will not (and should not) change:
 *
 *   • a real THREAT — we do not launder malware into a better grade;
 *   • a MISSING bundled file — we cannot invent a file we were never given.
 *
 * Everything else (a vague trigger, a bloated body, a hardcoded key, thin structure)
 * is a mistake with a right answer, so the ceiling assumes it gets fixed.
 *
 * This is what lets the product state a TARGET before the user clicks, and then close
 * with a real terminal state — "A 级 · 已到顶" or "B 级 · 这就是上限,原因是 X" —
 * instead of an open-ended "还能怎么提升" that reads as unfinished work forever.
 *
 * Pure analysis: runs NO optimization, so the detection phase stays read-only (the
 * core product rule) — it reasons about what a fix WOULD achieve, it never fixes.
 */
export function achievableCeiling(a: SkillAnalysis): Ceiling {
  const ax = Object.fromEntries(a.axes.map((x) => [x.key, x.score])) as Record<AxisKey, number>
  const blockedBy: Ceiling['blockedBy'] = []

  // A threat is the one risk we will not optimize away.
  const threatPenalty = a.findings
    .filter((f) => findingKind(f) === 'threat')
    .reduce((s, f) => s + SEV_WEIGHT[f.severity], 0)
  if (threatPenalty > 0)
    blockedBy.push({ axis: 'risk', reason: 'It contains a real threat signal. We will not rewrite malware into a better grade — this one is a human decision.' })

  // A dangling reference can't be fixed by editing text: the file isn't ours to write.
  const dangling = a.findings.some((f) => /isn’t present|isn't present/i.test(f.title))
  if (dangling)
    blockedBy.push({ axis: 'structure', reason: 'It points at a bundled file that wasn’t included, and we can’t invent a file we never got. Ship the file, then re-run.' })

  const best: Record<AxisKey, number> = {
    structure: dangling ? ax.structure : 100,
    trigger: 100,
    // Token cost is reliably recoverable (compression + progressive disclosure), but we
    // don't promise a perfect 100 — real content still has to live somewhere.
    tokens: Math.max(ax.tokens, 90),
    risk: Math.max(0, 100 - threatPenalty),
  }
  const score = overallFrom(best)
  const grade = gradeFromScore(score, a.findings.some((f) => f.severity === 'critical'))
  return { grade, score, clean: grade === 'A', blockedBy }
}

export function isOptimizable(a: SkillAnalysis): boolean {
  const tokens = a.axes.find((x) => x.key === 'tokens')?.score ?? 100
  const FIXABLE = new Set(['bloat', 'spec', 'trigger', 'privilege'])
  const cleanLeanA = a.overall.grade === 'A' && tokens >= 85 && !a.findings.some((f) => FIXABLE.has(f.category))
  return !cleanLeanA
}

/**
 * ON-CLICK optimizer: the instant the user asks to optimize, run the real work
 * (free rule-based trims + the deterministic progressive-disclosure split) and
 * return the honest process + result. Instant, client-side, writes nothing —
 * detection never calls this.
 */
export function optimizeNow(md: string, opts?: { bundleText?: string; bundleFiles?: string[] }): OptimizePlan {
  const a = analyzeSkill(md, opts)
  const o = optimizeSkill(md, opts)
  const split = splitProgressive(md, opts)
  return optimizePlan(a, o, split)
}
