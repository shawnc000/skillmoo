/**
 * composePortfolio — the capstone: turn a pile of installed skills + the user's
 * goal into a value-maximized ACTION PLAN. Deterministic, no model, no key.
 *
 * It unifies the three real static engines:
 *   - analyzeSkill      → per-skill safety gate + hygiene grade + token bloat
 *   - analyzePortfolio  → cross-skill overlaps + shadowing (the conflict count)
 *   - (optimize runs ONLY on the user's click via optimizeNow — never during detection)
 * …and emits exactly ONE recommended action per skill (keep / optimize / merge /
 * narrow / drop) plus goal-gaps to fill — i.e. "here is the best combination of
 * skills for your goal, and the moves to get there."
 *
 * HONESTY (the whole product): every action carries a concrete, stated reason.
 *  - DROP is only ever recommended for a skill that FAILS THE SAFETY GATE or is
 *    a near-duplicate of another (redundant). We never delete on a weak signal.
 *  - MERGE is a strong claim (two skills are redundant); it requires HIGH trigger
 *    overlap (Jaccard), not just a couple of shared domain words — otherwise two
 *    distinct same-domain skills would be wrongly merged.
 *  - A pending safety review is surfaced as a FLAG, never folded into an
 *    "optimize" reason (a token trim does not resolve a safety concern).
 *  - Value today = measured safety + hygiene + goal-relevance (keyword-based).
 *    Efficacy/lift is folded in ONLY once actually measured on the user's model.
 *    Semantic relevance + semantic merge are the model-powered (Pro) tier.
 */
import { analyzeSkill, type Gate } from './analyzeSkill'
import { analyzePortfolio } from './conflictScan'
import { isOptimizable, achievableCeiling } from './optimizePlan' // DETECTION-time read-only verdicts; the real optimize runs on the user's click (optimizeNow)

export interface PortfolioSkill {
  name: string
  /** Full SKILL.md text. Description is derived from its frontmatter if present. */
  md: string
  /** Full-bundle context (folder / ZIP / GitHub dir): concatenated scannable bundle
   *  files + their relative paths. Present ONLY when the WHOLE bundle is known — it
   *  enables bundled-script security scanning + reference-integrity. Absent (both
   *  undefined) = single-file input (paste / lone SKILL.md), the degraded mode. */
  bundleText?: string
  bundleFiles?: string[]
}

/** analyzeSkill/optimizeSkill opts from a skill's bundle context, or undefined for a
 *  single-file skill (so reference-integrity does NOT run and mis-flag phantom danglings). */
function bundleOpts(s: PortfolioSkill): { bundleText?: string; bundleFiles?: string[] } | undefined {
  if (s.bundleText === undefined && s.bundleFiles === undefined) return undefined
  const o: { bundleText?: string; bundleFiles?: string[] } = {}
  if (s.bundleText) o.bundleText = s.bundleText
  if (s.bundleFiles) o.bundleFiles = s.bundleFiles // [] is a valid "known-empty" bundle
  return o
}

export type ActionKind = 'keep' | 'optimize' | 'merge' | 'narrow' | 'drop'

export interface SkillAction {
  /** Original index in the input `skills[]` — lets the UI pair an action back to its
   *  source skill (names aren't unique) to show findings / run a per-skill optimize. */
  id: number
  name: string
  action: ActionKind
  grade: string
  /** analyzeSkill overall 0–100 at detection time — drives the grade progress bar. */
  score: number
  /** How far an honest rewrite could take this skill (achievableCeiling, 0–100) —
   *  the bar's "预计优化后" marker. PURE analysis; detection still runs no optimize. */
  ceilingScore: number
  gate: Gate
  tokens: number
  /** 0–1 keyword relevance to the goal (undefined when no goal was given). */
  relevance?: number
  reason: string
  /** For merge/drop-duplicate: the skill this one folds into / duplicates. For narrow:
   *  the specific skill its over-broad trigger can shadow. */
  mergeWith?: string
  savedPct?: number
  /** A soft note that does NOT change the action (e.g. "flagged for review"). */
  flag?: string
  /** merge/narrow: the shared trigger tokens driving the overlap (for a localized reason). */
  shared?: string[]
  /** Structured flag kind so the UI can localize (the English `flag` stays for the CLI). */
  flagKind?: 'review' | 'offgoal'
  /** The full per-skill detection findings + capabilities (so a UI can show the complete
   *  report per skill without re-analyzing). Carried through from analyzeSkill. */
  findings: { severity: string; category: string; title: string; detail: string }[]
  capabilities: { cap: string; label?: string; severity: string }[]
  /** DETECTION says only WHETHER a one-click optimize is worth offering (read-only,
   *  no optimization run). false = already optimal → no button. The actual optimize
   *  (process + result) runs only on the user's click, via optimizeNow(md, bundle). */
  optimizable: boolean
  /** The raw skill + its bundle context, so the UI can run the real optimize on click
   *  (client-side, instant, writes nothing) — never during detection. */
  md: string
  bundle?: { bundleText?: string; bundleFiles?: string[] }
}

export interface Gap {
  need: string
  reason: string
}

export interface PortfolioPlan {
  actions: SkillAction[]
  gaps: Gap[]
  summary: {
    total: number
    keep: number
    optimize: number
    merge: number
    narrow: number
    drop: number
    conflicts: number
    tokensNow: number
    /** tokens after applying the safe one-click optimize + dropping/merging. */
    tokensAfter: number
    goal?: string
  }
  /** Plain-language honesty note about what the ranking is (and isn't) based on. */
  basis: string
}

/* ---- lean keyword tooling for goal-relevance (heuristic, clearly labeled) ---- */
// Filler that survives stemming — the generic words every "Use this skill when
// the user wants X" description shares. Stopping them (AFTER stemming, so
// wants→want and users→user are caught too) keeps overlap on real domain tokens.
const STOP = new Set([
  'the', 'and', 'for', 'with', 'when', 'use', 'this', 'that', 'your', 'you', 'from',
  'into', 'of', 'to', 'in', 'on', 'or', 'be', 'is', 'are', 'my', 'our', 'want', 'need',
  'make', 'build', 'help', 'using', 'able', 'can', 'via', 'so', 'as', 'skill',
  'user', 'thing', 'task', 'variou', 'relat', 'provid', 'includ', 'gener', 'context',
  'creat', 'ask', 'get', 'work', 'let', 'given', 'various', 'related',
])
function stem(w: string): string {
  let s = w.replace(/'s$/, '')
  if (s.endsWith('ing') && s.length > 5) s = s.slice(0, -3)
  else if (s.endsWith('ed') && s.length > 4) s = s.slice(0, -2)
  else if (s.endsWith('es') && s.length > 4) s = s.slice(0, -2)
  else if (s.endsWith('s') && s.length > 3) s = s.slice(0, -1)
  return s
}
function tokens(text: string): Set<string> {
  const out = new Set<string>()
  // letters-only, ≥3 chars — splits hyphenated names (api-security-auditor →
  // api, security, auditor) so morphological coverage works.
  for (const w of (text.toLowerCase().match(/[a-z]{3,}/g) ?? [])) {
    if (STOP.has(w)) continue
    const s = stem(w)
    if (STOP.has(s)) continue // catch wants→want, users→user, various→variou
    out.add(s)
  }
  return out
}
/** term membership with a 5-char prefix fallback so morphological siblings match
 *  (secure↔security, deploy↔deployment) — cuts the keyword-heuristic false gaps. */
function hasTerm(set: Set<string>, term: string): boolean {
  if (set.has(term)) return true
  if (term.length < 5) return false
  const p = term.slice(0, 5)
  for (const t of set) if (t.length >= 5 && (t.startsWith(p) || term.startsWith(t.slice(0, 5)))) return true
  return false
}
function jaccard(a: Set<string>, b: Set<string>): number {
  if (!a.size || !b.size) return 0
  let inter = 0
  for (const t of a) if (b.has(t)) inter++
  return inter / (a.size + b.size - inter)
}

const GRADE_RANK: Record<string, number> = { A: 5, B: 4, C: 3, D: 2, F: 1 }
function gradeVal(g: string): number { return GRADE_RANK[g[0]?.toUpperCase()] ?? 0 }
const BROAD = /\b(?:any|all|every|whenever|anything|everything)\b/i

// MERGE needs HIGH overlap (a strong "these are redundant" claim); DUP is
// near-identical → drop the copy. Tuned so distinct same-domain skills (sharing
// a couple of words) are NOT merged.
const MERGE_SIM = 0.45
const DUP_SIM = 0.8

/**
 * Build the value-maximized plan. `goal` is optional free text ("ship a secure
 * Next.js SaaS", "write and review Terraform") used only for keyword relevance.
 */
export function composePortfolio(skills: PortfolioSkill[], goal?: string): PortfolioPlan {
  const goalTokens = goal ? tokens(goal) : null

  // 1) analyze every skill once. Keyed by INDEX — skill names are NOT unique
  //    (the same name can appear in two roots; a name-keyed map would collide).
  const rows = skills.map((s, id) => {
    const bopt = bundleOpts(s)
    const a = analyzeSkill(s.md, bopt) // DETECTION = read-only diagnosis only; NO optimize here
    const desc = a.frontmatter.description ?? ''
    const tks = tokens(`${s.name} ${desc}`)
    let relevance: number | undefined
    if (goalTokens && goalTokens.size) {
      let hit = 0
      for (const g of goalTokens) if (hasTerm(tks, g)) hit++
      relevance = hit / goalTokens.size
    }
    let value = a.overall.score
    if (a.overall.gate === 'block') value = 0
    if (relevance !== undefined) value = value * (0.35 + 0.65 * relevance)
    return { id, name: s.name, md: s.md, bopt, a, desc, tks, broad: BROAD.test(desc), relevance, value }
  })

  const decided = new Map<number, SkillAction>()
  const base = (r: (typeof rows)[number]): SkillAction => ({
    id: r.id, name: r.name, action: 'keep', grade: r.a.overall.grade, score: r.a.overall.score, ceilingScore: achievableCeiling(r.a).score, gate: r.a.overall.gate,
    tokens: r.a.tokens.total, relevance: r.relevance, reason: '',
    findings: r.a.findings.map((f) => ({ severity: f.severity, category: f.category, title: f.title, detail: f.detail })),
    capabilities: r.a.capabilities.map((c) => ({ cap: c.cap, label: c.label, severity: c.severity })),
    optimizable: isOptimizable(r.a),
    md: r.md,
    bundle: r.bopt,
  })
  const absorbed = (id: number) => { const d = decided.get(id); return d?.action === 'drop' || d?.action === 'merge' }

  // 2a) SAFETY FLOOR — a skill that fails the gate is dropped, no exceptions.
  for (const r of rows) {
    if (r.a.overall.gate === 'block') {
      const crit = r.a.findings.find((f) => f.severity === 'critical')
      decided.set(r.id, { ...base(r), action: 'drop', reason: `Fails the safety gate${crit ? ` — ${crit.title.toLowerCase()}` : ''}. Remove until fixed.` })
    }
  }

  // 2b) DUPLICATES & MERGES — pairwise trigger-token similarity. Same name OR
  //     ~identical triggers → duplicate (drop the copy); high-but-not-identical
  //     overlap → merge the weaker into the stronger. Processed strongest-first.
  const cand: { i: number; j: number; sim: number; sameName: boolean }[] = []
  for (let i = 0; i < rows.length; i++) {
    for (let j = i + 1; j < rows.length; j++) {
      const sameName = !!rows[i].name && rows[i].name === rows[j].name
      if (!sameName && (rows[i].tks.size < 4 || rows[j].tks.size < 4)) continue
      const sim = jaccard(rows[i].tks, rows[j].tks)
      if (sameName || sim >= MERGE_SIM) cand.push({ i, j, sim: sameName ? 1 : sim, sameName })
    }
  }
  cand.sort((a, b) => b.sim - a.sim)
  for (const { i, j, sim, sameName } of cand) {
    const [hi, lo] = rows[i].value >= rows[j].value ? [rows[i], rows[j]] : [rows[j], rows[i]]
    if (absorbed(lo.id) || absorbed(hi.id)) continue          // don't chain into an already-moved skill
    if (decided.get(hi.id)?.action === 'drop') continue       // never merge into a dropped (unsafe) skill
    const shared = [...lo.tks].filter((t) => hi.tks.has(t)).slice(0, 4)
    if (sameName || sim >= DUP_SIM) {
      decided.set(lo.id, { ...base(lo), action: 'drop', mergeWith: hi.name, shared, reason: `Duplicate of "${hi.name}" (${sameName ? 'same name, ' : ''}near-identical triggers). Redundant — keep one.` })
    } else {
      decided.set(lo.id, { ...base(lo), action: 'merge', mergeWith: hi.name, shared, reason: `Heavily overlaps "${hi.name}" (${shared.join(', ')}). Consolidate to stop them fighting to fire.` })
    }
  }

  // 2c) SHADOWING — an over-broad trigger (any/all/every) swallows specific
  //     skills. Narrow it so the specifics can fire — but only if it still
  //     collides with a NON-absorbed skill.
  for (const r of rows) {
    if (decided.has(r.id) || !r.broad) continue
    const victim = rows.find((o) => o.id !== r.id && !absorbed(o.id) && [...r.tks].some((t) => t.length > 3 && o.tks.has(t)))
    if (victim) {
      const shared = [...r.tks].filter((t) => t.length > 3 && victim.tks.has(t)).slice(0, 3)
      decided.set(r.id, { ...base(r), action: 'narrow', mergeWith: victim.name, shared, reason: `Over-broad trigger (any/all/every) can shadow "${victim.name}"${shared.length ? ` on ${shared.join(', ')}` : ''}. Narrow it to its real task.` })
    }
  }

  // 2d) HYGIENE — anything still undecided: optimize if there's a real safe win,
  //     else keep. A pending safety review becomes a FLAG (never an optimize reason).
  for (const r of rows) {
    if (decided.has(r.id)) continue
    // DETECTION-only: decide the badge from ANALYSIS, never by running optimize. The
    // real optimize (and its numbers) happens on the user's click. "optimize" here
    // just means the one-click is worth offering; "keep" means already optimal.
    const tokenScore = r.a.axes.find((x) => x.key === 'tokens')?.score ?? 100
    const why: string[] = []
    if (tokenScore < 85) why.push('trim token cost')
    if (r.a.findings.some((f) => f.category === 'trigger')) why.push('sharpen the trigger')
    if (r.a.findings.some((f) => f.category === 'spec')) why.push('tighten structure')
    const act: SkillAction = isOptimizable(r.a)
      ? { ...base(r), action: 'optimize', reason: `Grade ${r.a.overall.grade} — one-click optimize available${why.length ? ` (${why.join('; ')})` : ''}.` }
      : { ...base(r), action: 'keep', reason: `Grade ${r.a.overall.grade}, safe${r.relevance ? ', on-goal' : ''}, already lean. Keep as-is.` }
    if (r.a.overall.gate === 'review') { act.flag = 'Flagged for a safety review — check the finding before relying on it.'; act.flagKind = 'review' }
    decided.set(r.id, act)
  }

  // 2e) soft off-goal flag (does NOT drop — deletion needs a hard reason).
  if (goalTokens && goalTokens.size) {
    for (const r of rows) {
      const act = decided.get(r.id)!
      if (act.action !== 'drop' && act.action !== 'merge' && !act.flag && r.relevance === 0 && gradeVal(r.a.overall.grade) <= 2) {
        act.flag = 'Looks off-goal and low-grade — review whether you still need it.'
        act.flagKind = 'offgoal'
      }
    }
  }

  // 3) GAPS — goal terms no KEPT skill covers (heuristic; verify before acting).
  const gaps: Gap[] = []
  if (goalTokens && goalTokens.size) {
    const covered = new Set<string>()
    for (const r of rows) {
      const act = decided.get(r.id)!
      if (act.action === 'drop' || act.action === 'merge') continue
      for (const t of r.tks) covered.add(t)
    }
    for (const g of goalTokens) {
      if (g.length >= 4 && !hasTerm(covered, g)) gaps.push({ need: g, reason: `No kept skill's description mentions "${g}" — confirm it's covered, or add a skill for it.` })
    }
  }

  // 4) order for display: drop → narrow → merge → optimize → keep; within, by value.
  const ORDER: Record<ActionKind, number> = { drop: 0, narrow: 1, merge: 2, optimize: 3, keep: 4 }
  const withVal = rows.map((r) => ({ act: decided.get(r.id)!, value: r.value }))
  withVal.sort((x, y) => ORDER[x.act.action] - ORDER[y.act.action] || y.value - x.value)
  const actions = withVal.map((w) => w.act)

  // token accounting (DETECTION-level): dropped/merged tokens go away. Per-skill
  // optimize savings are NOT projected here — the optimize runs on the user's click,
  // so detection reports the honest current cost of what's kept.
  let tokensAfter = 0
  for (const r of rows) {
    const act = decided.get(r.id)!
    if (act.action === 'drop' || act.action === 'merge') continue
    tokensAfter += r.a.tokens.total
  }
  const count = (k: ActionKind) => actions.filter((a) => a.action === k).length

  // conflict COUNT for the summary (independent detector; fine with dup names).
  const conflicts = analyzePortfolio(rows.map((r) => ({ name: r.name, description: r.desc }))).conflicts.length

  return {
    actions,
    gaps: gaps.slice(0, 6),
    summary: {
      total: rows.length,
      keep: count('keep'), optimize: count('optimize'), merge: count('merge'), narrow: count('narrow'), drop: count('drop'),
      conflicts,
      tokensNow: rows.reduce((s, r) => s + r.a.tokens.total, 0),
      tokensAfter,
      goal: goal || undefined,
    },
    basis: goal
      ? 'Ranked on measured safety + hygiene + keyword relevance to your goal. Efficacy/lift is added once measured on your model; semantic relevance is the model-powered tier. DROP only for safety failures or near-duplicates.'
      : 'Ranked on measured safety + hygiene + cross-skill conflicts. Add a goal to weight by relevance. Efficacy/lift is added once measured on your model. DROP only for safety failures or near-duplicates.',
  }
}
