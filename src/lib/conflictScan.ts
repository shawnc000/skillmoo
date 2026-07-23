/**
 * conflictScan — cross-skill conflict detection over a *portfolio* of skills.
 *
 * The single-file health check can't see this: two skills whose descriptions
 * trigger on the same task will fight to fire, and an over-broad skill will
 * shadow (swallow) specific ones. This compares the trigger surface of every
 * pair and reports overlaps + shadowing — the "add the 10th skill and the 3rd
 * silently stops firing" problem, made visible.
 */
import type { Severity } from './analyzeSkill'

export interface SkillMeta {
  name: string
  description: string
}

export interface Conflict {
  a: string
  b: string
  shared: string[]
  kind: 'overlap' | 'shadow'
  severity: Severity
}

export interface PortfolioReport {
  conflicts: Conflict[]
  broad: string[] // skills with over-broad triggers
}

const STOP = new Set([
  'the', 'and', 'for', 'with', 'when', 'use', 'this', 'that', 'its', 'your', 'you',
  'ask', 'from', 'into', 'please', 'before', 'after', 'then', 'will', 'can', 'should',
  'must', 'each', 'some', 'are', 'was', 'been', 'being', 'have', 'has', 'get', 'gets',
  'make', 'made', 'onto', 'about', 'them', 'they', 'their', 'what', 'which', 'whom',
  'user', 'users', 'help', 'helps', 'thing', 'things', 'task', 'tasks', 'want', 'need',
])
const BROAD = /\b(?:any|all|every|whenever|anything|everything)\b/i

/** crude stemmer so review/reviewing/tests/test collapse together */
function stem(w: string): string {
  let s = w.replace(/'s$/, '')
  if (s.endsWith('ing') && s.length > 5) s = s.slice(0, -3)
  else if (s.endsWith('ed') && s.length > 4) s = s.slice(0, -2)
  else if (s.endsWith('es') && s.length > 4) s = s.slice(0, -2)
  else if (s.endsWith('s') && s.length > 3) s = s.slice(0, -1)
  return s
}

// Boilerplate that survives stemming — the words every "Use this skill when the
// user requests X to improve Y" description shares. Stopping them keeps the
// overlap signal on real domain tokens (design, layout, figma…), not filler.
const STEM_STOP = new Set([
  'skill', 'trigger', 'request', 'improv', 'reduc', 'involv', 'provid', 'includ',
  'ensur', 'turn', 'wher', 'qualiti', 'visibl', 'surfac', 'direct', 'matter',
  'prefer', 'handl', 'relat', 'variou', 'gener', 'creat', 'context',
  // Generic action/filler verbs+nouns that carry NO domain-trigger signal — they
  // co-occur across unrelated skills and manufacture phantom overlaps ("ask, work,
  // never"). Kept out so the shared set rests on real domain tokens.
  'ask', 'work', 'want', 'need', 'like', 'even', 'also', 'new', 'one', 'add',
  'over', 'never', 'similar', 'exist', 'mention', 'use', 'make', 'way', 'thing',
  'well', 'good', 'best', 'current', 'right', 'read', 'file', 'fil', 'content', 'edit',
  'modifi', 'open', 'form', 'set', 'run', 'build', 'support', 'allow', 'follow', 'cover',
  // More pure-process/plumbing words that co-occur across unrelated skills and
  // manufacture phantom overlaps (input/output/time/page…). Kept OUT so a "conflict"
  // only ever rests on real DOMAIN trigger words. NB: leave genuine dev-process
  // trigger words (plan/implement/feature/review/test…) IN — two planning skills
  // overlapping on "implementation" is a REAL "which one drives it" competition.
  'input', 'output', 'time', 'text', 'command', 'option', 'value', 'list', 'item',
  'step', 'result', 'session', 'page', 'pag', 'formatt', 'structur', 'complet', 'load',
  'guid', 'guide', 'through', 'integrat', 'toolkit', 'load', 'name', 'type', 'data',
  // The stock "Biases towards retrieval from <X> docs over pre-trained knowledge"
  // sentence Cloudflare (and others) append to every description — pure boilerplate.
  // NB: the crude stemmer leaves these words unchanged (they don't end in s/ed/ing),
  // so the stop entries must be the FULL words, not a guessed stem.
  'bias', 'toward', 'retrieval', 'pre-train', 'pretrain', 'pretrained', 'knowledge', 'doc', 'docs',
])

function triggerTokens(desc: string): Set<string> {
  const words = desc.toLowerCase().match(/[a-z][a-z-]{2,}/g) ?? []
  const out = new Set<string>()
  for (const w of words) {
    if (STOP.has(w)) continue
    if (/^(any|all|every|whenever|anything|everything)$/.test(w)) continue
    const s = stem(w)
    if (STEM_STOP.has(s)) continue
    out.add(s)
  }
  return out
}

const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 }

export function analyzePortfolio(skills: SkillMeta[]): PortfolioReport {
  const enriched = skills
    // Guard against an undefined description: in-app callers pass a string, but this is
    // exported and an untyped/external caller feeding JSON must degrade, not crash.
    .filter((s) => s.description?.trim())
    .map((s) => ({ name: s.name || '(unnamed)', tokens: triggerTokens(s.description), broad: BROAD.test(s.description) }))

  // Document-frequency filter (corpus-adaptive de-boilerplating): a token shared by
  // MORE THAN HALF the portfolio carries no discriminating trigger signal — it is
  // the org's stock phrasing ("cloudflare" in every Cloudflare skill, a shared
  // "biases towards retrieval…" tagline). Counting it manufactures phantom conflicts
  // among unrelated skills. We drop these high-DF tokens BEFORE pairing, but only
  // once the portfolio is large enough (≥6) for DF to be meaningful; on a tiny set
  // every token looks rare, so we skip the filter and rely on the stoplists.
  const N = enriched.length
  const df = new Map<string, number>()
  for (const s of enriched) for (const t of s.tokens) df.set(t, (df.get(t) ?? 0) + 1)
  const dfCap = N >= 6 ? Math.floor(N / 2) : Infinity
  // Each skill's DISCRIMINATIVE trigger set — high-DF boilerplate removed. Both the
  // shared count AND the union (jaccard denominator) use this same filtered set so
  // the ratio stays honest (filtering only the numerator would understate overlap).
  const dtok = enriched.map((s) => new Set([...s.tokens].filter((t) => (df.get(t) ?? 0) <= dfCap)))

  const broad = enriched.filter((s) => s.broad).map((s) => s.name)
  const conflicts: Conflict[] = []

  for (let i = 0; i < enriched.length; i++) {
    for (let j = i + 1; j < enriched.length; j++) {
      const A = enriched[i]
      const B = enriched[j]
      // Same name = a duplicate skill, not a trigger conflict (composePortfolio
      // dedups those) — never report a skill as conflicting with itself.
      if (A.name === B.name) continue
      const shared = [...dtok[i]].filter((t) => dtok[j].has(t))
      if (shared.length === 0) continue
      // Jaccard = shared / union, NOT raw count. Raw count scaled with description
      // length, so two verbose skills sharing a few incidental domain words falsely
      // "conflicted"; the ratio measures real trigger-surface overlap.
      const union = dtok[i].size + dtok[j].size - shared.length
      const jaccard = union > 0 ? shared.length / union : 0

      const eitherBroad = A.broad || B.broad
      if (eitherBroad && (jaccard >= 0.16 || shared.length >= 3)) {
        conflicts.push({ a: A.name, b: B.name, shared, kind: 'shadow', severity: jaccard >= 0.4 ? 'high' : 'medium' })
      } else if (jaccard >= 0.34 && shared.length >= 2) {
        conflicts.push({ a: A.name, b: B.name, shared, kind: 'overlap', severity: jaccard >= 0.55 ? 'high' : 'medium' })
      }
    }
  }

  conflicts.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.shared.length - a.shared.length)
  return { conflicts, broad }
}
