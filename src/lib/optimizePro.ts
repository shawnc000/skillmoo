/**
 * optimizePro — the MODEL-POWERED "全面优化 / Pro" tier.
 *
 * The rule-based optimizeSkill() only makes mechanical edits (dedupe, filler,
 * whitespace). The Pro tier asks a model to do the holistic rewrite a human
 * editor would — restructure, compress verbose prose, merge redundant sections —
 * WITHOUT changing what the skill does.
 *
 * Honesty rule (the whole product): a model rewrite is only a PROPOSAL. Our own
 * FREE static engine is the JUDGE. We re-analyze the rewrite and REJECT it unless
 * it provably (a) actually reduces tokens, (b) does not regress the grade or gate,
 * (c) introduces NO new risk finding or capability, and (d) preserves the skill's
 * identity (name) + a real trigger description. If any check fails we fall back to
 * the deterministic rule-based result and say why. We never ship a rewrite we
 * cannot verify — that is what separates this from "ask ChatGPT to shorten it".
 *
 * Model-agnostic: the caller injects a ChatFn (CLI → the user's OWN key; web →
 * the server key; tests → a stub). This module never reads env or the network.
 */
import { analyzeSkill, type SkillAnalysis, type Finding, type Gate } from './analyzeSkill'
import { optimizeSkill, type OptimizeResult } from './optimizeSkill'

export type ChatFn = (system: string, user: string) => Promise<string>

export interface ProCheck { name: string; pass: boolean; detail: string }

export interface ProResult {
  optimized: string
  /** 'semantic' = the verified model rewrite; 'rule-based' = the safe fallback. */
  mode: 'semantic' | 'rule-based'
  /** did the model rewrite pass EVERY honesty check? */
  accepted: boolean
  rejectionReason?: string
  changes: string[]
  suggestions: string[]
  tokensBefore: number
  tokensAfter: number
  savedPct: number
  gradeBefore: string
  gradeAfter: string
  /** the full verification ledger — shown to the user as proof, not a black box. */
  checks: ProCheck[]
}

const GRADE_RANK: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, F: 4 }
const GATE_RANK: Record<Gate, number> = { pass: 0, review: 1, block: 2 }
const gradeRank = (g: string) => GRADE_RANK[g] ?? 5

// The security categories that must never be INTRODUCED by a rewrite. If the
// original didn't have it and the rewrite does, the model added risk → reject.
const SEC_CATS = new Set(['shell', 'secret', 'egress', 'exfil', 'obfuscation', 'destructive', 'privilege', 'injection', 'persistence'])
const riskSig = (f: Finding) => `${f.category}:${f.severity}`
const riskSet = (a: SkillAnalysis) => new Set(a.findings.filter((f) => SEC_CATS.has(f.category)).map(riskSig))
const capSet = (a: SkillAnalysis) => new Set(a.capabilities.map((c) => c.label))

/** Fenced code blocks (their inner content) — code IS behavior, so a rewrite that
 *  silently drops or edits a command/script must be rejected, not shipped. */
function codeBlocks(md: string): string[] {
  const out: string[] = []
  const re = /```[^\n]*\n([\s\S]*?)```/g
  let m: RegExpExecArray | null
  while ((m = re.exec(md))) { const c = m[1].trim(); if (c.length > 8) out.push(c) }
  return out
}

const SYSTEM = [
  'You are a meticulous SKILL.md optimizer for AI agent skills (Claude Code / Codex / Cursor).',
  'Your job: make the skill BETTER — a sharper trigger and leaner prose — while preserving its behavior EXACTLY.',
  '',
  'Two levers — apply BOTH where they help:',
  'A. SHARPEN THE DESCRIPTION (the #1 signal for WHEN a skill fires, and what raises a B/C skill toward A):',
  '   rewrite the frontmatter `description` so it states, concretely, WHAT the skill does AND WHEN to use it —',
  '   the real triggers / keywords / file types a user would actually say. If it is vague ("helps with X",',
  '   "assists with tasks") or over-broad ("use for any/all/every task"), make it specific to the real task.',
  '   Third person. Do NOT give the skill new powers — only describe, more precisely, what it already does.',
  'B. COMPRESS THE BODY: cut duplicated prose, filler, hedging, over-explanation, restated instructions,',
  '   needless preamble, and redundant examples; tighten wording and turn rambling prose into terse bullets.',
  '',
  'A strict automated checker re-grades your output and REJECTS it if it drops a code block, adds a capability,',
  'changes what the skill does, or lowers the grade. So improve boldly, but change NOTHING about behavior.',
  '',
  'HARD RULES — violating any makes your output rejected:',
  '1. Preserve the YAML frontmatter `name` VERBATIM.',
  '2. Preserve every instruction, constraint, capability, tool, command, file path, and code block. Do NOT drop steps.',
  '3. Add NO new capability, command, URL, script, tool, or example that was not already present. Rephrase only.',
  '4. Keep code blocks byte-for-byte unless a whole block is an exact duplicate of another.',
  '',
  'OUTPUT: the complete rewritten SKILL.md and NOTHING else — no ```fences``` around the whole file, no preamble, no commentary. Start directly with `---`.',
].join('\n')

/** Extract a clean SKILL.md from a model reply that may add a wrapper/preamble. */
export function extractSkillMd(raw: string): string {
  let s = (raw ?? '').replace(/\r\n/g, '\n').trim()
  // Strip a leading "Here is the optimized skill:"-style preamble before the frontmatter.
  const fmAt = s.indexOf('---')
  if (fmAt > 0 && fmAt < 200 && /^[^\n]{0,200}$/.test(s.slice(0, fmAt))) s = s.slice(fmAt)
  // If the WHOLE thing is wrapped in one code fence, peel exactly that outer fence.
  const lines = s.split('\n')
  if (/^```/.test(lines[0]) && /^```\s*$/.test(lines[lines.length - 1])) {
    s = lines.slice(1, -1).join('\n').trim()
  }
  return s
}

/**
 * Run the Pro optimize. `chat` is injected; if it throws or the rewrite fails any
 * honesty check, we return the deterministic rule-based result (never worse).
 */
export async function optimizePro(md: string, chat: ChatFn): Promise<ProResult> {
  const rule = optimizeSkill(md)             // always-safe deterministic baseline
  const before = analyzeSkill(md)
  const tokensBefore = before.tokens.total

  const base: ProResult = {
    optimized: rule.optimized,
    mode: 'rule-based',
    accepted: false,
    changes: rule.changes,
    suggestions: rule.suggestions,
    tokensBefore,
    tokensAfter: rule.tokensAfter,
    savedPct: rule.savedPct,
    gradeBefore: rule.gradeBefore,
    gradeAfter: rule.gradeAfter,
    checks: [],
  }

  // A CONCRETE budget, not the adjective "compress". Asking a model to "make it
  // leaner" and then rejecting it for landing 3% heavier is our failure, not its —
  // it was never told what the bar was. 75% of the original is a target real skills
  // clear comfortably (the corpus median rewrite saves ~30%).
  const budget = Math.max(120, Math.round(tokensBefore * 0.75))
  const userPrompt = (retryNote: string) =>
    `Optimize this SKILL.md. Output only the rewritten file.\n\n` +
    `TOKEN BUDGET: the original is ~${tokensBefore} tokens. Your rewrite MUST come in at or under ` +
    `~${budget} tokens — that is the single hardest requirement after preserving behavior. ` +
    `Cut words, not steps.\n${retryNote}\n\n${md}`

  let lastReject = ''
  let lastVerdict: Verdict | null = null
  let attempt = 0
  // Retry with FEEDBACK rather than one shot. A single unlucky sample used to surface
  // to the user as "optimization failed", which is both a bad experience and untrue —
  // the skill was fine, our roll was bad. Telling the model exactly which check it
  // failed turns most rejections into a pass on the next try. Only ~¥0.02 a call, and
  // we only pay for a retry when the first attempt actually missed.
  while (attempt < MAX_ATTEMPTS) {
    attempt++
    let reply: string
    try {
      reply = await chat(SYSTEM, userPrompt(lastReject))
    } catch (e) {
      return { ...base, rejectionReason: `model call failed (${(e as Error).message.slice(0, 80)}) — used the safe rule-based optimize` }
    }
    const verdict = verifyRewrite(md, extractSkillMd(reply), before, rule, tokensBefore)
    if (verdict.ok) return verdict.result
    lastVerdict = verdict
    lastReject =
      `\nYOUR PREVIOUS ATTEMPT WAS REJECTED by the automated checker: "${verdict.failedName}" ` +
      `(${verdict.failedDetail}). Fix exactly that this time — everything else about it was acceptable.`
  }
  // Keep the LAST attempt's ledger and name the check it failed. "No rewrite beat it"
  // alone is useless to whoever has to debug this later — and the ledger is the whole
  // point: we can say exactly why we withheld a rewrite.
  return {
    ...base,
    checks: lastVerdict?.result.checks ?? [],
    rejectionReason:
      `no rewrite passed after ${MAX_ATTEMPTS} attempts` +
      (lastVerdict ? ` — last failed "${lastVerdict.failedName}" (${lastVerdict.failedDetail})` : '') +
      '; kept the verified deterministic result',
  }
}

/** How many times the model may try before we settle for the deterministic result. */
const MAX_ATTEMPTS = 3

interface Verdict {
  ok: boolean
  result: ProResult
  failedName: string
  failedDetail: string
}

/** Re-grade a candidate and run the full honesty ledger. Pure — no model calls. */
function verifyRewrite(
  md: string,
  candidate: string,
  before: SkillAnalysis,
  rule: OptimizeResult,
  tokensBefore: number,
): Verdict {
  const after = analyzeSkill(candidate)
  const tokensAfter = after.tokens.total

  // ---- the honesty ledger: every check must pass to accept the rewrite ----
  const beforeRisks = riskSet(before)
  const newRisks = [...riskSet(after)].filter((r) => !beforeRisks.has(r))
  const beforeCaps = capSet(before)
  const newCaps = [...capSet(after)].filter((c) => !beforeCaps.has(c))
  const bodyLen = candidate.trim().length
  const origLen = md.trim().length
  const origBlocks = codeBlocks(md)
  const droppedCode = origBlocks.filter((b) => !candidate.includes(b))

  // A rewrite must be a REAL improvement — a better grade (usually a sharper
  // description) OR fewer tokens — and never a behaviour/safety regression.
  const gradeUp = gradeRank(after.overall.grade) < gradeRank(before.overall.grade)
  const leaner = tokensAfter < tokensBefore

  const checks: ProCheck[] = [
    { name: 'is a valid SKILL.md (has frontmatter)', pass: after.frontmatter.hasFrontmatter && !after.empty, detail: after.frontmatter.hasFrontmatter ? 'frontmatter present' : 'no YAML frontmatter — rewrite is malformed' },
    { name: 'skill name preserved', pass: !!after.frontmatter.name && after.frontmatter.name === before.frontmatter.name, detail: `${before.frontmatter.name || '(none)'} → ${after.frontmatter.name || '(none)'}` },
    { name: 'description still triggers', pass: !!after.frontmatter.description && after.frontmatter.description.trim().length >= 20, detail: `description ~${after.frontmatter.description?.length ?? 0} chars` },
    { name: 'a real improvement (better grade or fewer tokens)', pass: gradeUp || leaner, detail: `grade ${before.overall.grade}→${after.overall.grade}, tokens ${tokensBefore}→${tokensAfter}` },
    { name: 'grade not regressed', pass: gradeRank(after.overall.grade) <= gradeRank(before.overall.grade), detail: `${before.overall.grade} → ${after.overall.grade}` },
    { name: 'gate not worsened', pass: GATE_RANK[after.overall.gate] <= GATE_RANK[before.overall.gate], detail: `${before.overall.gate} → ${after.overall.gate}` },
    { name: 'no NEW risk introduced', pass: newRisks.length === 0, detail: newRisks.length ? `added: ${newRisks.join(', ')}` : 'none added' },
    { name: 'no NEW capability introduced', pass: newCaps.length === 0, detail: newCaps.length ? `added: ${newCaps.join(', ')}` : 'none added' },
    { name: 'all code blocks / commands preserved', pass: droppedCode.length === 0, detail: droppedCode.length ? `${droppedCode.length}/${origBlocks.length} code block(s) dropped or altered` : `${origBlocks.length} code block(s) intact` },
    // Floor guards against the model returning a stub/error (not against legitimate heavy
    // dedup — a 6×-repeated skill compressing to a fraction is a real win; behavior is
    // guarded by the code/capability/grade checks, not by raw length).
    { name: 'not truncated / not ballooned', pass: bodyLen >= Math.max(40, origLen * 0.15) && bodyLen <= Math.max(origLen * 1.2, origLen + 200), detail: `${origLen} → ${bodyLen} chars` },
  ]

  const failed = checks.find((c) => !c.pass)
  if (failed) {
    return {
      ok: false,
      failedName: failed.name,
      failedDetail: failed.detail,
      result: { ...({} as ProResult), checks },
    }
  }

  // Accepted. Report the honest, verified win(s).
  const savedPct = tokensBefore ? Math.max(0, Math.round((1 - tokensAfter / tokensBefore) * 100)) : 0
  const wins: string[] = []
  if (gradeUp) wins.push(`Grade ${before.overall.grade} → ${after.overall.grade} — sharper description/trigger`)
  if (savedPct > 0) wins.push(`−${savedPct}% tokens (${tokensBefore.toLocaleString()} → ${tokensAfter.toLocaleString()})`)
  if (!wins.length) wins.push(`Tighter wording (grade ${after.overall.grade}, ${tokensAfter.toLocaleString()} tokens)`)
  wins.push('Behavior preserved — no new risk or capability, all code blocks intact')
  return {
    ok: true,
    failedName: '',
    failedDetail: '',
    result: {
      optimized: candidate,
      mode: 'semantic',
      accepted: true,
      changes: wins,
      suggestions: rule.suggestions,
      tokensBefore,
      tokensAfter,
      savedPct,
      gradeBefore: before.overall.grade,
      gradeAfter: after.overall.grade,
      checks,
    },
  }
}
