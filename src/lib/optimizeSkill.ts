/**
 * optimizeSkill — a real, deterministic "one-click optimize" (no model, free).
 *
 * This is the FIX step, not the detection step. Detection (analyzeSkill) is
 * read-only diagnosis; optimize is the only place a skill is ever rewritten —
 * that separation is both the neutral-authority trust boundary and the CLI red
 * line (scan never writes; optimize emits a rewrite the user chooses to apply).
 *
 * It applies only SAFE mechanical edits (dedupe prose, drop filler, collapse
 * whitespace) that reduce tokens WITHOUT changing behavior, then runs a
 * verify-or-reject gate: it re-analyzes the result and ships it ONLY if the
 * skill is provably not worse (grade/gate not down, no new risk, tokens not up,
 * every fenced code block byte-identical, name/description preserved). If any
 * check fails it reverts to the original — a one-click optimize can never make a
 * skill worse. The riskier fixes (over-broad triggers, embedded scripts, secret
 * access, missing bundled files, tool over-grant) are SUGGESTED, never silently
 * applied — auto-editing logic or the security surface can break a skill. The
 * smarter semantic rewrite is the model-powered tier (optimizePro) behind the
 * same verify gate.
 */
import { analyzeSkill, type SkillAnalysis } from './analyzeSkill'

export interface OptimizeResult {
  optimized: string
  changes: string[]
  /** Detection findings this optimize actually cleared (detect → fix loop closed). */
  resolved: string[]
  suggestions: string[]
  /** True when the rewrite passed the verify gate (or was a clean no-op). */
  verified: boolean
  tokensBefore: number
  tokensAfter: number
  savedPct: number
  gradeBefore: string
  gradeAfter: string
}

const FILLER: { re: RegExp; to?: string; label: string }[] = [
  { re: /\s*It helps you with all of your[^.]*\./gi, label: 'Removed a filler sentence from the description' },
  { re: /\s*and various related things\b\.?/gi, label: 'Removed vague “various related things”' },
  { re: /\bof any kind\b/gi, label: 'Removed “of any kind”' },
  { re: /,?\s*that you should imitate closely[^.]*(?=\n|$)/gi, label: 'Trimmed a verbose example preamble' },
  { re: /\s*(?:very )?carefully step by step\b/gi, label: 'Removed “carefully step by step” padding' },
  // Safe wordiness compression (meaning-preserving) — fewer tokens every call.
  { re: /\bin order to\b/gi, to: 'to', label: 'Shortened “in order to” → “to”' },
  { re: /\bdue to the fact that\b/gi, to: 'because', label: 'Shortened “due to the fact that” → “because”' },
  { re: /\bfor the purpose of\b/gi, to: 'to', label: 'Shortened “for the purpose of” → “to”' },
  { re: /\bin the event that\b/gi, to: 'if', label: 'Shortened “in the event that” → “if”' },
  { re: /\bat this point in time\b/gi, to: 'now', label: 'Shortened “at this point in time” → “now”' },
  { re: /\ba large number of\b/gi, to: 'many', label: 'Shortened “a large number of” → “many”' },
  { re: /\bthe majority of\b/gi, to: 'most', label: 'Shortened “the majority of” → “most”' },
  { re: /\bplease note that\b[\s,]*/gi, label: 'Removed “please note that” filler' },
  { re: /\bit is important to (?:note|remember) that\b[\s,]*/gi, label: 'Removed “it is important to note that” filler' },
]

/** Drop exact/near-duplicate prose lines (never touches fenced code blocks). */
function dedupeProse(md: string): { text: string; removed: number } {
  const lines = md.split('\n')
  const seen = new Set<string>()
  const out: string[] = []
  let inFence = false
  let removed = 0
  for (const line of lines) {
    if (/^\s*```/.test(line)) inFence = !inFence
    // Near-duplicate: same line ignoring case / inner whitespace / trailing
    // punctuation — safe to collapse (it's the same instruction, reformatted).
    const norm = line.trim().toLowerCase().replace(/\s+/g, ' ').replace(/[.!,;:]+$/, '')
    if (!inFence && norm.length > 20) {
      if (seen.has(norm)) {
        removed++
        continue
      }
      seen.add(norm)
    }
    out.push(line)
  }
  return { text: out.join('\n'), removed }
}

/** Fenced code blocks, in order — behavior lives here; optimize must preserve it byte-for-byte. */
function codeBlocks(md: string): string[] {
  return md.match(/```[\s\S]*?```/g) ?? []
}
const GRADE_RANK: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, F: 4 }
const GATE_RANK: Record<string, number> = { pass: 0, review: 1, block: 2 }
const secCats = (a: SkillAnalysis) =>
  new Set(a.findings.filter((f) => f.severity !== 'low').map((f) => f.category))

/**
 * Verify-or-reject gate for the rule-based tier. A one-click optimize must be
 * provably behavior-preserving and never a downgrade. Returns the reason on the
 * FIRST failed invariant (so it's legible), or null when the rewrite is safe.
 */
function verifyReject(before: SkillAnalysis, after: SkillAnalysis, origMd: string, outMd: string): string | null {
  // 1) every fenced code block preserved byte-for-byte (order + content).
  const cb = codeBlocks(origMd)
  const ca = codeBlocks(outMd)
  if (cb.length !== ca.length || cb.some((b, i) => b !== ca[i])) return 'a code block changed'
  // 2) skill identity: name must be unchanged; a present description stays present.
  if ((before.frontmatter.name || '') !== (after.frontmatter.name || '')) return 'the skill name changed'
  if (before.frontmatter.description && !after.frontmatter.description) return 'the description was emptied'
  // 3) grade must not drop.
  if ((GRADE_RANK[after.overall.grade] ?? 9) > (GRADE_RANK[before.overall.grade] ?? 9)) return 'the grade got worse'
  // 4) gate must not get stricter.
  if ((GATE_RANK[after.overall.gate] ?? 9) > (GATE_RANK[before.overall.gate] ?? 9)) return 'the safety gate got worse'
  // 5) no NEW risk category introduced.
  const b = secCats(before)
  for (const c of secCats(after)) if (!b.has(c)) return `a new risk (${c}) appeared`
  // 6) tokens must not increase.
  if (after.tokens.total > before.tokens.total) return 'tokens went up'
  return null
}

export function optimizeSkill(md: string, opts?: { bundleText?: string; bundleFiles?: string[] }): OptimizeResult {
  // opts (from the CLI's readBundle) lets optimize see the SAME findings the scan does
  // — e.g. a dangling references/ link — so its suggestions match. before/after use the
  // identical opts, so the verify gate compares like-for-like.
  const before = analyzeSkill(md, opts)
  const changes: string[] = []
  let out = md.replace(/\r\n/g, '\n')

  const wsTrimmed = out
    .split('\n')
    .map((l) => l.replace(/[ \t]+$/, ''))
    .join('\n')
  if (wsTrimmed !== out) {
    out = wsTrimmed
    changes.push('Trimmed trailing whitespace')
  }

  for (const f of FILLER) {
    if (f.re.test(out)) {
      out = out.replace(f.re, f.to ?? '')
      changes.push(f.label)
    }
  }

  const dd = dedupeProse(out)
  if (dd.removed > 0) {
    out = dd.text
    changes.push(`Removed ${dd.removed} duplicate line${dd.removed > 1 ? 's' : ''}`)
  }

  out = out.replace(/\n{3,}/g, '\n\n').trimEnd() + '\n'

  let after = analyzeSkill(out, opts)

  // Verify-or-reject: a one-click optimize must never make the skill worse. If any
  // safety invariant regressed (should be impossible for these mechanical edits —
  // this is the guarantee, not a hope), revert to the original untouched.
  let verified = true
  if (out !== (md.replace(/\r\n/g, '\n').trimEnd() + '\n')) {
    const reason = verifyReject(before, after, md, out)
    if (reason) {
      out = md
      after = before
      changes.length = 0
      changes.push(`Reverted — kept the original because an edit would have made it worse (${reason}).`)
      verified = false
    }
  }

  const tokensBefore = before.tokens.total
  const tokensAfter = after.tokens.total
  const savedPct = tokensBefore ? Math.max(0, Math.round((1 - tokensAfter / tokensBefore) * 100)) : 0

  // Close the detect → fix loop: which detection findings did the optimize actually
  // clear? (before ∖ after by title). Honest "we fixed these", distinct from the
  // suggestions we deliberately did NOT auto-apply.
  const afterTitles = new Set(after.findings.map((f) => f.title))
  const resolved = verified
    ? [...new Set(before.findings.filter((f) => !afterTitles.has(f.title)).map((f) => f.title))]
    : []

  // Finding-aware suggestions for the fixes we will NOT auto-apply — they touch the
  // security surface, the file layout, or need judgment (that's the Pro/human tier).
  const suggestions: string[] = []
  const has = (re: RegExp) => before.findings.some((f) => re.test(f.title))
  if (has(/too broad/i))
    suggestions.push('Tighten the over-broad trigger (any/all/every) to the specific task it should fire on.')
  if (has(/Monolithic/i))
    suggestions.push('Move the detail sections into references/ files loaded on demand (progressive disclosure) — big per-trigger token win, but it restructures the bundle, so we leave it to you.')
  if (has(/bundled file that isn’t present/i))
    suggestions.push('Ship the missing referenced file(s) or fix the path — the skill will dead-link at load time otherwise.')
  if (has(/Over-declared tools/i))
    suggestions.push('Narrow allowed-tools to what the skill actually uses (least privilege) — we don’t auto-remove a tool in case it’s used in a way we can’t see.')
  if (has(/doesn’t declare Bash/i))
    suggestions.push('Add Bash (scoped to the commands it needs) to allowed-tools, or move the shell out — it will otherwise prompt/fail at runtime.')
  if (before.capabilities.some((cap) => cap.cap === 'exec') || before.findings.some((f) => f.severity === 'critical' && f.category === 'shell'))
    suggestions.push('Replace the embedded shell/script with a read-only tool call so the skill can’t run arbitrary code.')
  // Structured condition ONLY — matching finding TITLES made this fire on the medium
  // exfil note ("Reads credentials and …"), telling users who already use os.environ
  // to "pass secrets via the runtime". high+secret = real key MATERIAL (~/.ssh/id_rsa,
  // cloud creds); a medium secret is os.environ = best practice, nothing to fix.
  if (before.findings.some((f) => f.category === 'secret' && f.severity === 'high'))
    suggestions.push('Stop reading private-key / cloud-credential files directly; take the value from the runtime environment instead.')
  if (before.findings.some((f) => f.category === 'injection'))
    suggestions.push('Delete the instruction-override text (prompt-injection risk).')

  return {
    optimized: out,
    changes,
    resolved,
    suggestions,
    verified,
    tokensBefore,
    tokensAfter,
    savedPct,
    gradeBefore: before.overall.grade,
    gradeAfter: after.overall.grade,
  }
}
