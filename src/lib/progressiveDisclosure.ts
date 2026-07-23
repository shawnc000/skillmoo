/**
 * progressiveDisclosure — a DETERMINISTIC, verify-safe "actually do it" fix for the
 * #1 token lever: a monolithic SKILL.md that pays its whole cost on every call.
 *
 * The rule-based optimize only TRIMS; it (correctly) refuses to rewrite meaning. But
 * the biggest honest win — moving detail into on-demand `references/` files — is
 * MECHANICAL, not semantic: we relocate whole sections verbatim and leave a pointer.
 * Nothing is invented, nothing is lost. So instead of only SUGGESTING it, we DO it and
 * hand the user the restructured result (a lean SKILL.md + a references file), so a
 * novice gets the fix, not homework.
 *
 * Behaviour-preserving by construction + a verify gate: every original code block still
 * exists in the union (SKILL.md ∪ references), the re-graded lean skill is leaner and
 * never worse (grade/gate/risk), or we don't apply it. Pure — no I/O, no model, no egress.
 */
import { analyzeSkill, estimateTokens, type SkillAnalysis } from './analyzeSkill'

export interface SplitFile { path: string; content: string }
export interface SplitResult {
  applied: boolean
  /** the lean SKILL.md (or the original, unchanged, when not applied) */
  skillMd: string
  /** generated on-demand files (references/…) */
  files: SplitFile[]
  /** headings relocated into references/ */
  movedSections: string[]
  tokensBefore: number
  tokensAfter: number
  savedPct: number
  gradeBefore: string
  gradeAfter: string
  verified: boolean
  /** why it was not applied (or the safety reason it reverted) */
  reason?: string
}

const GRADE_RANK: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, F: 4 }
const GATE_RANK: Record<string, number> = { pass: 0, review: 1, block: 2 }
const codeBlocks = (md: string): string[] => md.match(/```[\s\S]*?```/g) ?? []

/** Fence-aware split of a body into an intro (before the first H2) + H2 sections.
 *  Never splits on a `## ` that sits inside a fenced code block. */
function splitSections(body: string): { intro: string; sections: { heading: string; text: string }[] } {
  const introLines: string[] = []
  const sections: { heading: string; lines: string[] }[] = []
  let cur: { heading: string; lines: string[] } | null = null
  let inFence = false
  for (const line of body.split('\n')) {
    if (/^\s*```/.test(line)) inFence = !inFence
    if (!inFence && /^##\s+/.test(line)) {
      cur = { heading: line.replace(/^#+\s*/, '').trim(), lines: [line] }
      sections.push(cur)
    } else if (cur) cur.lines.push(line)
    else introLines.push(line)
  }
  return { intro: introLines.join('\n'), sections: sections.map((s) => ({ heading: s.heading, text: s.lines.join('\n') })) }
}

function verifySplit(before: SkillAnalysis, after: SkillAnalysis, tb: number, ta: number): string | null {
  if (ta >= tb) return 'the SKILL.md would not get leaner'
  if ((GRADE_RANK[after.overall.grade] ?? 9) > (GRADE_RANK[before.overall.grade] ?? 9)) return 'the grade would get worse'
  if ((GATE_RANK[after.overall.gate] ?? 9) > (GATE_RANK[before.overall.gate] ?? 9)) return 'the safety gate would get worse'
  const b = new Set(before.findings.filter((f) => f.severity !== 'low').map((f) => f.category))
  for (const f of after.findings) if (f.severity !== 'low' && !b.has(f.category)) return `a new risk (${f.category}) would appear`
  return null
}

/**
 * Restructure a monolithic skill into a lean SKILL.md + a references/ file, moving the
 * largest detail sections off the always-loaded surface. Returns applied:false (with a
 * reason) whenever it isn't safe or worthwhile — a no-op is always allowed.
 */
export function splitProgressive(md: string, opts?: { bundleText?: string; bundleFiles?: string[] }): SplitResult {
  const norm = (md ?? '').replace(/\r\n/g, '\n')
  const before = analyzeSkill(norm, opts)
  const tokensBefore = before.tokens.total
  const notApplied = (reason: string): SplitResult => ({ applied: false, skillMd: norm, files: [], movedSections: [], tokensBefore, tokensAfter: tokensBefore, savedPct: 0, gradeBefore: before.overall.grade, gradeAfter: before.overall.grade, verified: false, reason })

  const fmM = norm.match(/^﻿?\s*---\s*\n[\s\S]*?\n---\s*\n?/)
  const fmBlock = fmM ? fmM[0] : ''
  const name = before.frontmatter.name || 'skill'
  const body = fmM ? norm.slice(fmM[0].length) : norm

  // Guardrails: only a genuinely bloated, multi-section skill that doesn't already defer.
  if (/(?:references?|scripts?|assets?)\//i.test(norm)) return notApplied('already uses references/ — progressive disclosure is in place')
  if (tokensBefore < 700) return notApplied('already lean — nothing worth deferring')
  const { intro, sections } = splitSections(body)
  if (sections.length < 3) return notApplied('not enough distinct sections to split safely')

  // Move the largest sections until the SKILL.md is lean, always keeping the intro and at
  // least the single smallest section inline so the operational core stays in SKILL.md.
  const sized = sections.map((s, i) => ({ ...s, i, tok: estimateTokens(s.text) }))
  const keepInline = [...sized].sort((a, b) => a.tok - b.tok)[0]
  const LEAN_TARGET = 500
  const moved: typeof sized = []
  let running = tokensBefore
  for (const s of [...sized].filter((s) => s.i !== keepInline.i).sort((a, b) => b.tok - a.tok)) {
    if (running <= LEAN_TARGET) break
    moved.push(s)
    running -= s.tok
  }
  if (moved.length < 2) return notApplied('splitting would not defer enough to be worth it')

  const movedSet = new Set(moved.map((m) => m.i))
  const kept = sized.filter((s) => !movedSet.has(s.i)).sort((a, b) => a.i - b.i)
  const movedOrdered = sized.filter((s) => movedSet.has(s.i)).sort((a, b) => a.i - b.i)

  const refPath = 'references/details.md'
  const toc = movedOrdered.map((s) => `- ${s.heading}`).join('\n')
  const refContent =
    `# ${name} — reference\n\n> Detailed material for the \`${name}\` skill. Loaded on demand, so it costs no tokens until the agent needs it.\n\n` +
    `## Contents\n${toc}\n\n${movedOrdered.map((s) => s.text.trim()).join('\n\n')}\n`

  const pointer = `## Reference\n\nDetailed guidance lives in [\`${refPath}\`](${refPath}), loaded on demand: ${movedOrdered.map((s) => s.heading).join(', ')}.\n`
  const skillMd = (`${fmBlock}${intro.trim()}\n\n${kept.map((s) => s.text.trim()).join('\n\n')}\n\n${pointer}`).replace(/\n{3,}/g, '\n\n').trimEnd() + '\n'
  const files: SplitFile[] = [{ path: refPath, content: refContent }]

  // Verify — behaviour-preserving for a SPLIT: all original code survives in the union,
  // and the re-graded lean skill (with the reference present) is leaner and not worse.
  const union = `${skillMd}\n${refContent}`
  const oc = codeBlocks(norm)
  const uc = codeBlocks(union)
  if (oc.length !== uc.length || oc.some((b) => !union.includes(b))) return notApplied('a code block would be lost in the split')

  const after = analyzeSkill(skillMd, {
    bundleFiles: [...(opts?.bundleFiles ?? []), refPath],
    bundleText: `${opts?.bundleText ?? ''}\n${refContent}`,
  })
  const tokensAfter = after.tokens.total
  const reason = verifySplit(before, after, tokensBefore, tokensAfter)
  if (reason) return notApplied(reason)

  const savedPct = tokensBefore ? Math.max(0, Math.round((1 - tokensAfter / tokensBefore) * 100)) : 0
  if (savedPct < 15) return notApplied('the token saving would be too small to be worth restructuring')

  return { applied: true, skillMd, files, movedSections: movedOrdered.map((s) => s.heading), tokensBefore, tokensAfter, savedPct, gradeBefore: before.overall.grade, gradeAfter: after.overall.grade, verified: true }
}
