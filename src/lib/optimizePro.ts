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

/** Fenced code blocks — code IS behavior, so a rewrite that silently drops, edits, or
 *  invents a command/script must be rejected, not shipped. Matches BOTH multi-line fences
 *  AND single-line one-liners (```rm -rf .``` on one line) — the old `\n`-requiring regex
 *  missed one-liners, letting a short command be dropped/invented under the radar. Compares
 *  whole blocks (fences included); the >4-char floor ignores empty/noise fences only. */
function codeBlocks(md: string): string[] {
  const src = md.replace(/\r\n/g, '\n')
  const blocks: string[] = []
  // Line-based fence scan handling BOTH ``` and ~~~ fences (multi-line and single-line), so a
  // command in a tilde-fenced block can't be dropped/altered under the radar.
  const lines = src.split('\n')
  let fence: string | null = null, buf: string[] = []
  for (const line of lines) {
    const fm = line.match(/^[\s>]*(`{3,}|~{3,})/)
    // single-line fence: ```cmd``` or ~~~cmd~~~ on one line
    const one = line.match(/^[\s>]*(`{3,}|~{3,})[^\n]*?\1\s*$/)
    if (fence) {
      buf.push(line)
      if (fm && fm[1][0] === fence[0] && fm[1].length >= fence.length) { blocks.push(buf.join('\n').trim()); fence = null; buf = [] }
    } else if (one && one[1].length >= 3) {
      blocks.push(line.trim())
    } else if (fm) { fence = fm[1]; buf = [line] }
  }
  if (buf.length) blocks.push(buf.join('\n').trim()) // unterminated fence → keep what we have
  const fenced = blocks.filter((b) => b.length > 4)
  // Inline `code` that is clearly a COMMAND (a CLI tool + an argument) — code is behavior even
  // inline, so dropping `gh auth login` / `dbmate up` must be caught. A command-shape heuristic
  // (first token an identifier, plus a flag / subcommand / path arg) plus a broad tool list, so
  // a plain prose span (`someVar`, `file.ts`) is not required-to-survive (no false reject).
  const CLI = /^(?:sudo\s+)?(?:gh|git|npm|npx|yarn|pnpm|make|cargo|go|python3?|pip3?|poetry|uv|docker|docker-compose|kubectl|helm|curl|wget|ssh|scp|rsync|rm|cp|mv|mkdir|chmod|chown|ln|tar|systemctl|service|node|deno|bun|terraform|tofu|ansible|vagrant|aws|gcloud|az|heroku|fly|flyctl|vercel|netlify|wrangler|supabase|brew|apt|apt-get|yum|dnf|apk|pacman|bash|sh|zsh|source|export|eval|sqlite3?|psql|mysql|mongo|redis-cli|dbmate|migrate|flyway|alembic|prisma|rails|artisan|manage\.py|gradlew?|mvn|dotnet|cargo|rustc|gcc|clang|ffmpeg|openssl|gpg)\b/i
  const inline: string[] = []
  for (const m of src.matchAll(/`([^`\n]{2,120})`/g)) {
    const s = m[1].trim()
    const before = src.slice(Math.max(0, m.index! - 16), m.index!).toLowerCase()
    // A command shape: a CLI tool with a FLAG or a path, OR a 3+ token invocation, OR any tool
    // span that a RUN context introduces ("running `dbmate up`"). A bare "tool noun" ("`git
    // history`") preceded by an article ("the/a/inspect the") is a PROSE noun phrase, not a command.
    const runContext = /\b(?:run|runs|running|ran|execute|executing|invoke|invoking|exec|call|calling)\s*$/.test(before)
    const proseNoun = /\b(?:the|a|an|this|that|your|its?|our|their)\s*$/.test(before)
    const hasFlagOrPath = /\s--?[a-z]|\s\.?\/|\s[a-z]+\/|["'|>&;]/.test(s)
    const tokens = s.split(/\s+/).length
    if (CLI.test(s) && (hasFlagOrPath || tokens >= 3 || (runContext && !proseNoun))) inline.push(s)
  }
  return [...fenced, ...inline]
}

// A guardrail = a prose line pairing a SAFETY DIRECTIVE with a HIGH-STAKES action. The
// engine credits none of these, so a model rewrite could silently strip one ("Never delete
// without confirming", "Only run against staging, never production") and still look like an
// "improvement". We check each ORIGINAL guardrail LINE survives as a candidate DIRECTIVE
// line with high word overlap — so gutting it (dropping the directive, keeping the nouns
// elsewhere) is caught, while a meaning-preserving reword ("production"→"prod") is allowed.
const SAFETY_DIRECTIVE = /(?:\bnever\b|\balways\b|\bdo not\b|\bdon'?t\b|\bmust\b|\bonly\b|\bensure\b|\bwithout\b|\bbefore\b|\brequire\b|\bask\b|\bconfirm\b|\bverify\b|\bavoid\b|不(?:要|得|能)|必须|务必|禁止|切勿|请勿)/i
// High-stakes concepts widened well beyond delete/deploy to security/ops safety (ssl/tls/cert,
// sanitize/validate/escape, encrypt, auth, expose/leak, rollback, audit) so a guardrail like
// "Never disable SSL verification" / "Always sanitize the response" is recognized.
const HIGH_STAKES = /(?:\bdelet\w*|\bremov\w*|\brm\b|\bdrop\w*|\btruncat\w*|\boverwrit\w*|\bforce\b|\bpush\w*|\bdeploy\w*|\bproduc\w*|\bprod\b|\bstaging\b|\birreversibl\w*|\bdestructiv\w*|\bcredential\w*|\bsecret\w*|\bpassword\w*|\bpermission\w*|\bapproval\b|\bbackup\b|\bback up\b|\bmigrat\w*|\bssl\b|\btls\b|\bcert\w*|\bverif\w*|\bsanitiz\w*|\bvalidat\w*|\bescap\w*|\bencrypt\w*|\bdecrypt\w*|\bauth\w*|\bexpos\w*|\bleak\w*|\brollback\b|\baudit\w*|\bdisabl\w*|\bbypass\w*|\binjection\b|\bexecut\w*|\beval\b|\broot\b|\bsudo\b|删除|生产|部署|凭证|密钥|密码|备份|加密|验证|权限)/i
// A line that OPENS with a strong imperative safety directive is a guardrail on its own —
// "Never disable X", "Always sanitize Y" — regardless of a specific high-stakes noun.
const STRONG_IMPERATIVE = /^[-*>\s]*(?:never|always|must(?:\s+not)?|do\s+not|don'?t|only|ensure|require|under\s+no\s+circumstances)\b/i
const STOP_WORD = new Set(['the', 'a', 'an', 'and', 'or', 'to', 'of', 'in', 'on', 'for', 'with', 'you', 'your', 'it', 'is', 'be', 'this', 'that', 'any', 'all', 'from', 'into', 'not', 'do', 'no'])
const contentWords = (s: string): Set<string> =>
  new Set((s.toLowerCase().match(/[a-z0-9]{3,}/g) || []).filter((w) => !STOP_WORD.has(w)))
/** Guardrail prose lines: a strong-imperative directive, OR a safety directive naming a
 *  high-stakes action. Lowercased. */
function guardrailLines(md: string): string[] {
  return md.replace(/```[\s\S]*?```/g, '').split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length >= 10 && (STRONG_IMPERATIVE.test(l) || (SAFETY_DIRECTIVE.test(l) && HIGH_STAKES.test(l))))
}
// A PROHIBITION marker (the original forbids something) and a PERMISSIVE marker (the rewrite
// now ALLOWS it). We reject only a true INVERSION — a prohibition whose survivor became
// permissive — NOT a meaning-preserving reword into an equivalent positive requirement
// ("Never deploy without a passing test run" → "Only deploy after the tests pass" is fine).
const NEGATION = /\b(?:never|do not|do\s?n'?t|must not|must never|shall not|should not|cannot|can'?t|refuse to|no\s+(?:auto|silent|unattended))\b|不(?:要|得|能|准)|禁止|切勿|请勿|严禁/i
// NB "without approval/confirmation" is intentionally NOT here — it is usually part of a
// PROHIBITION ("never deploy WITHOUT approval" = require approval), so an inversion is signaled
// by whenever/anytime/freely/optional/no-need, not by a "without" clause.
const PERMISSIVE = /\b(?:whenever|any\s?time|freely|at\s+will|as\s+(?:needed|desired|you\s+wish|appropriate)|if\s+(?:desired|you\s+want|needed)|optional(?:ly)?|no\s+need\s+to|feel\s+free|is\s+(?:fine|ok|okay|allowed|permitted|acceptable))\b|随时|无需(?:确认|审批|批准)/i
/** Original guardrail lines with NO surviving candidate directive line (≥60% word overlap AND
 *  the survivor is not a permission-inversion of a prohibition). Catches a gutted OR inverted
 *  directive while allowing an equivalent positive rewording. */
function droppedGuardrails(orig: string, candidate: string): string[] {
  const candLines = guardrailLines(candidate)
  const candSets = candLines.map(contentWords)
  return guardrailLines(orig).filter((g) => {
    const gw = contentWords(g)
    if (gw.size < 2) return false
    const gProhibits = NEGATION.test(g) || /\bonly\b|\bwithout\b|\bmust\b|\bnever\b/i.test(g)
    return !candLines.some((cl, i) => {
      const cw = candSets[i]
      let hit = 0
      for (const w of gw) if (cw.has(w) || [...cw].some((c) => c.startsWith(w.slice(0, 4)) || w.startsWith(c.slice(0, 4)))) hit++
      // 0.45 (not 0.6): an equivalent reword ("Never deploy without a passing test run" →
      // "Only deploy after the tests pass") keeps the action+stakes but drops polarity words;
      // inversion is caught by the PERMISSIVE check, and outright gutting still scores near 0.
      if (hit / gw.size < 0.45) return false
      if (gProhibits && PERMISSIVE.test(cl)) return false // prohibition inverted to a permission
      return true
    })
  })
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
  const mdN = md.replace(/\r\n/g, '\n')
  const candN = candidate.replace(/\r\n/g, '\n')
  const origBlocks = codeBlocks(md)
  const candBlocks = codeBlocks(candidate)
  const droppedCode = origBlocks.filter((b) => !candN.includes(b))
  // Bidirectional: a code block in the candidate that was NOT in the original = the model
  // invented a command (HARD RULE 3). Rejected — code is behavior in both directions.
  const addedCode = candBlocks.filter((b) => !mdN.includes(b))
  // Guardrail LINES in the original with no surviving candidate directive line (≥60% word
  // overlap) — catches a gutted directive even if its nouns survive elsewhere.
  const lostGuardrails = droppedGuardrails(md, candidate)
  // references/ pointers the split injected — a rewrite that drops the pointer orphans the
  // shipped reference file (dead link at load), so require each to survive.
  // Strip a captured trailing sentence-period/punctuation so "references/errors.md." (end of a
  // sentence) doesn't become an unmatchable pointer token that false-rejects a re-punctuated rewrite.
  const refPointers = [...new Set((mdN.match(/references\/[\w./-]+/gi) || []).map((r) => r.toLowerCase().replace(/[.,;:)\]]+$/, '')))].filter((r) => /\.\w+$/.test(r))
  const lostRefs = refPointers.filter((r) => !candN.toLowerCase().includes(r))
  // Named triggers (languages / file types / frameworks) the description advertises. Dropping
  // several = a SEMANTIC scope-narrowing the static trigger subscore can't see (it stays 100).
  // Named triggers = languages/file-types/frameworks AND the head nouns of any ENUMERATED
  // list in the description ("invoices, receipts, purchase orders, and contracts"). Dropping
  // several = a semantic scope-narrowing the static trigger subscore can't see.
  const descKw = (d: string): Set<string> => {
    const kw = new Set<string>()
    for (const m of d.match(/\b(?:python|javascript|typescript|golang?|rust|java|ruby|php|swift|kotlin|scala|elixir|sql|css|html|json|yaml|toml|xml|csv|xlsx?|docx?|pptx?|pdf|markdown|graphql|grpc|react|vue|svelte|angular|django|flask|rails|kubernetes|k8s|docker|terraform|aws|gcp|azure|node|deno|bun)\b|\.[a-z0-9]{2,5}\b/gi) || []) kw.add(m.toLowerCase().replace(/^\./, ''))
    // enumerated OBJECT list (≥3 comma/and/or items) that follows a PREPOSITION — "from
    // invoices, receipts, purchase orders, and contracts" names trigger objects. A list that
    // follows a subject+verb ("it sorts imports, removes variables, and fixes indentation")
    // is a list of ACTIONS the skill performs, not triggers, so we don't require it to survive.
    const enumM = d.match(/\b(?:from|for|of|on|with|into|across|involving|including|about|regarding|such\s+as|between|among|over)\s+((?:[a-z][a-z-]{2,}\s+){0,2}[a-z][a-z-]{2,}(?:s\b)?(?:\s*,\s*(?:and\s+|or\s+)?(?:[a-z][a-z-]{2,}\s+){0,2}[a-z][a-z-]{2,}(?:s\b)?){2,})/i)
    const VERBISH = /(?:s|ed|ing)$/
    if (enumM) for (const item of enumM[1].split(/\s*,\s*|\s+(?:and|or)\s+/i)) {
      const parts = item.trim().split(/\s+/); const head = parts.pop()
      // skip a verb-led item (first token ends in -s/-ed/-ing → likely an action, not an object)
      if (parts[0] && VERBISH.test(parts[0]) && parts.length >= 1) continue
      if (head && head.length >= 3 && !STOP_WORD.has(head.toLowerCase())) kw.add(head.toLowerCase().replace(/s$/, ''))
    }
    return kw
  }
  const origTriggers = descKw(before.frontmatter.description || '')
  const newTriggers = descKw(after.frontmatter.description || '')
  const lostTriggers = [...origTriggers].filter((k) => !newTriggers.has(k) && ![...newTriggers].some((n) => n.startsWith(k.slice(0, 4)) || k.startsWith(n.slice(0, 4))))

  // A rewrite must be a REAL improvement — a better grade (usually a sharper
  // description) OR fewer tokens — and never a behaviour/safety regression.
  const gradeUp = gradeRank(after.overall.grade) < gradeRank(before.overall.grade)
  const leaner = tokensAfter < tokensBefore
  const savedPctV = tokensBefore ? Math.round((1 - tokensAfter / tokensBefore) * 100) : 0
  // The description is intent-affecting (it decides WHEN the skill fires). The Pro job is to
  // SHARPEN it, so a rewrite that lowers the trigger subscore — a vaguer/narrower trigger,
  // even at the same grade band — is a silent behavior change and is rejected.
  const triggerOf = (x: SkillAnalysis) => x.axes.find((ax) => ax.key === 'trigger')?.score ?? 0
  const triggerNotWorse = triggerOf(after) >= triggerOf(before) - 4
  const descChanged = (before.frontmatter.description || '').trim() !== (after.frontmatter.description || '').trim()

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
    { name: 'no code block invented', pass: addedCode.length === 0, detail: addedCode.length ? `${addedCode.length} code block(s) not in the original` : 'no new code' },
    // Safety guardrails are uncredited by the grader, so they need their own line: a rewrite
    // that silently drops "never delete without confirming" / "only run on staging" is rejected.
    { name: 'safety guardrails preserved', pass: lostGuardrails.length === 0, detail: lostGuardrails.length ? `dropped guardrail(s) about: ${lostGuardrails.join(', ')}` : 'all guardrails intact' },
    // The trigger description decides WHEN the skill fires — Pro sharpens it, so a trigger
    // subscore regression (a vaguer/narrower description at the same grade) is a silent
    // behavior change and is rejected.
    { name: 'trigger not weakened', pass: triggerNotWorse, detail: `trigger ${triggerOf(before)}→${triggerOf(after)}` },
    // Semantic trigger coverage: the description must not silently drop named triggers
    // (languages / file types / frameworks). "Python, JS, Go, Rust" → "Python only" keeps the
    // static subscore at 100 but the skill now under-fires; reject if ≥2 named triggers vanish.
    { name: 'named triggers preserved', pass: lostTriggers.length < 2, detail: lostTriggers.length ? `dropped: ${lostTriggers.join(', ')}` : 'trigger scope intact' },
    // A split injected a references/ pointer; dropping it orphans the shipped reference file.
    { name: 'reference pointers preserved', pass: lostRefs.length === 0, detail: lostRefs.length ? `dropped pointer(s): ${lostRefs.join(', ')}` : refPointers.length ? 'references/ intact' : 'no references' },
    // A drastic cut with NO grade gain is likelier gutting than tightening — reject and fall
    // back to the safe rule-based dedup. EXEMPT grade A (it can't rank higher, so an A→A
    // compression could never satisfy gradeUp) — the flagship "rambling A → terse A" case is
    // instead protected by the guardrail / code / trigger / floor checks above.
    { name: 'large cut must earn a better grade (not gutting)', pass: savedPctV < 60 || gradeUp || before.overall.grade === 'A', detail: `−${savedPctV}% tokens, grade ${before.overall.grade}→${after.overall.grade}` },
    // Floor guards against the model returning a stub/error. Raised 15%→22% so an instruction-
    // dense skill can't be 80%-gutted and pass on a token drop; genuine heavy dedup is still
    // fine (guarded by the code/capability/grade/guardrail checks, not by raw length alone).
    { name: 'not truncated / not ballooned', pass: bodyLen >= Math.max(60, origLen * 0.22) && bodyLen <= Math.max(origLen * 1.2, origLen + 200), detail: `${origLen} → ${bodyLen} chars` },
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
  // The description decides WHEN the skill fires — surface the change so the user can confirm
  // the new trigger matches their intent (it is not silently applied without being shown).
  if (descChanged) wins.push(`Trigger description updated — confirm it still matches your intent: “${(after.frontmatter.description || '').trim()}”`)
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
