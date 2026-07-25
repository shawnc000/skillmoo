/**
 * detectionResult — the SIX results every scan reports, in one shape, in both languages.
 *
 * The contract is that a reader always gets the same six answers, and that an answer we
 * cannot compute says so instead of going missing. A field that silently disappears reads
 * as "clean"; a field that says "needs ≥2 skills" reads as what it is. That difference is
 * the whole reason this file exists rather than each component assembling its own subset.
 *
 *   1 Security grade   A–F                        — analyzeSkill
 *   2 Gate             pass / review / block      — analyzeSkill
 *   3 Token size       always-on vs on-activation, against the spec's budget
 *   4 Risk evidence    the located citations behind the risk verdict
 *   5 Trigger quality  will it fire, and only when it should
 *   6 Conflict level   PORTFOLIO-level: undeterminable from one skill, and it says so
 *
 * Framework-free on purpose: the React app, the static page generator and the CLI all
 * render from this, so the wording can never drift between them. No numbers are invented
 * here — it only reads what the engines measured.
 */
import type { SkillAnalysis, Finding, FindingEvidence, Gate } from './analyzeSkill'
import { SPEC_BODY_TOKENS, SPEC_BODY_LINES } from './analyzeSkill'
import type { PortfolioReport } from './conflictScan'

export type Lang = 'en' | 'zh'

/**
 * How a finding title gets localized. Injected rather than owned: the app already ships a
 * 63-entry engine dictionary (src/i18n/engineZh), and a second copy in here would drift
 * out of sync the first time a rule is renamed. This file stays framework- and
 * app-agnostic so the public MIT engine can ship it unchanged; callers without a
 * translator get English, which is honest rather than guessed.
 */
export type Translate = (title: string) => string
const identity: Translate = (t) => t
export type ResultState = 'ok' | 'warn' | 'bad' | 'unknown'

export interface ResultField {
  key: 'grade' | 'gate' | 'tokens' | 'evidence' | 'trigger' | 'conflict'
  /** localized field name */
  label: string
  /** the headline answer, already localized */
  value: string
  /** one line of plain-language meaning — never a bare number */
  note: string
  state: ResultState
  /** citations, for the evidence field */
  citations?: (FindingEvidence & { title: string; severity: string })[]
}

export interface DetectionResult {
  lang: Lang
  fields: ResultField[]
  /** true when every field could actually be computed */
  complete: boolean
}

const T = {
  grade: { en: 'Security grade', zh: '安全评级' },
  gate: { en: 'Gate', zh: '闸门' },
  tokens: { en: 'Token size', zh: 'Token 体积' },
  evidence: { en: 'Risk evidence', zh: '风险证据' },
  trigger: { en: 'Trigger quality', zh: '触发质量' },
  conflict: { en: 'Conflict level', zh: '冲突程度' },
} as const

/** The gate words, spelled out. A coloured badge alone does not tell a reader the verdict. */
const GATE_WORD: Record<Gate, { en: string; zh: string }> = {
  pass: { en: 'PASS', zh: '通过' },
  review: { en: 'REVIEW', zh: '待复核' },
  block: { en: 'BLOCK', zh: '拦截' },
}
const GATE_NOTE: Record<Gate, { en: string; zh: string }> = {
  pass: { en: 'No must-fix safety problem found — safe to install.', zh: '没有必须修的安全问题——可以安装。' },
  review: { en: 'It can do something powerful. Not proof of malice — read what it does before installing.', zh: '它具备某种强能力。这不等于有恶意——安装前先看清它做什么。' },
  block: { en: 'An unambiguous safety problem. Do not install.', zh: '存在明确的安全问题。不要安装。' },
}

const pick = (s: { en: string; zh: string }, lang: Lang) => s[lang]
const n = (x: number) => x.toLocaleString('en-US')

function gradeField(a: SkillAnalysis, lang: Lang): ResultField {
  const g = a.overall.grade
  const state: ResultState = g === 'A' || g === 'B' ? 'ok' : g === 'C' ? 'warn' : 'bad'
  return {
    key: 'grade',
    label: pick(T.grade, lang),
    value: g,
    note: lang === 'zh'
      ? `${a.overall.score}/100 · 同一份文件永远得到同一个评级(规则版本 ${a.vector.version})`
      : `${a.overall.score}/100 · the same file always gets the same grade (rubric ${a.vector.version})`,
    state,
  }
}

function gateField(a: SkillAnalysis, lang: Lang): ResultField {
  const gate = a.overall.gate
  return {
    key: 'gate',
    label: pick(T.gate, lang),
    value: pick(GATE_WORD[gate], lang),
    note: pick(GATE_NOTE[gate], lang),
    state: gate === 'pass' ? 'ok' : gate === 'review' ? 'warn' : 'bad',
  }
}

/**
 * Token size, split the way the harness actually bills it. The metadata is in the system
 * prompt every turn whether or not the skill fires; the body is only paid on activation.
 * Reporting one number for both overstates the standing cost by an order of magnitude.
 */
function tokenField(a: SkillAnalysis, lang: Lang): ResultField {
  const alwaysOn = a.tokens.description + 8 // name + description + the listing's own framing
  const body = a.tokens.body
  const overTokens = body > SPEC_BODY_TOKENS
  return {
    key: 'tokens',
    label: pick(T.tokens, lang),
    value: lang === 'zh' ? `常驻 ${n(alwaysOn)} · 触发时 ${n(body)}` : `${n(alwaysOn)} always-on · ${n(body)} on activation`,
    note: lang === 'zh'
      ? `常驻部分每一轮对话都要付,不管它有没有触发;正文只在触发时加载。官方建议正文低于 ${n(SPEC_BODY_TOKENS)} token、${SPEC_BODY_LINES} 行——目前${overTokens ? '**已超出**' : `用了预算的 ${Math.round((body / SPEC_BODY_TOKENS) * 100)}%`}。`
      : `The always-on part is billed every turn whether it fires or not; the body loads only on activation. The spec recommends a body under ${n(SPEC_BODY_TOKENS)} tokens and ${SPEC_BODY_LINES} lines — this is ${overTokens ? '**over budget**' : `at ${Math.round((body / SPEC_BODY_TOKENS) * 100)}% of it`}.`,
    state: overTokens ? 'warn' : 'ok',
  }
}

/**
 * Risk evidence — the citations, not a restatement of the grade. A verdict a stranger
 * cannot check is an opinion, so this field reports WHERE each risk finding lives and
 * says plainly when a finding could not be pinned to a line.
 */
function evidenceField(a: SkillAnalysis, lang: Lang, tr: Translate): ResultField {
  const RISKY = new Set(['injection', 'persistence', 'obfuscation', 'exfil', 'shell', 'secret', 'network', 'privilege', 'install', 'filesystem'])
  const risky = a.findings.filter((f: Finding) => RISKY.has(f.category) && f.severity !== 'low')
  const cited = risky.filter((f) => f.evidence)
  const citations = cited.map((f) => ({ ...(f.evidence as FindingEvidence), title: tr(f.title), severity: f.severity }))

  if (risky.length === 0) {
    return {
      key: 'evidence',
      label: pick(T.evidence, lang),
      value: lang === 'zh' ? '无风险发现' : 'No risk findings',
      note: lang === 'zh'
        ? `风险轴 ${a.risk.score}/100(${a.risk.level})。没有发现需要举证的风险行为。`
        : `Risk axis ${a.risk.score}/100 (${a.risk.level}). Nothing risky to cite.`,
      state: 'ok',
      citations: [],
    }
  }
  const uncited = risky.length - cited.length
  return {
    key: 'evidence',
    label: pick(T.evidence, lang),
    value: lang === 'zh' ? `${cited.length}/${risky.length} 条已定位到行` : `${cited.length}/${risky.length} pinned to a line`,
    note: lang === 'zh'
      ? `每条都给出行号和原文,你可以自己去核。${uncited > 0 ? `其中 ${uncited} 条是整体判定,无法指向单独一行。` : ''}`
      : `Each carries a line number and the matched text, so you can check it yourself.${uncited > 0 ? ` ${uncited} of them are whole-file verdicts with no single line to point at.` : ''}`,
    state: a.findings.some((f) => f.severity === 'critical') ? 'bad' : 'warn',
    citations,
  }
}

function triggerField(a: SkillAnalysis, lang: Lang, tr: Translate): ResultField {
  const axis = a.axes.find((x) => x.key === 'trigger')
  const score = axis?.score ?? 0
  const issues = a.findings.filter((f) => f.category === 'trigger')
  const state: ResultState = score >= 85 ? 'ok' : score >= 60 ? 'warn' : 'bad'
  return {
    key: 'trigger',
    label: pick(T.trigger, lang),
    value: `${score}/100`,
    note: issues.length
      ? issues.map((f) => tr(f.title)).join(' · ')
      : (lang === 'zh'
        ? '描述说清了「做什么」和「什么时候用」——该触发时会触发,不该触发时不会抢。'
        : 'The description states what it does and when to use it — it should fire when wanted and not steal other requests.'),
    state,
  }
}

/**
 * Conflict level is a property of a SET, so one skill cannot answer it. Rather than hide
 * the field, it reports that the answer needs more than one skill — the honest state.
 */
function conflictField(portfolio: PortfolioReport | undefined, count: number, lang: Lang): ResultField {
  if (!portfolio || count < 2) {
    return {
      key: 'conflict',
      label: pick(T.conflict, lang),
      value: lang === 'zh' ? '需 ≥2 个技能' : 'Needs ≥2 skills',
      note: lang === 'zh'
        ? '冲突是「技能之间」的问题:两个描述抢同一类请求时才会互相压制。扫描你安装的整套技能才能判定。'
        : 'Conflict lives BETWEEN skills: two descriptions competing for the same request suppress each other. Scan your whole installed set to get this.',
      state: 'unknown',
    }
  }
  const shadow = portfolio.conflicts.filter((c) => c.kind === 'shadow').length
  const overlap = portfolio.conflicts.length - shadow
  const total = portfolio.conflicts.length
  const state: ResultState = total === 0 ? 'ok' : shadow > 0 ? 'bad' : 'warn'
  return {
    key: 'conflict',
    label: pick(T.conflict, lang),
    value: total === 0
      ? (lang === 'zh' ? '无冲突' : 'None')
      : (lang === 'zh' ? `${total} 对(遮蔽 ${shadow} · 重叠 ${overlap})` : `${total} pair${total > 1 ? 's' : ''} (${shadow} shadow · ${overlap} overlap)`),
    note: total === 0
      ? (lang === 'zh' ? `已比对 ${count} 个技能的触发面,两两之间没有争抢。` : `Compared the trigger surface of all ${count} skills — none compete.`)
      : (lang === 'zh'
        ? '「遮蔽」= 一个描述过宽的技能会吞掉更具体的那个;「重叠」= 两者抢同一类请求。收窄其中一个的描述即可解开。'
        : 'A “shadow” is an over-broad skill swallowing a specific one; an “overlap” is two skills competing for the same request. Narrowing one description resolves it.'),
    state,
  }
}

/**
 * Assemble all six. `portfolio` + `skillCount` are optional: pass them when scanning an
 * installed set so conflict can be answered; omit them for a single skill and the field
 * reports that it needs more than one.
 */
export function detectionResult(
  a: SkillAnalysis,
  lang: Lang,
  ctx?: { portfolio?: PortfolioReport; skillCount?: number; translate?: Translate },
): DetectionResult {
  const tr = lang === 'zh' ? (ctx?.translate ?? identity) : identity
  const fields = [
    gradeField(a, lang),
    gateField(a, lang),
    tokenField(a, lang),
    evidenceField(a, lang, tr),
    triggerField(a, lang, tr),
    conflictField(ctx?.portfolio, ctx?.skillCount ?? 1, lang),
  ]
  return { lang, fields, complete: fields.every((f) => f.state !== 'unknown') }
}
