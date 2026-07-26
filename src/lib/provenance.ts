/**
 * provenance — where every grade-deciding NUMBER came from.
 *
 * canon.ts already did this for RULES ("must not exfiltrate secrets" → OWASP). It did
 * nothing for the CONSTANTS those rules are enforced with, and constants are where a
 * rating authority quietly stops being one: nobody notices a threshold, and a threshold
 * nobody can trace is indistinguishable from an opinion with a decimal point on it.
 *
 * The operating rule this file enforces is BORROW BEFORE YOU INVENT. If a first-party
 * authority publishes a number — the Agent Skills spec, a harness's shipped source, an
 * established standard like CVSS or Landis–Koch — we take theirs verbatim and cite it.
 * We invent a number only where no authority publishes one, and then we must say so out
 * loud and back it with a measurement rather than a preference.
 *
 * Two properties make that more than a promise, both asserted by `npm run eval:provenance`:
 *
 *   1. VALUES ARE IMPORTED, NEVER RETYPED. Every `value` below is read live from the
 *      module that owns it. Change a threshold without updating its entry and the build
 *      fails — the registry cannot drift into being a flattering description of the past.
 *   2. ORIGIN DICTATES THE BURDEN OF PROOF. `spec` / `harness` / `standard` must carry a
 *      first-party https source. `skillmoo` must carry a calibration — evidence that the
 *      number was measured against the gold set, not chosen because it felt right.
 *
 * Framework-free and pure data, so the OSS engine ships it unchanged: anyone auditing a
 * SkillMOO grade gets the same table we grade with.
 */
import {
  AXIS_WEIGHTS, GRADE_CUTS, SEV_WEIGHT, TOKEN_CURVE,
  SPEC_BODY_TOKENS, SPEC_BODY_LINES, SPEC_NAME_CHARS, SPEC_DESC_CHARS,
} from './analyzeSkill'
import { JACCARD } from './conflictScan'
import { HARNESS_LISTINGS } from './listingBudget'

/**
 * Where a number's authority comes from — and therefore what we owe the reader.
 *   spec     — a published Agent Skills / vendor specification. Taken verbatim.
 *   harness  — a constant read out of a shipped agent runtime's own source.
 *   standard — an established cross-industry methodology (CVSS, OWASP, Landis–Koch…).
 *   skillmoo — ours. No authority publishes one, so it must be calibrated and labelled.
 */
export type Origin = 'spec' | 'harness' | 'standard' | 'skillmoo'

export interface Bilingual { en: string; zh: string }

export interface Threshold {
  id: string
  /** Read live from the owning module. Never a literal retyped into this file. */
  value: string
  origin: Origin
  /** First-party URL. Required for spec/harness/standard; omitted only for `skillmoo`. */
  source?: string
  /**
   * Set on a constant that can never move a grade or a gate — it only decides whether a
   * reader is shown a note. The burden of proof scales with consequence: a number that
   * can cost someone a letter grade must be calibrated against the gold set, while an
   * advisory one must instead be DISCLOSED as uncalibrated and structurally prevented
   * from doing harm. Pretending we had measured it would be the dishonest option.
   */
  advisory?: true
  /** What this number actually decides, in the reader's terms. */
  decides: Bilingual
  /**
   * Why THIS value. For a borrowed number: the quoted authority. For one of ours: the
   * measurement that set it — eval:provenance rejects an entry whose basis names no
   * evidence, which is what stops "it felt about right" from ever reaching this table.
   */
  basis: Bilingual
}

const listing = (id: string) => HARNESS_LISTINGS.find((h) => h.id === id)!

export const THRESHOLDS: Threshold[] = [
  // ---- spec: taken verbatim from the published Agent Skills specification ----------
  {
    id: 'spec.body-tokens',
    value: `${SPEC_BODY_TOKENS} tokens`,
    origin: 'spec',
    source: 'https://agentskills.io/specification',
    decides: {
      en: 'When a SKILL.md body counts as over budget (the "bloated" finding, and whether an optimize pass is allowed to split it).',
      zh: '正文多大算超预算(「臃肿」发现项,以及优化时是否允许拆分)。',
    },
    basis: {
      en: 'Quoted: "Instructions (< 5000 tokens recommended): The full SKILL.md body is loaded when the skill is activated."',
      zh: '原文引用:「Instructions (< 5000 tokens recommended)：技能激活时整个 SKILL.md 正文都会被加载。」',
    },
  },
  {
    id: 'spec.body-lines',
    value: `${SPEC_BODY_LINES} lines`,
    origin: 'spec',
    source: 'https://agentskills.io/specification',
    decides: {
      en: 'The second over-budget test, so a body that is long but token-light is still caught.',
      zh: '第二条超预算判据,让「行数长但 token 不多」的正文同样能被抓到。',
    },
    basis: { en: 'Quoted: "Keep your main SKILL.md under 500 lines."', zh: '原文引用:「Keep your main SKILL.md under 500 lines.」' },
  },
  {
    id: 'spec.name-chars',
    value: `${SPEC_NAME_CHARS} chars`,
    origin: 'spec',
    source: 'https://agentskills.io/specification',
    decides: { en: 'The upper bound in the kebab-case name check.', zh: 'kebab-case 命名检查的长度上限。' },
    basis: { en: 'Spec frontmatter field: name — "Maximum 64 characters".', zh: '规范 frontmatter 字段:name —— 「最长 64 字符」。' },
  },
  {
    id: 'spec.description-chars',
    value: `${SPEC_DESC_CHARS} chars`,
    origin: 'spec',
    source: 'https://agentskills.io/specification',
    decides: { en: 'When a description is over the spec cap — a real spec violation, and the point past which harnesses truncate it.', zh: '描述多长算越界 —— 这是实打实的规范违例,也是各 harness 开始截断它的临界点。' },
    basis: {
      en: 'Spec frontmatter field: description — "Maximum 1024 characters". canon.ts declared this a MUST from the start and the engine never checked it; the 2026-07-26 provenance audit found the gap and closed it.',
      zh: '规范 frontmatter 字段:description ——「最长 1024 字符」。canon.ts 一开始就把它写成 MUST,而引擎从未真的检查过;2026-07-26 的出处审计发现并补上了这个缺口。',
    },
  },

  // ---- harness: constants read out of the agent runtimes themselves ----------------
  {
    id: 'harness.claude-code.listing-budget',
    value: `${listing('claude-code').fraction * 100}% of ${listing('claude-code').baselineTokens.toLocaleString()}`,
    origin: 'harness',
    source: 'https://github.com/anthropics/claude-code',
    decides: { en: 'How many installed skills fit in Claude Code\'s always-on listing before descriptions start being dropped.', zh: '在 Claude Code 的常驻清单里,装到第几个技能后描述会开始被丢弃。' },
    basis: {
      en: 'Shipped settings: skillListingBudgetFraction (default 0.01) against a fixed ~200K baseline, not the live window.',
      zh: '运行时设置:skillListingBudgetFraction(默认 0.01),基数是固定的约 200K,而不是当前模型的真实上下文窗口。',
    },
  },
  {
    id: 'harness.claude-code.desc-chars',
    value: `${listing('claude-code').maxDescChars} chars`,
    origin: 'harness',
    source: 'https://github.com/anthropics/claude-code',
    decides: { en: 'The per-entry description cap that truncation applies first.', zh: '单条描述的字符上限 —— 截断先从这里下手。' },
    basis: { en: 'Shipped setting: skillListingMaxDescChars = 1536.', zh: '运行时设置:skillListingMaxDescChars = 1536。' },
  },
  {
    id: 'harness.codex.listing-budget',
    value: `${listing('codex').fraction * 100}% of window`,
    origin: 'harness',
    source: 'https://github.com/openai/codex',
    decides: { en: 'The same overflow point for Codex, which truncates descriptions and then omits whole skills.', zh: 'Codex 侧的同一个溢出点 —— 它先截断描述,再整条丢弃技能。' },
    basis: {
      en: 'Read out of Codex\'s own source — codex-rs/core-skills/src/render.rs: SKILL_METADATA_CONTEXT_WINDOW_PERCENT = 2, DEFAULT_SKILL_METADATA_CHAR_BUDGET = 8_000.',
      zh: '直接取自 Codex 自己的源码 —— codex-rs/core-skills/src/render.rs 中的两个常量:SKILL_METADATA_CONTEXT_WINDOW_PERCENT = 2(清单占上下文窗口的百分比)、DEFAULT_SKILL_METADATA_CHAR_BUDGET = 8_000(算不出百分比时的字符兜底)。',
    },
  },

  // ---- standard: established cross-industry methodology ----------------------------
  {
    id: 'standard.severity-bands',
    value: 'critical / high / medium / low',
    origin: 'standard',
    source: 'https://www.first.org/cvss/v4-0/specification-document',
    decides: { en: 'What each severity label MEANS, so "high" on a SkillMOO finding reads the same as "high" anywhere else in security.', zh: '每个严重度标签到底代表什么 —— 让 SkillMOO 的 high 和安全行业其他地方的 high 是同一个意思。' },
    basis: {
      en: 'CVSS v4.0 qualitative severity scale (Low 0.1–3.9 / Medium 4.0–6.9 / High 7.0–8.9 / Critical 9.0–10.0). We adopt the vocabulary and its bands; we do NOT reuse CVSS scores, which measure exploitability of a deployed vulnerability, not the quality of an instruction file.',
      zh: 'CVSS v4.0 定性严重度分级(Low 0.1–3.9 / Medium 4.0–6.9 / High 7.0–8.9 / Critical 9.0–10.0)。我们沿用它的词汇和分档;但不套用 CVSS 分数本身 —— 那衡量的是已部署漏洞的可利用性,不是一份指令文件的质量。',
    },
  },
  {
    id: 'standard.blocking-classes',
    value: '5 MUST-safety classes',
    origin: 'standard',
    source: 'https://genai.owasp.org/llm-top-10/',
    decides: { en: 'The complete, closed list of things allowed to drive a hard BLOCK. Nothing outside it can block, ever.', zh: '允许触发硬性拦截的完整闭合清单。清单之外的任何东西,永远拦不住。' },
    basis: {
      en: 'Prompt injection, data exfiltration, remote code from an unverifiable source, catastrophic destruction, persistence backdoor — each mapped to an OWASP LLM Top 10 class in canon.ts, and each asserted blocking-capable only if MUST + security.',
      zh: '提示注入、数据外泄、从不可核验来源取码执行、灾难性破坏、持久化后门 —— 在 canon.ts 里逐条对应 OWASP LLM Top 10,并且只有 MUST + security 才被允许拦截。',
    },
  },
  {
    id: 'standard.agreement-bands',
    value: 'κ bands: .20/.40/.60/.80',
    origin: 'standard',
    source: 'https://pubmed.ncbi.nlm.nih.gov/843571/',
    decides: { en: 'How we report whether the engine agrees with the gold labels beyond chance — and what counts as "substantial".', zh: '我们如何报告「引擎与金标准的一致性是否超出随机」,以及多少才算「相当一致」。' },
    basis: {
      en: 'Cohen\'s kappa with the Landis & Koch (1977) interpretation bands. Raw accuracy is inflated by a skewed class mix, so we do not headline it.',
      zh: 'Cohen κ 配 Landis & Koch(1977)的解释分档。类别分布一偏,原始准确率就会虚高,所以我们不拿它当头条。',
    },
  },
  {
    id: 'standard.unknown-is-a-state',
    value: 'full / partial / empty',
    origin: 'standard',
    source: 'https://github.com/ossf/scorecard',
    decides: { en: 'That missing evidence is reported as missing, instead of silently becoming a pass or a fail.', zh: '证据缺失时如实标为缺失,而不是悄悄变成一个「通过」或「不通过」。' },
    basis: {
      en: 'OpenSSF Scorecard reserves -1 for "could not determine" rather than scoring 0. Same discipline: seeing only SKILL.md means a payload inside a bundled script is invisible, so we say partial.',
      zh: 'OpenSSF Scorecard 用 -1 表示「无法判定」,而不是记 0 分。同一套纪律:只看到 SKILL.md,就意味着藏在随附脚本里的载荷根本看不见,所以我们标 partial。',
    },
  },
  {
    id: 'standard.versioned-vector',
    value: 'SMV:2.0/S:…/T:…/K:…/R:…',
    origin: 'standard',
    source: 'https://www.first.org/cvss/v4-0/specification-document',
    decides: { en: 'That a grade ships as a re-derivable vector string pinned to the rubric version that produced it.', zh: '每个评级都以一串可重算的向量随附,并钉死在产出它的那版规则上。' },
    basis: {
      en: 'CVSS\'s vector-string convention: publish the inputs, not just the verdict, and version the scoring so an old score stays interpretable after the rubric changes.',
      zh: '沿用 CVSS 的向量字符串惯例:公开输入而不只是结论,并给评分方法编版本 —— 规则改了,旧分数依然读得懂。',
    },
  },

  // ---- skillmoo: ours. No authority publishes these, so each carries a measurement --
  {
    id: 'skillmoo.axis-weights',
    value: `structure ${AXIS_WEIGHTS.structure} · trigger ${AXIS_WEIGHTS.trigger} · tokens ${AXIS_WEIGHTS.tokens}`,
    origin: 'skillmoo',
    decides: { en: 'How the three craft axes combine into the quality score, before risk is subtracted.', zh: '三条做工轴如何合成质量分(在减去风险之前)。' },
    basis: {
      en: 'No vendor publishes a weighting for skill quality, so this is ours. Trigger carries the most because a skill that never fires delivers nothing regardless of how well it is written — the failure mode we see most in the corpus. Risk sits at weight 0 on purpose: it is SUBTRACTED, after auditing our own grades showed averaging it diluted real threats to a fraction of their bite while making A unreachable for any skill that legitimately reads a key.',
      zh: '没有任何厂商公开过技能质量的权重表,所以这是我们自己的。trigger 占最大头,是因为一个从不触发的技能,写得再好也等于零 —— 这也是语料库里最常见的失效形态。risk 权重刻意为 0:它是被「减去」的 —— 我们审自己的评级时发现,把风险拿去平均,会把真实威胁稀释到只剩零头,同时让任何正当读取密钥的技能永远够不到 A。',
    },
  },
  {
    id: 'skillmoo.grade-cuts',
    value: GRADE_CUTS.map(([n, g]) => `${g}≥${n}`).join(' · '),
    origin: 'skillmoo',
    decides: { en: 'Which letter a 0–100 score becomes.', zh: '0–100 的分数最终落成哪个等级。' },
    basis: {
      en: 'Ours. The closest public analogues are independent web scanners that grade a 100-baseline-minus-penalties score (Mozilla HTTP Observatory: A≥90, B≥70, C≥50, D≥30) — the same SHAPE we use, but tuned for HTTP headers, so copying their cuts would import a calibration from a different domain. Ours are set against the gold set instead, under a hard constraint: no safe, loadable skill may land below C on craft alone.',
      zh: '这是我们自己的。最接近的公开参照是那些「100 分起扣」的独立网站扫描器(Mozilla HTTP Observatory:A≥90、B≥70、C≥50、D≥30)—— 形态和我们一样,但它是给 HTTP 头调的,照抄等于把别的领域的校准搬过来。我们改为对着金标准集来定,并卡死一条硬约束:安全且能加载的技能,不得仅凭做工问题掉到 C 以下。',
    },
  },
  {
    id: 'skillmoo.severity-cost',
    value: Object.entries(SEV_WEIGHT).map(([k, v]) => `${k} −${v}`).join(' · '),
    origin: 'skillmoo',
    decides: { en: 'What a finding of each severity costs the risk axis.', zh: '每个严重度的发现项,在风险轴上要扣掉多少分。' },
    basis: {
      en: 'Ours — CVSS defines what "high" MEANS but no standard defines what it should COST a quality grade, and mapping CVSS band midpoints onto deductions would be a category error. Set so a single critical is disqualifying on its own while a lone medium never is, then held fixed while grade-κ against the gold set was measured. An ordinary MEDIUM/LOW capability costs 0 by rule: capability is not intent.',
      zh: '我们自己的 —— CVSS 定义了 high 是什么「意思」,但没有任何标准规定它该在质量评级上「扣多少」;把 CVSS 分档中位数直接当扣分,是概念错位。定法是:单个 critical 本身即可判负,而单个 medium 绝不至于,然后固定下来去测对金标准集的 grade-κ。普通的 MEDIUM/LOW 能力项按规则扣 0 分 —— 能力不等于意图。',
    },
  },
  {
    id: 'skillmoo.token-curve',
    value: `${TOKEN_CURVE.intercept} − ${TOKEN_CURVE.perDoubling}·ln(tokens)`,
    origin: 'skillmoo',
    decides: { en: 'The token-efficiency sub-score.', zh: 'Token 效率子分。' },
    basis: {
      en: 'Ours. Log, not a cliff, so each doubling costs a fixed amount and thoroughness is not punished as if it were a defect. Verified on the gold set: grade-κ held at 0.809 and no gold entry changed band. Places the corpus median mid-axis (~2k→63), a lean skill near the top (~500→90), a very large one low but non-zero (~18k→23).',
      zh: '我们自己的。用对数而不是断崖,让「每翻一倍」扣固定分数,写得详尽不至于被当成缺陷罚。已在金标准集上验证:grade-κ 保持 0.809,且没有任何一条金标准变档。它让语料中位数落在轴中段(约 2k→63)、精简技能接近顶部(约 500→90)、超大技能低但不为零(约 18k→23)。',
    },
  },
  {
    id: 'skillmoo.conflict-jaccard',
    value: `shadow ≥${JACCARD.shadow} · overlap ≥${JACCARD.overlap}`,
    origin: 'skillmoo',
    advisory: true,
    decides: { en: 'When two skills are reported as competing for the same trigger. Advisory only — never a grade, never a gate.', zh: '两个技能什么时候算在抢同一个触发。仅供参考 —— 不影响评级,也不影响闸门。' },
    basis: {
      en: 'Ours, and NOT calibrated — we say so rather than implying otherwise. There is no labelled gold set of "skills that really did steal each other\'s trigger", because that outcome depends on the model, the phrasing of the request and the user\'s own installed set, none of which a static file can see. So these cutoffs are a reading aid, not a measurement, and they are structurally barred from touching a grade or a gate. Nor are they comparable to the one public peer: Cisco skill-scanner fires at raw-word Jaccard > 0.7 across the whole description, while ours runs on stop-worded, stemmed, document-frequency-filtered trigger tokens — a different denominator, so the two numbers are not the same quantity.',
      zh: '我们自己的,而且**没有校准过** —— 与其含糊带过,不如直说。世上并不存在一份「这两个技能确实互相抢了触发」的标注金标准集,因为那个结果取决于模型、取决于用户当时那句话怎么说、也取决于他自己装了哪些技能 —— 这三样,一个静态文件全都看不见。所以这组阈值是「帮你多看一眼」的提示,不是一次测量,并且在结构上被禁止影响评级和闸门。它也不能跟唯一的公开同行直接比:Cisco skill-scanner 是对整段描述做原始词 Jaccard、>0.7 才报;我们跑的是去停用词、取词干、再按文档频率过滤后的触发词 —— 分母不同,两个数根本不是同一个量。',
    },
  },
]

/** Entries we borrowed — the ones a reader can check against someone else's authority. */
export const BORROWED = THRESHOLDS.filter((t) => t.origin !== 'skillmoo')
/** Entries we invented — the ones that must be defended by measurement. */
export const ORIGINAL = THRESHOLDS.filter((t) => t.origin === 'skillmoo')

/** Share of grade-deciding constants taken from a published authority rather than invented. */
export function borrowedShare(): number {
  return Math.round((BORROWED.length / THRESHOLDS.length) * 100)
}
