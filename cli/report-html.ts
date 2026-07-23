/**
 * report-html — turn a scan into a self-contained, shareable HTML report.
 * No backend, no network: the CLI writes this file locally. Same visual
 * language as the site (light charcoal + orange signal, grade badges). Bilingual: pass
 * `lang: 'zh'` in the data (web sets it from the UI; CLI detects the locale).
 */
import type { Finding, Severity } from '../src/lib/analyzeSkill'
import type { Conflict } from '../src/lib/conflictScan'
import { zhFinding, zhDetail, zhChange } from '../src/i18n/engineZh.js'

export interface ReportSkill {
  name: string; source: string; path: string; a: { findings: Finding[] }
  tokens: number; grade: string; unsafe: boolean; review: boolean; bloated: boolean; bloatRatio: number; reason: string
  /** Present ONLY when optimize was computed (content stayed local) — enables the
   *  report page's one-click optimize / restore from stats. */
  optTokens?: number
  savedPct?: number
  changes?: string[]
}
export interface ReportData {
  generatedAt: string
  locations: { source: string; dir: string; count: number }[]
  skills: ReportSkill[]
  conflicts: Conflict[]
  broad: string[]
  median: number
  bloatThresh: number
  /** true when this report carries per-skill optimize stats. */
  optimizable?: boolean
  /** report language (defaults to en). */
  lang?: 'en' | 'zh'
}

type Lang = 'en' | 'zh'
const Z = {
  en: {
    docTitle: 'SkillMOO scan report', h1: 'Your skill footprint', skills: 'skills',
    tSkills: 'skills', tUnsafe: 'unsafe', tReview: 'review', tBloated: 'bloated', tConflicts: 'conflicts', tMedian: 'median tok',
    mUnsafe: 'unsafe', mReview: 'review', mBloated: 'bloated', mOk: 'ok',
    median: 'median', tok: 'tok',
    skillsH2: (ok: number, att: number) => `Skills · ${ok} clean, ${att} need attention`,
    conflictsH2: (n: number, top: boolean) => `Conflicts · ${n} pairs${top ? ' (top 20)' : ''}`,
    shadow: 'shadow', overlap: 'overlap', broad: 'Over-broad triggers: ',
    copyLink: 'Copy link', copiedLink: 'Copied link ✓', optimize: 'One-click optimize', restore: 'Restore original',
    savesum: (pct: number, before: string, after: string) => `Optimized — saves <b>${pct}%</b> (${before} → ${after} tok/run). Rule-based, safe.`,
    shareView: 'Shareable report — anyone with the link can view.',
    optimized: 'optimized',
    healthT: 'Portfolio health', clean: 'clean', tOk: 'clean',
    optCta: 'One-click optimize →', optLean: 'Already lean — nothing to safely auto-trim. The semantic rewrite (Pro) can still tighten wording at ',
    optLeanPill: '✓ Already lean', getFile: 'Want the rewritten file? Run <code>npx skillmoo optimize &lt;file&gt;</code> locally — it prints to your screen and never touches your files.',
    verdictOk: 'clean · passes safety + bloat + conflict checks', verdictReason: (r: string) => `flagged: ${r}`,
    capsL: 'What it can do:', moreF: (k: number) => `+${k} more finding${k > 1 ? 's' : ''}`,
    emptyH: 'No analyzable skill found',
    emptyP: 'We couldn’t find a valid SKILL.md in what was submitted, so there’s nothing to grade yet — this is NOT an error with your skill, just that the input wasn’t a recognizable skill file.',
    emptyWhy: [
      'A valid skill is a <code>SKILL.md</code> file that opens with YAML frontmatter (at least <code>name:</code> and <code>description:</code>).',
      'Pasting a README, a script, or an empty file won’t match — the parser needs that frontmatter.',
      'For a FULL audit, submit the whole skill <b>folder</b> (or its ZIP) so bundled <code>references/</code> + <code>scripts/</code> get scanned too — not just the SKILL.md.',
    ],
    emptyCta: 'Re-run <code>npx skillmoo scan</code> in your project, or drop the skill folder at <a href="https://skillmoo.com">skillmoo.com</a>.',
    foot: 'Safety &amp; bloat are real static analysis. One-click optimize is the rule-based, safe tier; the semantic rewrite lives at <a href="https://skillmoo.com">skillmoo.com</a>. Ratings are never for sale.',
  },
  zh: {
    docTitle: 'SkillMOO 检测报告', h1: '你的技能画像', skills: '个技能',
    tSkills: '技能', tUnsafe: '不安全', tReview: '待复核', tBloated: '臃肿', tConflicts: '冲突', tMedian: '中位 token',
    mUnsafe: '不安全', mReview: '待复核', mBloated: '臃肿', mOk: '正常',
    median: '中位', tok: 'token',
    skillsH2: (ok: number, att: number) => `技能 · ${ok} 个干净，${att} 个需注意`,
    conflictsH2: (n: number, top: boolean) => `冲突 · ${n} 对${top ? '（前 20）' : ''}`,
    shadow: '遮蔽', overlap: '重叠', broad: '过于宽泛的触发：',
    copyLink: '复制链接', copiedLink: '已复制链接 ✓', optimize: '一键优化', restore: '恢复原版',
    savesum: (pct: number, before: string, after: string) => `已优化 —— 每次调用省 <b>${pct}%</b>（${before} → ${after} token）。规则级、安全。`,
    shareView: '可分享报告——任何拿到链接的人都能查看。',
    optimized: '已优化',
    healthT: '技能组合健康度', clean: '个干净', tOk: '干净',
    optCta: '一键优化 →', optLean: '已经很精简——没有可安全自动裁剪的部分。语义级改写(Pro)仍能进一步收紧措辞：',
    optLeanPill: '✓ 已经很精简', getFile: '想拿到改写后的文件？在本地跑 <code>npx skillmoo optimize &lt;文件&gt;</code>——它只输出到屏幕,绝不改动你的任何文件。',
    verdictOk: '干净 · 通过安全 + 臃肿 + 冲突检查', verdictReason: (r: string) => `已标记：${r}`,
    capsL: '它能做什么：', moreF: (k: number) => `另有 ${k} 项发现`,
    emptyH: '没有检测到可分析的技能',
    emptyP: '提交的内容里没找到有效的 SKILL.md,所以暂时没有可评级的对象——这不是你技能的问题,只是输入不是可识别的技能文件。',
    emptyWhy: [
      '有效技能是一个 <code>SKILL.md</code> 文件,开头是 YAML frontmatter(至少有 <code>name:</code> 和 <code>description:</code>)。',
      '粘贴 README、脚本或空文件都匹配不上——解析器需要那段 frontmatter。',
      '要做<b>完整</b>审计,请提交整个技能<b>文件夹</b>(或其 ZIP),这样捆绑的 <code>references/</code> + <code>scripts/</code> 也会一并扫描——而不只是 SKILL.md。',
    ],
    emptyCta: '在你项目里跑 <code>npx skillmoo scan</code>,或把技能文件夹拖到 <a href="https://skillmoo.com">skillmoo.com</a>。',
    foot: '安全与臃肿是真实的静态分析。一键优化是规则级安全档；语义级改写在 <a href="https://skillmoo.com">skillmoo.com</a>。评级永不出售。',
  },
} satisfies Record<Lang, Record<string, unknown>>

const esc = (s: string) => s.replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]!))
const gColor = (g: string) => (g === 'A' || g === 'B' ? '#12a877' : g === 'C' ? '#d98800' : g === 'D' ? '#e06a2c' : '#e23d4b')
const gBg = (g: string) => (g === 'A' || g === 'B' ? 'rgba(18,168,119,.14)' : g === 'C' ? 'rgba(217,136,0,.14)' : g === 'D' ? 'rgba(224,106,44,.14)' : 'rgba(226,61,75,.14)')

function rank(s: ReportSkill): number { return s.unsafe ? 0 : s.review ? 1 : s.bloated ? 2 : 3 }

/**
 * Harden UNTRUSTED report data (anyone can POST to /api/report) before it is
 * stored or rendered: whitelist every enum, coerce numbers, cap array sizes,
 * truncate strings, and keep only findings from `a`. This is the authoritative
 * fix for stored-XSS, storage-DoS, and rating-data poisoning at the public
 * intake — the render layer additionally escapes, as defense in depth.
 */
const SEVS = new Set<Severity>(['critical', 'high', 'medium', 'low'])
const KINDS = new Set(['shadow', 'overlap'])
const GRADES = new Set(['A', 'B', 'C', 'D', 'F'])
const asRec = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' ? (v as Record<string, unknown>) : {})
const asStr = (v: unknown, max: number): string => (typeof v === 'string' ? v.slice(0, max) : '')
const asNum = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0 }
const asArr = (v: unknown, max: number): unknown[] => (Array.isArray(v) ? v.slice(0, max) : [])

export function sanitizeReportData(raw: unknown): ReportData | null {
  if (!raw || typeof raw !== 'object') return null
  const d = asRec(raw)
  const skills: ReportSkill[] = asArr(d.skills, 300).map((s0) => {
    const s = asRec(s0)
    const findings: Finding[] = asArr(asRec(s.a).findings, 40).map((f0) => {
      const f = asRec(f0)
      return {
        severity: (SEVS.has(f.severity as Severity) ? f.severity : 'low') as Severity,
        category: asStr(f.category, 40),
        title: asStr(f.title, 200),
        detail: asStr(f.detail, 500),
      }
    })
    return {
      name: asStr(s.name, 120), source: asStr(s.source, 80), path: asStr(s.path, 200),
      a: { findings },
      tokens: asNum(s.tokens),
      grade: GRADES.has(s.grade as string) ? (s.grade as string) : 'F',
      unsafe: s.unsafe === true, review: s.review === true, bloated: s.bloated === true,
      bloatRatio: asNum(s.bloatRatio), reason: asStr(s.reason, 200),
      optTokens: s.optTokens === undefined ? undefined : asNum(s.optTokens),
      savedPct: s.savedPct === undefined ? undefined : asNum(s.savedPct),
      changes: s.changes === undefined ? undefined : asArr(s.changes, 40).map((c) => asStr(c, 200)),
    }
  })
  const conflicts = asArr(d.conflicts, 100).map((c0) => {
    const c = asRec(c0)
    return {
      a: asStr(c.a, 120), b: asStr(c.b, 120),
      kind: KINDS.has(c.kind as string) ? (c.kind as 'shadow' | 'overlap') : 'overlap',
      shared: asArr(c.shared, 12).map((x) => asStr(x, 40)),
    }
  }) as Conflict[]
  return {
    generatedAt: asStr(d.generatedAt, 40),
    locations: asArr(d.locations, 20).map((l0) => { const l = asRec(l0); return { source: asStr(l.source, 80), dir: asStr(l.dir, 200), count: asNum(l.count) } }),
    skills, conflicts,
    broad: asArr(d.broad, 40).map((x) => asStr(x, 60)),
    median: asNum(d.median), bloatThresh: asNum(d.bloatThresh),
    optimizable: d.optimizable === true, lang: d.lang === 'zh' ? 'zh' : 'en',
  }
}

export function renderHtml(d: ReportData): string {
  const lang: Lang = d.lang === 'zh' ? 'zh' : 'en'
  const L = Z[lang]
  const zh = lang === 'zh'
  const nUnsafe = d.skills.filter((s) => s.unsafe).length
  const nReview = d.skills.filter((s) => s.review).length
  const nBloat = d.skills.filter((s) => s.bloated).length
  const okCount = d.skills.filter((s) => !s.unsafe && !s.review && !s.bloated).length
  const sorted = [...d.skills].sort((a, b) => rank(a) - rank(b) || b.tokens - a.tokens)

  // Small inline glyphs (stroke, currentColor) so each stat reads at a glance — the
  // dashboard-grade cue the plain number grid was missing.
  const ICON: Record<string, string> = {
    skills: '<path d="M3 7l9-4 9 4-9 4-9-4z"/><path d="M3 12l9 4 9-4"/><path d="M3 17l9 4 9-4"/>',
    unsafe: '<path d="M12 2l8 4v6c0 5-3.4 8-8 10-4.6-2-8-5-8-10V6z"/><path d="M12 9v3.5"/><path d="M12 16h.01"/>',
    review: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
    bloat: '<circle cx="8" cy="9" r="5"/><path d="M8 4a5 5 0 0 1 0 10"/><circle cx="16" cy="15" r="5"/>',
    conflict: '<path d="M6 4v10a3 3 0 0 0 3 3h6"/><path d="M15 20l3-3-3-3"/><path d="M18 4l-3 3 3 3"/>',
    median: '<path d="M4 20V11"/><path d="M10 20V4"/><path d="M16 20v-6"/><path d="M3 20h18"/>',
  }
  const tile = (label: string, val: string | number, color: string, icon: string, sub = '') =>
    `<div class="tile"><div class="ti" style="color:${color};background:color-mix(in srgb,${color} 13%,transparent)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICON[icon] ?? ''}</svg></div><div class="l">${label}</div><div class="v" style="color:${color}">${val}</div>${sub ? `<div class="s">${sub}</div>` : ''}</div>`

  const card = (s: ReportSkill) => {
    const mark = s.unsafe ? `<span class="mk bad">${L.mUnsafe}</span>` : s.review ? `<span class="mk warn">${L.mReview}</span>` : s.bloated ? `<span class="mk warn">${L.mBloated}</span>` : `<span class="mk ok">${L.mOk}</span>`
    const shown = s.a.findings.slice(0, 5)
    const moreN = s.a.findings.length - shown.length
    const isOk = !s.unsafe && !s.review && !s.bloated
    const findings = shown.map((f) => `<li class="f ${esc(f.severity)}"><b>${esc(zh ? zhFinding(f.title) : f.title)}</b><span>${esc(zh ? zhDetail(f.detail) : f.detail)}</span></li>`).join('')
      + (moreN > 0 ? `<li class="f dim">${L.moreF(moreN)}</li>` : '')
      + (isOk ? `<li class="verdict">${L.verdictOk}</li>` : '')
    const ratio = s.bloatRatio >= 1.15 ? `<span class="ratio">${s.bloatRatio.toFixed(1)}× ${L.median}</span>` : ''
    const tokCell = s.optTokens !== undefined && s.savedPct
      ? `<div class="ctok"><b class="tok-o">${s.tokens.toLocaleString()}</b><b class="tok-n">${s.optTokens.toLocaleString()}</b> ${L.tok} ${ratio}</div>`
      : `<div class="ctok"><b>${s.tokens.toLocaleString()}</b> ${L.tok} ${ratio}</div>`
    const optBlock = s.optTokens !== undefined && s.savedPct
      ? `<div class="opt"><div class="optline"><b>−${s.savedPct}%</b> ${L.optimized} · ${s.tokens.toLocaleString()} → ${s.optTokens.toLocaleString()} ${L.tok}</div>${s.changes && s.changes.length ? `<ul class="ochanges">${s.changes.map((ch) => `<li>${esc(zh ? zhChange(ch) : ch)}</li>`).join('')}</ul>` : ''}</div>`
      : ''
    return `<article class="card" style="--gc:${gColor(s.grade)}">
      <div class="chead">
        <span class="grade" style="color:${gColor(s.grade)};background:${gBg(s.grade)}">${esc(s.grade)}</span>
        <div class="cmeta"><div class="cname">${esc(s.name)} ${mark}</div><div class="csrc">${esc(s.source)} · <span class="mono">${esc(s.path.replace(process.env.HOME || '~', '~'))}</span></div></div>
        ${tokCell}
      </div>
      ${findings ? `<ul class="findings">${findings}</ul>` : ''}
      ${optBlock}
    </article>`
  }

  const optimizable = !!d.optimizable && d.skills.some((s) => s.optTokens !== undefined)
  const totalTok = d.skills.reduce((n, s) => n + s.tokens, 0)
  const totalOpt = d.skills.reduce((n, s) => n + (s.optTokens ?? s.tokens), 0)
  const totalSaved = totalTok > 0 ? Math.round((1 - totalOpt / totalTok) * 100) : 0
  const wand = '<svg class="wand" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2l1.5 4.6L18 8l-4.5 1.4L12 14l-1.5-4.6L6 8l4.5-1.4z"/><path d="M19 12.5l.7 2.3 2.3.7-2.3.7-.7 2.3-.7-2.3-2.3-.7 2.3-.7z" opacity=".72"/></svg>'
  const shareBar = optimizable
    ? `<div class="share">
        <button class="sbtn" onclick="var u=location.href.split('#')[0]+(document.body.classList.contains('optimized')?'#optimized':'');navigator.clipboard&&navigator.clipboard.writeText(u);this.textContent='${L.copiedLink}';var b=this;setTimeout(function(){b.textContent='${L.copyLink}'},1500)">${L.copyLink}</button>
        <button class="sbtn prim" id="optbtn" onclick="skToggleOpt()">${wand}<span id="optlabel">${L.optimize}</span></button>
        <span class="savesum">${L.savesum(totalSaved, totalTok.toLocaleString(), totalOpt.toLocaleString())} <a href="#" onclick="skToggleOpt();return false">${L.restore}</a></span>
      </div>
      <div class="gethint">${L.getFile}</div>`
    : `<div class="share">
        <button class="sbtn" onclick="navigator.clipboard&&navigator.clipboard.writeText(location.href);this.textContent='${L.copiedLink}';var b=this;setTimeout(function(){b.textContent='${L.copyLink}'},1500)">${L.copyLink}</button>
        <span class="leanpill">${L.optLeanPill}</span>
        <span class="dim" style="font-size:12px">${L.shareView}</span>
      </div>
      <div class="leannote">${L.optLean}<a href="https://skillmoo.com" rel="noopener">skillmoo.com</a>.</div>`

  const conflictRows = d.conflicts
    .sort((a, b) => (a.kind === b.kind ? 0 : a.kind === 'shadow' ? -1 : 1) || b.shared.length - a.shared.length)
    .slice(0, 20)
    .map((c) => `<tr><td><b>${esc(c.a)}</b> ⇄ <b>${esc(c.b)}</b></td><td class="${esc(c.kind)}">${c.kind === 'shadow' ? L.shadow : L.overlap}</td><td class="mono dim">${esc(c.shared.slice(0, 6).join(', '))}</td></tr>`)
    .join('')

  const n = d.skills.length
  const pct = (x: number) => (n ? Math.round((x / n) * 100) : 0)
  const healthBar = n === 0 ? '' : `<div class="health">
    <div class="ht"><span>${L.healthT}</span><b>${okCount}/${n} ${L.clean}</b></div>
    <div class="hbar">${nUnsafe ? `<span class="un" style="width:${pct(nUnsafe)}%"></span>` : ''}${nReview ? `<span class="rev" style="width:${pct(nReview)}%"></span>` : ''}${okCount ? `<span class="ok" style="width:${pct(okCount)}%"></span>` : ''}</div>
    <div class="hleg">
      <span><i style="background:var(--good)"></i>${L.tOk} <b class="n">${okCount}</b></span>
      <span><i style="background:var(--warn)"></i>${L.tReview} <b class="n">${nReview}</b></span>
      <span><i style="background:var(--crit)"></i>${L.tUnsafe} <b class="n">${nUnsafe}</b></span>
      <span><i style="background:var(--warn)"></i>${L.tBloated} <b class="n">${nBloat}</b></span>
    </div></div>`

  // No-result / empty state: uploaded content produced no analyzable skill. Explain
  // WHY (not a valid SKILL.md) + guide to the correct operation — never a blank page.
  const emptyState = `<div class="empty">
    <h3>${L.emptyH}</h3>
    <p>${L.emptyP}</p>
    <ul class="why">${L.emptyWhy.map((w) => `<li>${w}</li>`).join('')}</ul>
    <p style="margin-top:16px">${L.emptyCta}</p>
  </div>`

  return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${L.docTitle}</title><meta name="theme-color" content="#f7f6f8"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;800&display=swap" rel="stylesheet"><style>
:root{color-scheme:light;--bg:#f7f6f8;--surface:#ffffff;--panel:#ffffff;--line:#e6e4e9;--ink:#303638;--ink2:#565b5e;--ink3:#838890;--sig:#f4a159;--good:#12a877;--warn:#d98800;--crit:#e23d4b;--mono:ui-monospace,"SF Mono",Menlo,monospace;--disp:'Orbitron',system-ui,-apple-system,sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:920px;margin:0 auto;padding:40px 22px 70px}
.brand{display:flex;align-items:center;gap:9px;font-family:var(--disp);font-weight:700;letter-spacing:-.01em;font-size:17px}
.brand .g{color:var(--sig)}
h1{font-family:var(--disp);font-size:25px;letter-spacing:-.01em;margin:22px 0 6px}
.sub{color:var(--ink3);font-size:13px;font-family:var(--mono)}
/* stat tiles — elevated cards, icon chip + clean numeral (dashboard-grade) */
.tiles{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:24px 0 18px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:15px 16px 16px;box-shadow:0 1px 2px rgba(48,54,56,.04),0 5px 16px rgba(48,54,56,.05);transition:transform .18s cubic-bezier(.4,0,.2,1),box-shadow .18s cubic-bezier(.4,0,.2,1)}
.tile:hover{transform:translateY(-2px);box-shadow:0 2px 4px rgba(48,54,56,.05),0 12px 26px rgba(48,54,56,.09)}
.tile .ti{width:30px;height:30px;border-radius:9px;display:flex;align-items:center;justify-content:center}
.tile .ti svg{width:16px;height:16px}
.tile .l{font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink3);font-family:var(--mono);font-weight:600;margin-top:12px}
.tile .v{font:800 29px/1 system-ui,-apple-system,sans-serif;font-variant-numeric:tabular-nums;margin-top:5px;letter-spacing:-.02em}
.tile .s{font-size:10.5px;color:var(--ink3);margin-top:3px}
/* portfolio health hero — proportional stacked bar (clean/review/unsafe) */
.health{background:var(--surface);border:1px solid var(--line);border-radius:18px;padding:20px 22px;margin:24px 0;box-shadow:0 1px 2px rgba(48,54,56,.04),0 6px 20px rgba(48,54,56,.05)}
.health .ht{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:14px}
.health .ht span{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink3);font-weight:600}
.health .ht b{color:var(--ink);font:800 15px/1 system-ui,-apple-system,sans-serif;font-variant-numeric:tabular-nums}
.hbar{display:flex;height:13px;border-radius:999px;overflow:hidden;background:var(--line)}
.hbar span{display:block;transition:width .6s cubic-bezier(.4,0,.2,1)}
.hbar .ok{background:var(--good)}.hbar .rev{background:var(--warn)}.hbar .un{background:var(--crit)}
.hleg{display:flex;gap:20px;flex-wrap:wrap;margin-top:14px;font-size:12px;color:var(--ink2)}
.hleg i{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:6px;vertical-align:0}
.hleg .n{font-family:var(--mono);font-weight:700;color:var(--ink)}
/* empty / no-result state */
.empty{background:var(--panel);border:1px dashed var(--line);border-radius:16px;padding:34px 26px;text-align:center;margin:24px 0}
.empty h3{font-family:var(--disp);font-size:20px;margin:0 0 8px}
.empty p{color:var(--ink2);font-size:14px;max-width:52ch;margin:0 auto 8px}
.empty code{font-family:var(--mono);font-size:12.5px;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:1px 6px}
.empty .why{text-align:left;max-width:44ch;margin:16px auto 0;font-size:13px;color:var(--ink2)}
.empty .why li{margin:5px 0}
.caps{list-style:none;margin:9px 0 0;padding:9px 0 0;border-top:1px solid var(--line);display:flex;flex-wrap:wrap;gap:6px}
.cap{font-size:11px;font-family:var(--mono);color:var(--ink2);background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:2px 8px}
.cap.high{color:var(--crit);border-color:rgba(226,61,75,.3)}.cap.medium{color:var(--warn);border-color:rgba(217,136,0,.3)}
.f.dim{color:var(--ink3);font-style:italic}
.verdict{font-size:12px;color:var(--good);font-family:var(--mono)}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--ink3);font-family:var(--mono);margin:34px 0 14px;border-bottom:1px solid var(--line);padding-bottom:9px}
.card{background:var(--surface);border:1px solid var(--line);border-left:3px solid var(--gc);border-radius:12px;padding:14px 16px;margin-bottom:10px}
.chead{display:flex;align-items:center;gap:13px}
.grade{flex:none;width:34px;height:34px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-weight:800;font-size:18px}
.cmeta{flex:1;min-width:0}.cname{font-weight:650;font-size:15px}.csrc{font-size:11.5px;color:var(--ink3);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mono{font-family:var(--mono)}.dim{color:var(--ink3)}
.ctok{flex:none;text-align:right;font-family:var(--mono);font-size:12px;color:var(--ink3)}.ctok b{color:var(--ink);font-size:15px}
.ratio{display:block;color:var(--warn);font-size:11px;margin-top:2px}
.mk{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;padding:2px 7px;border-radius:5px;margin-left:6px;vertical-align:1px}
.mk.ok{color:var(--good);background:rgba(18,168,119,.13)}.mk.warn{color:var(--warn);background:rgba(217,136,0,.13)}.mk.bad{color:var(--crit);background:rgba(226,61,75,.14)}
.findings{list-style:none;margin:11px 0 0;padding:11px 0 0;border-top:1px solid var(--line);display:flex;flex-direction:column;gap:7px}
.f{font-size:12px;color:var(--ink3)}.f b{color:var(--ink2);margin-right:7px}
.f.critical b,.f.high b{color:var(--crit)}.f.medium b{color:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
td{padding:8px 6px;border-bottom:1px solid var(--line)}td.shadow{color:var(--crit)}td.overlap{color:var(--warn)}
.foot{margin-top:40px;padding-top:18px;border-top:1px solid var(--line);color:var(--ink3);font-size:12px}
.foot a{color:var(--sig);text-decoration:none}
.share{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:18px 0 2px}
.sbtn{font:inherit;font-size:13px;font-weight:600;padding:7px 14px;border-radius:9px;border:1px solid var(--line);background:var(--panel);color:var(--ink);cursor:pointer}
.sbtn.prim{background:linear-gradient(135deg,#f8b673,#f4a159 52%,#ee8c3d);color:#3a2410;border-color:transparent;font-weight:700;padding:9px 17px;font-size:13.5px;display:inline-flex;align-items:center;gap:7px;box-shadow:inset 0 1px 0 rgba(255,255,255,.42),0 2px 8px rgba(238,140,61,.32);transition:transform .12s ease,box-shadow .12s ease,filter .12s ease}
.sbtn.prim:hover{transform:translateY(-1px);box-shadow:inset 0 1px 0 rgba(255,255,255,.5),0 6px 18px rgba(238,140,61,.46);filter:saturate(1.05)}
.sbtn.prim:active{transform:translateY(0);box-shadow:inset 0 1px 2px rgba(120,60,10,.28)}
.sbtn.prim .wand{width:15px;height:15px;flex:none}
.leanpill{font-size:12.5px;font-weight:700;color:var(--good);padding:6px 12px;border:1px solid var(--line);border-radius:999px;background:var(--panel)}
.leannote{margin:9px 0 2px;font-size:12px;color:var(--ink3);line-height:1.55}.leannote a{color:var(--sig);text-decoration:none}
.gethint{display:none;margin:9px 0 2px;font-size:12px;color:var(--ink3);line-height:1.55}
.gethint code{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;background:var(--panel);border:1px solid var(--line);border-radius:5px;padding:1px 5px}
body.optimized .gethint{display:block}
.savesum{display:none;font-size:12.5px;color:var(--ink2)}.savesum b{color:var(--good)}.savesum a{color:var(--sig);text-decoration:none;margin-left:6px}
body.optimized .savesum{display:inline}
.opt{display:none;margin-top:11px;padding-top:11px;border-top:1px dashed var(--line)}
body.optimized .opt{display:block}
.optline{font-size:12.5px;color:var(--good);font-weight:600}
.ochanges{list-style:none;margin:7px 0 0;padding:0;display:flex;flex-direction:column;gap:4px}
.ochanges li{font-size:12px;color:var(--ink3)}.ochanges li:before{content:"✓ ";color:var(--good)}
.tok-n{display:none;color:var(--good)!important}
body.optimized .tok-o{display:none}body.optimized .tok-n{display:inline}
@media(max-width:680px){.tiles{grid-template-columns:repeat(3,1fr)}}
</style></head><body><div class="wrap">
<div class="brand"><svg width="27" height="27" viewBox="0 0 32 32" fill="none" aria-label="SkillMOO"><path d="M4 26 C 12 25, 14 10, 25 7.5" stroke="currentColor" stroke-width="2.3" stroke-linecap="round"/><circle cx="9" cy="22.6" r="1.35" fill="currentColor" fill-opacity=".4"/><circle cx="15.5" cy="13.7" r="1.65" fill="currentColor" fill-opacity=".72"/><circle cx="25" cy="7.5" r="2.6" fill="#f4a159"/><circle cx="25" cy="7.5" r="4.6" stroke="#f4a159" stroke-opacity=".45" stroke-width="1"/><circle cx="25" cy="7.5" r="6.7" stroke="#f4a159" stroke-opacity=".18" stroke-width="1"/></svg>Skill<span class="g">MOO</span></div>
<h1>${L.h1}</h1>
<div class="sub">${esc(d.generatedAt)} · ${d.skills.length} ${L.skills} · ${d.locations.filter((l) => l.count).map((l) => esc(l.source) + ' (' + l.count + ')').join(' · ')}</div>
${n === 0 ? emptyState : `${shareBar}
${healthBar}
<div class="tiles">
  ${tile(L.tSkills, n, 'var(--sig)', 'skills')}
  ${tile(L.tUnsafe, nUnsafe, nUnsafe ? 'var(--crit)' : 'var(--good)', 'unsafe')}
  ${tile(L.tReview, nReview, nReview ? 'var(--warn)' : 'var(--ink3)', 'review')}
  ${tile(L.tBloated, nBloat, nBloat ? 'var(--warn)' : 'var(--good)', 'bloat')}
  ${tile(L.tConflicts, d.conflicts.length, d.conflicts.length ? 'var(--warn)' : 'var(--good)', 'conflict')}
  ${tile(L.tMedian, d.median.toLocaleString(), 'var(--ink3)', 'median')}
</div>
<h2>${L.skillsH2(okCount, n - okCount)}</h2>
${sorted.map(card).join('')}
${d.conflicts.length ? `<h2>${L.conflictsH2(d.conflicts.length, d.conflicts.length > 20)}</h2><table>${conflictRows}</table>${d.broad.length ? `<p class="dim" style="font-size:12px;margin-top:10px">${L.broad}<span class="mono">${esc(d.broad.join(', '))}</span></p>` : ''}` : ''}`}
<div class="foot">${L.foot}</div>
</div>
<script>
function skToggleOpt(){var on=document.body.classList.toggle('optimized');var l=document.getElementById('optlabel');if(l)l.textContent=on?'${L.restore}':'${L.optimize}';if(on){location.hash='optimized'}else{history.replaceState(null,'',location.pathname+location.search)}}
if(location.hash==='#optimized'){document.body.classList.add('optimized');var _l=document.getElementById('optlabel');if(_l)_l.textContent='${L.restore}'}
</script>
</body></html>`
}
