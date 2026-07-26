/**
 * skillmoo — the CLI wedge.
 *
 *   skillmoo scan                 grade every skill installed in Claude Code / Codex
 *   skillmoo scan --json          machine-readable output
 *   skillmoo scan --dir <path>    add an extra skills root
 *   skillmoo report <file>        full report for one SKILL.md
 *   skillmoo optimize <file>      rule-based one-click optimize (before → after)
 *
 * Analysis is 100% local — no model, no signup — and reuses the same engine as the
 * website (src/lib/*). The one network call is the OPT-OUT share: an interactive
 * `scan` (a TTY, no --json/--report) uploads an ANONYMIZED report — grades + findings
 * only, home paths tilde-stripped, never the skill's text — to mint a shareable
 * skillmoo.com/r/<id> link. `--no-share` / `--json` / a piped or CI run stays fully
 * offline. This is the free wedge + the data intake.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { relative, join } from 'node:path'
import { homedir } from 'node:os'
import { defaultRoots, discover, readBundle, type Root } from './discover'
import { analyzeSkill, type SkillAnalysis } from '../src/lib/analyzeSkill'
import { analyzePortfolio } from '../src/lib/conflictScan'
import { optimizeSkill } from '../src/lib/optimizeSkill'
import { optimizePro, type ChatFn } from '../src/lib/optimizePro'
import { composePortfolio } from '../src/lib/composePortfolio'
import { c, gradeBadge, padEndV } from './format'
import { renderHtml, type ReportData } from './report-html'

// Injected from packages/cli/package.json at build time (build-cli.mjs) so the reported
// version can NEVER drift from the published one (it silently did until 2026-07-18).
// A dev run via tsx (no define) falls back to a clearly-not-released marker.
declare const __CLI_VERSION__: string | undefined
const VERSION = typeof __CLI_VERSION__ !== 'undefined' ? __CLI_VERSION__ : '0.0.0-dev'
const tilde = (p: string) => p.replace(homedir(), '~')

interface Graded {
  name: string; path: string; source: string
  a: SkillAnalysis
  tokens: number; grade: string; gate: string
  unsafe: boolean; review: boolean; bloated: boolean; bloatRatio: number
  reason: string
}

/** The bundle context for a skill on disk — the SAME evidence `skillmoo scan` grades on.
 *  Every command must analyse the whole bundle when one exists: a grade measured on
 *  SKILL.md alone cannot see a payload in scripts/, so `skillmoo report` used to print
 *  A 90/100 where the full bundle grades D 57/100. Read-only, bounded. */
function bundleOptsFor(skillPath: string): { bundleText?: string; bundleFiles?: string[] } | undefined {
  const b = readBundle(skillPath)
  if (!b.bundle) return undefined
  return { ...(b.text ? { bundleText: b.text } : {}), bundleFiles: b.files }
}

function grade(found: ReturnType<typeof discover>['found']): Graded[] {
  // Also scan each skill's REFERENCED/bundled files (references/*.md, scripts/*) so a
  // payload hidden outside the SKILL.md still counts — read-only, bounded (see readBundle).
  const analyzed = found.map((s) => {
    const bundle = readBundle(s.path)
    const opts = bundle.bundle
      ? { ...(bundle.text ? { bundleText: bundle.text } : {}), bundleFiles: bundle.files }
      : undefined
    return { ...s, a: analyzeSkill(s.md, opts), bundleFiles: bundle.files }
  })
  const toks = analyzed.map((x) => x.a.tokens.total).sort((a, b) => a - b)
  const median = toks.length ? toks[Math.floor(toks.length / 2)] : 0
  const bloatThresh = Math.max(Math.round(median * 1.6), 350)
  return analyzed.map((x) => {
    const g = x.a.overall.grade, gate = x.a.overall.gate, lvl = x.a.risk.level
    const tokens = x.a.tokens.total
    const unsafe = gate === 'block' || g === 'F' || lvl === 'high' || lvl === 'critical'
    const review = !unsafe && (gate === 'review' || lvl === 'medium')
    const bloated = tokens > bloatThresh
    const ratio = median ? tokens / median : 1
    const topFinding = x.a.findings.find((f) => f.severity === 'critical' || f.severity === 'high') ?? x.a.findings[0]
    const reason = unsafe
      ? (topFinding?.title ?? 'blocked by gate').toLowerCase()
      : bloated
        ? `${ratio.toFixed(1)}× median tokens`
        : review
          ? (topFinding?.title ?? 'needs review').toLowerCase()
          : 'clean'
    return { name: x.name, path: x.path, source: x.source, a: x.a, tokens, grade: g, gate, unsafe, review, bloated, bloatRatio: ratio, reason }
  })
}

function rank(s: Graded): number {
  return s.unsafe ? 0 : s.review ? 1 : s.bloated ? 2 : 3
}

/**
 * Opt-in upload of a scan report → a shareable skillmoo.com/r/<id> link.
 * Home paths are already tilde-stripped in `data` before this is called, so
 * no machine identity leaves. This is the data flywheel (see CLAUDE.md).
 */
async function publishReport(data: ReportData): Promise<void> {
  const base = (process.env.SKILLMOO_API || 'https://skillmoo.com').replace(/\/$/, '')
  process.stdout.write('  ' + c.dim(`uploading report to ${base.replace(/^https?:\/\//, '')}… `))
  try {
    const res = await fetch(base + '/api/report', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ data }),
    })
    if (res.status === 501) { console.log(c.yellow('not enabled yet') + c.dim(' — hosted reports coming soon')); return }
    if (!res.ok) {
      const j = (await res.json().catch(() => ({}))) as { error?: string }
      console.log(c.red('failed') + c.dim(' — ' + (j.error || 'HTTP ' + res.status)))
      return
    }
    const j = (await res.json()) as { url: string }
    console.log(c.green('done'))
    console.log('')
    console.log('  ' + c.green('✓') + ' ' + c.bold('Full report — open it in your browser:'))
    console.log('')
    console.log('     ' + c.cyan(j.url))
    console.log('')
    console.log('  ' + c.dim('See every finding in detail, ') + c.bold('optimize in one click') + c.dim(', restore anytime, and share.'))
    console.log('  ' + c.dim('Uploaded grades & findings only — never your file contents.  (skip: ') + c.cyan('--no-share') + c.dim(')') + '\n')
  } catch (e) {
    console.log(c.red('offline') + c.dim(' — ' + (e as Error).message))
  }
}

async function runScan(argv: string[]): Promise<number> {
  const json = argv.includes('--json')
  const extra: Root[] = []
  for (let i = 0; i < argv.length; i++) if (argv[i] === '--dir' && argv[i + 1]) extra.push({ dir: argv[++i], source: 'custom' })
  const roots = [...defaultRoots(), ...extra]

  const { found, locations } = discover(roots)
  if (found.length === 0) {
    if (json) { console.log(JSON.stringify({ skills: [], locations }, null, 2)); return 0 }
    console.log('\n' + c.bold('◇ SkillMOO scan') + '\n')
    console.log(c.dim('  No skills found. Looked in:'))
    for (const l of locations) console.log('    ' + c.gray(tilde(l.dir)))
    console.log('\n  ' + c.dim('Point at a skills folder with ') + c.cyan('skillmoo scan --dir <path>') + '\n')
    return 0
  }

  const skills = grade(found)
  const median = (() => { const t = skills.map((s) => s.tokens).sort((a, b) => a - b); return t[Math.floor(t.length / 2)] })()
  const bloatThresh = Math.max(Math.round(median * 1.6), 350)
  const portfolio = analyzePortfolio(skills.map((s) => ({ name: s.name, description: s.a.frontmatter.description ?? '' })))

  const nUnsafe = skills.filter((s) => s.unsafe).length
  const nReview = skills.filter((s) => s.review).length
  const nBloat = skills.filter((s) => s.bloated).length
  const nOk = skills.filter((s) => !s.unsafe && !s.review && !s.bloated).length

  if (json) {
    console.log(JSON.stringify({
      version: VERSION,
      locations: locations.filter((l) => l.exists),
      summary: { total: skills.length, medianTokens: median, unsafe: nUnsafe, review: nReview, bloated: nBloat, ok: nOk, conflicts: portfolio.conflicts.length },
      skills: skills.map((s) => ({ name: s.name, path: s.path, source: s.source, grade: s.grade, gate: s.gate, score: s.a.overall.score, tokens: s.tokens, risk: s.a.risk.level, unsafe: s.unsafe, review: s.review, bloated: s.bloated, reason: s.reason, findings: s.a.findings.map((f) => ({ severity: f.severity, title: f.title })) })),
      conflicts: portfolio.conflicts,
      broadTriggers: portfolio.broad,
    }, null, 2))
    return 0
  }

  const out: string[] = []
  out.push('')
  out.push('  ' + c.bold('◇ SkillMOO') + c.dim(' scan · v' + VERSION))
  out.push('')
  // scanned locations (truncate long paths from the left — the tail is what matters)
  const dshort = (p: string) => { const t = tilde(p); return t.length > 33 ? '…' + t.slice(-32) : t }
  for (const l of locations) {
    if (!l.exists) continue
    out.push('  ' + c.gray('scan  ') + padEndV(c.cyan(l.source), 26) + padEndV(c.dim(dshort(l.dir)), 35) + c.bold(String(l.count)))
  }
  out.push('  ' + c.dim('─'.repeat(56)))
  out.push('  ' + c.bold(`${skills.length} skills`) + c.dim(`  ·  median ${median} tok/call  ·  bloat cutoff ${bloatThresh}`))
  out.push('  ' + c.dim('read-only — reads each skill + its referenced files (references/, scripts/) to grade them; never edits your files.'))
  out.push('')
  // summary line
  out.push('  ' + padEndV(c.dim('safety'), 13) + `${nUnsafe ? c.red('✕ ' + nUnsafe + ' unsafe') : c.green('✓ 0 unsafe')}   ${c.yellow('! ' + nReview + ' review')}   ${c.green('✓ ' + nOk + ' ok')}`)
  out.push('  ' + padEndV(c.dim('bloat'), 13) + (nBloat ? c.yellow('~ ' + nBloat + ' bloated') : c.green('✓ none bloated')))
  out.push('  ' + padEndV(c.dim('conflicts'), 13) + (portfolio.conflicts.length ? c.yellow('⚠ ' + portfolio.conflicts.length + ' pair' + (portfolio.conflicts.length > 1 ? 's' : '')) : c.green('✓ none')))
  out.push('')

  // table, worst first
  const trunc = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + '…' : s)
  const sorted = [...skills].sort((a, b) => rank(a) - rank(b) || b.tokens - a.tokens)
  const nameW = Math.min(28, Math.max(...sorted.map((s) => s.name.length)))
  for (const s of sorted) {
    const mark = s.unsafe ? c.red('✕') : s.review ? c.yellow('!') : s.bloated ? c.yellow('~') : c.green('✓')
    const rt = trunc(s.reason, 34)
    const reason = s.unsafe ? c.red(rt) : s.bloated ? c.yellow(rt) : s.review ? c.yellow(rt) : c.dim(rt)
    out.push('  ' + gradeBadge(s.grade) + '  ' + mark + '  ' + padEndV(c.bold(trunc(s.name, nameW)), nameW + 2) + padEndV(reason, 36) + padEndV(c.dim(String(s.tokens) + ' tok'), 11) + c.gray(s.source))
  }

  // conflicts detail
  if (portfolio.conflicts.length) {
    out.push('')
    out.push('  ' + c.dim('conflicts') + c.dim(`  (${portfolio.conflicts.length} pair${portfolio.conflicts.length > 1 ? 's' : ''}, worst first)`))
    const shown = [...portfolio.conflicts]
      .sort((a, b) => (a.kind === b.kind ? 0 : a.kind === 'shadow' ? -1 : 1) || b.shared.length - a.shared.length)
      .slice(0, 6)
    for (const cf of shown) {
      const kind = cf.kind === 'shadow' ? c.red(cf.kind) : c.yellow(cf.kind)
      out.push('    ' + c.bold(trunc(cf.a, 24)) + c.dim(' ⇄ ') + c.bold(trunc(cf.b, 24)) + c.dim('  ') + kind + c.dim(': ') + c.dim(cf.shared.slice(0, 4).join(', ')))
    }
    if (portfolio.conflicts.length > shown.length) out.push('    ' + c.dim(`… +${portfolio.conflicts.length - shown.length} more  (skillmoo scan --json)`))
  }
  if (portfolio.broad.length) {
    out.push('  ' + c.dim('over-broad triggers: ') + c.yellow(portfolio.broad.join(', ')))
  }

  // The terminal gives you the gist; the full, interactive report lives on the
  // web (every finding in detail + one-click optimize). An interactive scan
  // auto-generates that shareable link; CI / piped / --no-share stay local.
  const noShare = argv.includes('--no-share') || !!process.env.SKILLMOO_NO_SHARE
  const wantReport = argv.some((x) => x === '--report' || x === '--html')
  const explicitPublish = argv.includes('--publish')
  const autoPublish = !!process.stdout.isTTY && !noShare && !explicitPublish && !wantReport && !argv.includes('--json')
  const wantPublish = explicitPublish || autoPublish

  out.push('')
  if (!wantPublish) {
    out.push('  ' + c.bold('→ Full report + one-click optimize, in your browser'))
    out.push('    run  ' + c.cyan('skillmoo scan --publish') + c.dim('   creates a shareable link · grades/findings only, never file contents'))
  }
  out.push('  ' + c.dim('·') + ' auto-fix bloat + conflicts  ' + c.cyan('→ skillmoo pro'))
  out.push('')
  console.log(out.join('\n'))

  if (wantReport || wantPublish) {
    // Sanitize: strip home paths to `~` so a shared report carries no identity.
    // optimize stats are computed LOCALLY from the skill's content; only the
    // resulting numbers + change descriptions travel — never the raw skill text.
    const data: ReportData = {
      generatedAt: new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC',
      locations: locations.filter((l) => l.exists).map((l) => ({ source: l.source, dir: tilde(l.dir), count: l.count })),
      skills: skills.map((s, i) => {
        const o = optimizeSkill(found[i].md, bundleOptsFor(found[i].path))
        const win = o.savedPct > 0
        // Upload ONLY the computed findings from `a` — never the rest of the
        // analysis (which carries the skill's own description text). Red line:
        // no skill content leaves the machine.
        return { name: s.name, source: s.source, path: tilde(s.path), a: { findings: s.a.findings }, tokens: s.tokens, grade: s.grade, unsafe: s.unsafe, review: s.review, bloated: s.bloated, bloatRatio: s.bloatRatio, reason: s.reason, optTokens: win ? o.tokensAfter : undefined, savedPct: win ? o.savedPct : undefined, changes: win ? o.changes : undefined }
      }),
      conflicts: portfolio.conflicts, broad: portfolio.broad, median, bloatThresh, optimizable: true,
      lang: /(^|[._-])zh/i.test(process.env.LANG || process.env.LC_ALL || process.env.LC_MESSAGES || '') ? 'zh' : 'en',
    }
    if (wantReport) {
      const reportIdx = argv.findIndex((x) => x === '--report' || x === '--html')
      const next = argv[reportIdx + 1]
      const custom = next && !next.startsWith('-') ? next : null
      // Never clobber: if the default report file exists, pick the next free name.
      let outPath = custom ? (custom.startsWith('/') ? custom : join(process.cwd(), custom)) : join(process.cwd(), 'skillmoo-report.html')
      if (!custom && existsSync(outPath)) {
        let n = 2
        while (existsSync(join(process.cwd(), `skillmoo-report-${n}.html`))) n++
        outPath = join(process.cwd(), `skillmoo-report-${n}.html`)
      }
      writeFileSync(outPath, renderHtml(data))
      console.log('  ' + c.green('✓') + ' HTML report → ' + c.cyan(outPath) + c.dim('  (open in a browser · shareable)') + '\n')
    }
    if (wantPublish) await publishReport(data)
  }
  return nUnsafe > 0 ? 2 : 0
}

/**
 * `skillmoo plan [--goal "..."]` — the capstone. Discovers installed skills and
 * emits a value-maximized ACTION PLAN: keep / optimize / merge / narrow / drop,
 * plus goal-gaps to fill. Deterministic (composePortfolio), no model, no signup.
 */
function runPlan(argv: string[]): number {
  const json = argv.includes('--json')
  let goal: string | undefined
  const extra: Root[] = []
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--goal' && argv[i + 1]) goal = argv[++i]
    else if (argv[i] === '--dir' && argv[i + 1]) extra.push({ dir: argv[++i], source: 'custom' })
  }
  const { found, locations } = discover([...defaultRoots(), ...extra])
  if (found.length === 0) {
    if (json) { console.log(JSON.stringify({ actions: [], gaps: [], summary: { total: 0 } }, null, 2)); return 0 }
    console.log('\n  ' + c.bold('◇ SkillMOO plan') + '\n\n  ' + c.dim('No skills found. Looked in:'))
    for (const l of locations) console.log('    ' + c.gray(tilde(l.dir)))
    console.log('\n  ' + c.dim('Point at a skills folder with ') + c.cyan('skillmoo plan --dir <path>') + '\n')
    return 0
  }

  const plan = composePortfolio(found.map((s) => ({ name: s.name, md: s.md })), goal)
  if (json) { console.log(JSON.stringify(plan, null, 2)); return 0 }

  const ACT: Record<string, { label: string; col: (s: string) => string }> = {
    drop: { label: 'DROP', col: c.red }, narrow: { label: 'NARROW', col: c.yellow },
    merge: { label: 'MERGE', col: c.yellow }, optimize: { label: 'OPTIMIZE', col: c.cyan },
    keep: { label: 'KEEP', col: c.green },
  }
  const trunc = (str: string, n: number) => (str.length > n ? str.slice(0, n - 1) + '…' : str)
  const s = plan.summary
  const out: string[] = ['']
  out.push('  ' + c.bold('◇ SkillMOO') + c.dim(' plan · v' + VERSION))
  if (s.goal) out.push('  ' + c.dim('goal   ') + c.cyan(trunc(s.goal, 60)))
  out.push('')
  out.push('  ' + c.bold(`${s.total} skills`) + c.dim(`  ·  ${s.conflicts} conflict${s.conflicts === 1 ? '' : 's'}  ·  ${s.tokensNow} → `) + c.green(String(s.tokensAfter)) + c.dim(' tok/call'))
  out.push('  ' + [s.drop && c.red(`${s.drop} drop`), s.narrow && c.yellow(`${s.narrow} narrow`), s.merge && c.yellow(`${s.merge} merge`), s.optimize && c.cyan(`${s.optimize} optimize`), s.keep && c.green(`${s.keep} keep`)].filter(Boolean).join(c.dim('  ·  ')))
  out.push('')
  const nameW = Math.min(24, Math.max(8, ...plan.actions.map((a) => a.name.length)))
  for (const a of plan.actions) {
    const A = ACT[a.action]
    const rel = a.relevance !== undefined ? c.dim(`  rel ${Math.round(a.relevance * 100)}%`) : ''
    out.push('  ' + gradeBadge(a.grade) + '  ' + A.col('●') + ' ' + padEndV(A.col(A.label), 9) + padEndV(c.bold(trunc(a.name, nameW)), nameW + 2) + rel)
    out.push('       ' + c.dim(trunc(a.reason, 80)))
    if (a.flag) out.push('       ' + c.yellow('⚑ ') + c.dim(trunc(a.flag, 74)))
  }
  if (plan.gaps.length) {
    out.push('')
    out.push('  ' + c.dim('gaps') + c.dim('  (goal terms no kept skill covers — verify or add)'))
    for (const g of plan.gaps) out.push('    ' + c.yellow('+ ') + c.bold(g.need) + c.dim('  ' + trunc(g.reason, 64)))
  }
  out.push('')
  out.push('  ' + c.dim('apply: ') + c.cyan('skillmoo optimize <file>') + c.dim(' per skill  ·  auto-apply all ') + c.cyan('→ skillmoo pro'))
  out.push('  ' + c.dim(trunc(plan.basis, 96)))
  out.push('')
  console.log(out.join('\n'))
  return s.drop > 0 ? 2 : 0
}

function runReport(file?: string): number {
  if (!file) { console.error('usage: skillmoo report <SKILL.md>'); return 1 }
  const a = analyzeSkill(readFileSync(file, 'utf8'), bundleOptsFor(file))
  console.log('\n  ' + gradeBadge(a.overall.grade) + '  ' + c.bold(a.frontmatter.name ?? relative(process.cwd(), file)) + c.dim('  ·  ' + a.tokens.total + ' tok  ·  gate ' + a.overall.gate))
  console.log('  ' + c.dim(a.overall.verdict) + '\n')
  for (const f of a.findings) {
    const col = f.severity === 'critical' || f.severity === 'high' ? c.red : f.severity === 'medium' ? c.yellow : c.dim
    console.log('  ' + col('● ') + c.bold(f.title) + c.dim(' [' + f.severity + ']'))
    console.log('    ' + c.dim(f.detail))
  }
  if (!a.findings.length) console.log('  ' + c.green('✓ no issues'))
  console.log('')
  return a.overall.gate === 'block' ? 2 : 0
}

async function runOptimize(file: string | undefined, argv: string[]): Promise<number> {
  if (!file) { console.error('usage: skillmoo optimize <SKILL.md> [--pro]'); return 1 }
  const md = readFileSync(file, 'utf8')

  if (!argv.includes('--pro')) {
    // Same bundle context the scan uses — so optimize's suggestions (e.g. a dangling
    // references/ link) match what `skillmoo scan` reported. Read-only.
    const o = optimizeSkill(md, bundleOptsFor(file))
    console.log('')
    if (o.savedPct > 0) {
      console.log('  ' + c.bold('one-click optimize') + '   ' + c.dim(`${o.tokensBefore} → `) + c.green(String(o.tokensAfter)) + c.dim(' tok  ') + c.bold(c.green(`−${o.savedPct}%`)) + (o.gradeAfter !== o.gradeBefore ? c.dim('   grade ' + o.gradeBefore + '→') + c.green(o.gradeAfter) : ''))
      for (const ch of o.changes) console.log('    ' + c.green('✓ ') + c.dim(ch))
    } else {
      console.log('  ' + c.bold('one-click optimize') + c.dim(`   ${o.tokensBefore} tok · no safe automatic cuts`))
      console.log('  ' + c.dim('  the bloat here is real content — trimming it is the semantic rewrite (--pro).'))
    }
    // Close the detect → fix loop: which detection findings did this actually clear?
    if (o.resolved.length) {
      console.log('  ' + c.green('fixed') + c.dim(` ${o.resolved.length} issue${o.resolved.length > 1 ? 's' : ''} the scan flagged:`))
      for (const r of o.resolved) console.log('    ' + c.green('✓ ') + c.dim(r))
    }
    if (o.suggestions.length) console.log('  ' + c.dim('needs your call (not auto-applied):'))
    for (const sg of o.suggestions) console.log('    ' + c.yellow('→ ') + c.dim(sg))
    console.log('\n  ' + c.dim('verify-or-reject: this rewrite is checked to never worsen grade/gate/safety before it ships.'))
    console.log('  ' + c.dim('rule-based tier (free, 100% local)  ·  semantic rewrite → skillmoo optimize --pro') + '\n')
    return 0
  }

  // ---- Pro (semantic) tier ----------------------------------------------------
  // RED LINE: the default optimize is 100% local. --pro is the ONE path that sends
  // the file off-machine, and ONLY to YOUR OWN model endpoint (never ours), only
  // with your explicit --pro opt-in, with the egress disclosed up front. We write
  // NOTHING to disk: the verified rewrite goes to stdout so you can redirect it.
  const s = process.stderr
  const base = (process.env.SKILLMOO_MODEL_URL || process.env.OPENAI_BASE_URL || process.env.GEN_BASE_URL || '').replace(/\/$/, '')
  const key = process.env.SKILLMOO_MODEL_KEY || process.env.OPENAI_API_KEY || process.env.GEN_API_KEY || ''
  const model = process.env.SKILLMOO_MODEL || process.env.OPENAI_MODEL || process.env.EVAL_MODEL || process.env.GEN_MODEL || ''
  if (!base || !key || !model) {
    s.write(`\n  ${c.bold('skillmoo optimize --pro')} uses ${c.bold('YOUR OWN')} model key — never ours, never a SkillMOO server.\n\n`)
    s.write('  Point it at any OpenAI-compatible endpoint (DeepSeek, OpenAI, a local model…):\n')
    s.write(c.dim('    export SKILLMOO_MODEL_URL=https://api.deepseek.com\n'))
    s.write(c.dim('    export SKILLMOO_MODEL_KEY=sk-...\n'))
    s.write(c.dim('    export SKILLMOO_MODEL=deepseek-chat\n\n'))
    s.write(`  ${c.dim('The free rule-based optimize (no --pro) stays 100% local — no key, no network.')}\n\n`)
    return 1
  }
  s.write(`\n  ${c.yellow('⚠')}  ${c.bold('--pro')} sends ${c.bold(relative(process.cwd(), file))} to ${c.bold(base)} using your key.\n`)
  s.write(`  ${c.dim('This is the only time SkillMOO makes a network call with your file. The default optimize never does. Ctrl-C to cancel.')}\n`)
  s.write(`  ${c.dim('optimizing with ' + model + ' …')}\n`)

  const chat: ChatFn = async (system, user) => {
    const res = await fetch(`${base}/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` },
      body: JSON.stringify({ model, messages: [{ role: 'system', content: system }, { role: 'user', content: user }], temperature: 0.2, max_tokens: 8192 }),
    })
    if (!res.ok) throw new Error(`${model} HTTP ${res.status}`)
    const j = (await res.json()) as { choices?: { message?: { content?: string } }[] }
    return (j.choices?.[0]?.message?.content ?? '').replace(/<think>[\s\S]*?<\/think>/gi, '').trim()
  }

  const r = await optimizePro(md, chat, bundleOptsFor(file))
  s.write(`\n  ${c.bold(r.mode === 'semantic' ? '✓ Pro semantic optimize — verified' : '↩ Pro rewrite rejected → safe rule-based fallback')}   `)
  s.write(c.dim(`${r.tokensBefore} → `) + (r.savedPct > 0 ? c.green(String(r.tokensAfter)) : String(r.tokensAfter)) + c.dim(' tok') + (r.savedPct > 0 ? '  ' + c.bold(c.green(`−${r.savedPct}%`)) : '') + (r.gradeAfter !== r.gradeBefore ? c.dim('  grade ' + r.gradeBefore + '→') + c.green(r.gradeAfter) : '') + '\n')
  for (const ck of r.checks) s.write(`    ${ck.pass ? c.green('✓') : c.red('✗')} ${c.dim(ck.name)} ${c.dim('— ' + ck.detail)}\n`)
  if (r.rejectionReason) s.write(`  ${c.yellow('→ ' + r.rejectionReason)}\n`)
  s.write('\n  ' + c.dim(r.mode === 'semantic'
    ? 'verified rewrite below (stdout) — save it with:  skillmoo optimize ' + relative(process.cwd(), file) + ' --pro > optimized.md'
    : 'showing the safe rule-based result below (stdout).') + '\n\n')
  process.stdout.write(r.optimized.endsWith('\n') ? r.optimized : r.optimized + '\n')
  return 0
}

function help(): void {
  console.log(`
  ${c.bold('◇ SkillMOO')} ${c.dim('· v' + VERSION)}  — grade the agent skills you've installed

  ${c.bold('skillmoo scan')}                ${c.dim('grade skills across Claude Code, Codex, Cursor, Copilot, Cline, Windsurf')}
    ${c.dim('--report [file]')}            ${c.dim('write a shareable HTML report (local file)')}
    ${c.dim('--publish')}                  ${c.dim('force the shareable skillmoo.com/r/<id> report link')}
    ${c.dim('--no-share')}                 ${c.dim('never upload — keep the scan fully local (or SKILLMOO_NO_SHARE=1)')}
    ${c.dim('--json')}                     ${c.dim('machine-readable output')}
    ${c.dim('--dir <path>')}               ${c.dim('add an extra skills root')}
  ${c.bold('skillmoo plan')}                ${c.dim('value-max action plan: keep/optimize/merge/narrow/drop + gaps')}
    ${c.dim('--goal "<text>"')}            ${c.dim('weight the plan toward what you\'re trying to build')}
  ${c.bold('skillmoo report')} ${c.dim('<file>')}       ${c.dim('full report for one SKILL.md')}
  ${c.bold('skillmoo optimize')} ${c.dim('<file>')}     ${c.dim('rule-based one-click optimize (100% local)')}
    ${c.dim('--pro')}                      ${c.dim('AI semantic rewrite, verified safe — uses YOUR model key (SKILLMOO_MODEL_KEY)')}

  ${c.dim('Analysis is 100% local — no model, no signup. (Only `optimize --pro` calls a model, your own endpoint.)')}
  ${c.dim('An interactive `scan` also uploads an anonymized report — grades & findings only, never file contents —')}
  ${c.dim('for the shareable link. Use --no-share (or --json / a piped/CI run) to stay fully offline.')}
`)
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2)
  let code = 0
  switch (cmd) {
    case undefined:
    case 'scan': code = await runScan(rest); break
    case 'plan': code = runPlan(rest); break
    case 'report': code = runReport(rest.find((a) => !a.startsWith('-'))); break
    case 'optimize': code = await runOptimize(rest.find((a) => !a.startsWith('-')), rest); break
    case '-v': case '--version': case 'version': console.log(VERSION); break
    case '-h': case '--help': case 'help': help(); break
    default: console.error(`unknown command: ${cmd}\n`); help(); code = 1
  }
  process.exit(code)
}
main()
