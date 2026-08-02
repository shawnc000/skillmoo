/**
 * skillmoo — the CLI wedge.
 *
 *   skillmoo scan                 grade every skill installed in Claude Code / Codex
 *   skillmoo scan --json          machine-readable output
 *   skillmoo scan --dir <path>    add an extra skills root
 *   skillmoo report <file>        full report for one SKILL.md
 *   skillmoo optimize <file>      rule-based one-click optimize (before → after)
 *
 * Static analysis is 100% local — no model, no signup — and reuses the same engine as the
 * website (src/lib/*). Static commands make no network call unless the user passes
 * the explicit `scan --publish` sharing flag. Published reports contain derived
 * anonymous labels and derived grade/finding categories, never names, paths, snippets,
 * evidence, or Skill file contents.
 */
import { writeFileSync, existsSync } from 'node:fs'
import { relative, join } from 'node:path'
import { homedir } from 'node:os'
import { defaultRoots, discover, readBundle, readPrimarySkill, type Root } from './discover'
import { analyzeSkill, type SkillAnalysis } from '../src/lib/analyzeSkill'
import { analyzePortfolio } from '../src/lib/conflictScan'
import { judgeAllListings, judgeListing, alwaysOnTokens, HARNESS_LISTINGS } from '../src/lib/listingBudget'
import { crossSkillRisks } from '../src/lib/crossSkillScan'
import { optimizeSkill } from '../src/lib/optimizeSkill'
import { optimizePro, type ChatFn } from '../src/lib/optimizePro'
import { composePortfolio } from '../src/lib/composePortfolio'
import { planPortfolioGoal } from '../src/lib/portfolioGoalPlan'
import { planGoal } from '../src/lib/bundleMatch'
import { summarizeCombinationEvidence, summarizeSkillEvidence } from '../src/lib/skillTrust'
import { MATCH_CATALOG_META, MATCH_SKILLS } from '../src/data/matchCatalog'
import { ARTIFACT_INDEX } from '../src/data/artifactIndex'
import { completePackageRejectedNames, filterCompletePackageEligible } from '../src/lib/artifactRouting'
import { c, gradeBadge, padEndV, safeTerminalText, wrapTo } from './format'
import { renderHtml, type ReportData } from './report-html'
import { runVerifyCommand } from './verify'
import { runSetupCommand } from './setup'
import { buildPublishReport, shouldPublishScan } from './sharePolicy'
import { runCatalogCommand } from './catalog'

// Injected from the repository package.json at build time (build-cli.mjs) so the reported
// version can NEVER drift from the published one (it silently did until 2026-07-18).
// A dev run via tsx (no define) falls back to a clearly-not-released marker.
declare const __CLI_VERSION__: string | undefined
const VERSION = typeof __CLI_VERSION__ !== 'undefined' ? __CLI_VERSION__ : '0.0.0-dev'
const COMPLETE_PACKAGE_REJECTED = completePackageRejectedNames(ARTIFACT_INDEX)
const MATCHABLE_SKILLS = filterCompletePackageEligible(MATCH_SKILLS, ARTIFACT_INDEX)
const tilde = (p: string) => p.replace(homedir(), '~')

interface Graded {
  name: string; path: string; source: string; md: string
  a: SkillAnalysis
  tokens: number; grade: string; gate: string
  unsafe: boolean; review: boolean; bloated: boolean; bloatRatio: number
  reason: string; complete: boolean; issues: string[]
  opts?: { bundleText?: string; bundleFiles?: string[] }
}

/** The bundle context for a skill on disk — the SAME evidence `skillmoo scan` grades on.
 *  Every command must analyse the whole bundle when one exists: a grade measured on
 *  SKILL.md alone cannot see a payload in scripts/, and mixing the two bases is what
 *  produced the false "D → A" on the web card (see optimizePlan). Read-only, bounded. */
function bundleOptsFor(b: ReturnType<typeof readBundle>): { bundleText?: string; bundleFiles?: string[] } | undefined {
  if (!b.bundle) return undefined
  return { ...(b.text ? { bundleText: b.text } : {}), bundleFiles: b.files }
}

const bundleIssueSummary = (issues: string[]): string => `incomplete bundle evidence: ${issues[0] ?? 'unknown bundle read failure'}`

function grade(found: ReturnType<typeof discover>['found']): Graded[] {
  // Also scan each skill's REFERENCED/bundled files (references/*.md, scripts/*) so a
  // payload hidden outside the SKILL.md still counts — read-only, bounded (see readBundle).
  const analyzed = found.map((s) => {
    const bundle = readBundle(s.path)
    const opts = bundleOptsFor(bundle)
    return { ...s, a: analyzeSkill(s.md, opts), opts, complete: bundle.complete, issues: bundle.issues }
  })
  const toks = analyzed.map((x) => x.a.tokens.total).sort((a, b) => a - b)
  const median = toks.length ? toks[Math.floor(toks.length / 2)] : 0
  const bloatThresh = Math.max(Math.round(median * 1.6), 350)
  return analyzed.map((x) => {
    const g = x.complete ? x.a.overall.grade : '?', gate = x.complete ? x.a.overall.gate : 'review', lvl = x.a.risk.level
    const tokens = x.a.tokens.total
    const unsafe = x.complete && (gate === 'block' || g === 'F' || lvl === 'high' || lvl === 'critical')
    const review = !unsafe && (!x.complete || gate === 'review' || lvl === 'medium')
    const bloated = x.complete && tokens > bloatThresh
    const ratio = median ? tokens / median : 1
    const topFinding = x.a.findings.find((f) => f.severity === 'critical' || f.severity === 'high') ?? x.a.findings[0]
    const reason = !x.complete
      ? bundleIssueSummary(x.issues)
      : unsafe
      ? (topFinding?.title ?? 'blocked by gate').toLowerCase()
      : bloated
        ? `${ratio.toFixed(1)}× median tokens`
        : review
          ? (topFinding?.title ?? 'needs review').toLowerCase()
          : 'clean'
    return { name: x.name, path: x.path, source: x.source, md: x.md, a: x.a, tokens, grade: g, gate, unsafe, review, bloated, bloatRatio: ratio, reason, complete: x.complete, issues: x.issues, opts: x.opts }
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
      body: JSON.stringify({ data: buildPublishReport(data) }),
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
    console.log('  ' + c.dim('Uploaded anonymous labels, grades, finding categories, and counts — never names, paths, snippets, or file contents.  (skip: ') + c.cyan('--no-share') + c.dim(')') + '\n')
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
  const truncatedLocations = locations.filter((location) => location.truncated).length
  if (found.length === 0) {
    if (json) {
      console.log(JSON.stringify({ skills: [], locations, summary: { total: 0, complete: truncatedLocations === 0, incompleteSkills: 0, truncatedLocations } }, null, 2))
      return truncatedLocations ? 2 : 0
    }
    console.log('\n' + c.bold('◇ SkillMOO scan') + '\n')
    if (truncatedLocations) {
      console.log(c.red('  Scan incomplete: one or more roots exceeded a read/count/byte boundary.'))
      console.log(c.dim('  No clean grade can be claimed until every eligible Skill is readable.\n'))
      return 2
    }
    console.log(c.dim('  No skills found. Looked in:'))
    for (const l of locations) console.log('    ' + c.gray(tilde(l.dir)))
    console.log('\n  ' + c.dim('Point at a skills folder with ') + c.cyan('skillmoo scan --dir <path>') + '\n')
    return 0
  }

  const skills = grade(found)
  const median = (() => { const t = skills.map((s) => s.tokens).sort((a, b) => a - b); return t[Math.floor(t.length / 2)] })()
  const bloatThresh = Math.max(Math.round(median * 1.6), 350)
  const portfolio = analyzePortfolio(skills.map((s) => ({ name: s.name, description: s.a.frontmatter.description ?? '' })))
  // The listing is a fixed budget: past a point the harness silently drops the
  // descriptions it matches your request against. Judge each harness we actually
  // found skills under, not every harness we know about.
  // Partition by harness first: a skill under ~/.codex/skills is never in Claude
  // Code's listing, so judging the whole pile against each harness would invent
  // a budget pressure neither one actually has.
  const harnessOf = (src: string) => (/codex/i.test(src) ? 'codex' : /claude/i.test(src) ? 'claude-code' : '')
  const byHarness = new Map<string, { name: string; description: string }[]>()
  for (const s of skills) {
    const h = harnessOf(s.source)
    if (!h) continue
    const e = { name: s.name, description: s.a.frontmatter.description ?? '' }
    byHarness.set(h, [...(byHarness.get(h) ?? []), e])
  }
  const listings = judgeAllListings([]).flatMap((v) => {
    const entries = byHarness.get(v.harness)
    return entries?.length ? [judgeListing(entries, HARNESS_LISTINGS.find((h) => h.id === v.harness)!)] : []
  })
  // Always-on is per harness too; report the largest single listing as the standing cost.
  const alwaysOn = Math.max(0, ...[...byHarness.values()].map((e) => alwaysOnTokens(e)))
  const crossRisks = crossSkillRisks(skills.map((s) => ({ name: s.name, body: s.md })))

  const nUnsafe = skills.filter((s) => s.unsafe).length
  const nReview = skills.filter((s) => s.review).length
  const nBloat = skills.filter((s) => s.bloated).length
  const nIncompleteSkills = skills.filter((s) => !s.complete).length
  const scanComplete = nIncompleteSkills === 0 && truncatedLocations === 0
  const nOk = skills.filter((s) => s.complete && !s.unsafe && !s.review && !s.bloated).length

  if (json) {
    console.log(JSON.stringify({
      version: VERSION,
      locations: locations.filter((l) => l.exists),
      summary: { total: skills.length, complete: scanComplete, incompleteSkills: nIncompleteSkills, truncatedLocations, medianTokens: median, unsafe: nUnsafe, review: nReview, bloated: nBloat, ok: nOk, conflicts: portfolio.conflicts.length },
      skills: skills.map((s) => ({ name: s.name, path: s.path, source: s.source, complete: s.complete, issues: s.issues, grade: s.grade, gate: s.gate, score: s.complete ? s.a.overall.score : null, tokens: s.tokens, risk: s.complete ? s.a.risk.level : 'unknown', unsafe: s.unsafe, review: s.review, bloated: s.bloated, reason: s.reason, findings: s.a.findings.map((f) => ({ severity: f.severity, title: f.title })) })),
      conflicts: portfolio.conflicts,
      broadTriggers: portfolio.broad,
      alwaysOnTokens: alwaysOn,
      listings,
      crossSkillRisks: crossRisks,
    }, null, 2))
    return scanComplete && nUnsafe === 0 ? 0 : 2
  }

  const out: string[] = []
  out.push('')
  out.push('  ' + c.bold('◇ SkillMOO') + c.dim(' scan · v' + VERSION))
  out.push('')
  // scanned locations (truncate long paths from the left — the tail is what matters)
  const dshort = (p: string) => { const t = tilde(p); return t.length > 33 ? '…' + t.slice(-32) : t }
  for (const l of locations) {
    if (!l.exists) continue
    out.push('  ' + c.gray('scan  ') + padEndV(c.cyan(l.source), 26) + padEndV(c.dim(dshort(l.dir)), 35) + c.bold(`${l.count}${l.truncated ? ' capped' : ''}`))
  }
  out.push('  ' + c.dim('─'.repeat(56)))
  out.push('  ' + c.bold(`${skills.length} skills`) + c.dim(`  ·  median ${median} tok/call  ·  bloat cutoff ${bloatThresh}`))
  out.push('  ' + c.dim('read-only — reads each skill + its referenced files (references/, scripts/) to grade them; never edits your files.'))
  out.push('')
  // summary line
  out.push('  ' + padEndV(c.dim('safety'), 13) + `${nUnsafe ? c.red('✕ ' + nUnsafe + ' unsafe') : c.green('✓ 0 unsafe')}   ${c.yellow('! ' + nReview + ' review')}   ${c.green('✓ ' + nOk + ' ok')}`)
  if (!scanComplete) out.push('  ' + padEndV(c.dim('evidence'), 13) + c.red(`✕ incomplete · ${nIncompleteSkills} bundle${nIncompleteSkills === 1 ? '' : 's'} · ${truncatedLocations} capped root${truncatedLocations === 1 ? '' : 's'}`))
  out.push('  ' + padEndV(c.dim('bloat'), 13) + (nBloat ? c.yellow('~ ' + nBloat + ' bloated') : c.green('✓ none bloated')))
  out.push('  ' + padEndV(c.dim('conflicts'), 13) + (portfolio.conflicts.length ? c.yellow('⚠ ' + portfolio.conflicts.length + ' pair' + (portfolio.conflicts.length > 1 ? 's' : '')) : c.green('✓ none')))
  if (listings.length) {
    const cut = listings.filter((v) => v.overflows)
    // Report the harness closest to its cap — that is the one that will bite first.
    const tightest = [...listings].sort((a, b) => b.listingTokens / b.budgetTokens - a.listingTokens / a.budgetTokens)[0]
    const pct = Math.round((tightest.listingTokens / tightest.budgetTokens) * 100)
    out.push('  ' + padEndV(c.dim('listing'), 13) + (cut.length
      ? c.red('✕ truncated in ' + cut.map((v) => v.harnessLabel).join(', '))
      : (pct >= 80 ? c.yellow(`⚠ ${pct}% of ${tightest.harnessLabel} budget`) : c.green(`✓ fits (${pct}% of ${tightest.harnessLabel} budget)`)))
      + c.dim(`  ·  ${alwaysOn} tok always-on, every turn`))
  }
  if (crossRisks.length) out.push('  ' + padEndV(c.dim('cross-skill'), 13) + c.yellow('⚠ ' + crossRisks.length + ' pair risk' + (crossRisks.length > 1 ? 's' : '')))
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
  // listing budget: the harness silently drops the descriptions it matches on
  for (const v of listings) {
    out.push('')
    const head = v.overflows ? c.red('listing overflow') : c.dim('listing budget')
    out.push('  ' + head + c.dim(`  ${v.harnessLabel} · ${v.listingTokens.toLocaleString()} / ${v.budgetTokens.toLocaleString()} tok`))
    for (const line of wrapTo(v.detail, 92)) out.push('    ' + (v.overflows ? c.yellow(line) : c.dim(line)))
    for (const o of v.overLongEntries.slice(0, 3)) {
      out.push('    ' + c.yellow(`${o.name}: description ${o.chars} chars > ${o.cap} cap — the tail is cut, and an exclusion clause at the end is lost`))
    }
  }
  // cross-skill capability risks (advisory — never gates a grade)
  if (crossRisks.length) {
    out.push('')
    out.push('  ' + c.dim('cross-skill') + c.dim(`  (${crossRisks.length}, advisory — what these skills can do TOGETHER)`))
    for (const r of crossRisks.slice(0, 4)) {
      out.push('    ' + c.bold(r.skills.map((n) => trunc(n, 20)).join(c.dim(' + '))) + c.dim('  ' + r.kind))
      out.push('      ' + c.dim(trunc(r.detail, 100)))
    }
    if (crossRisks.length > 4) out.push('    ' + c.dim(`… +${crossRisks.length - 4} more  (skillmoo scan --json)`))
  }
  if (portfolio.broad.length) {
    out.push('  ' + c.dim('over-broad triggers: ') + c.yellow(portfolio.broad.join(', ')))
  }

  // The terminal gives you the gist; the full, interactive report lives on the
  // web (every finding in detail + one-click optimize). Sharing is explicit;
  // ordinary interactive, CI, piped, JSON, and local-report scans stay local.
  const wantReport = argv.some((x) => x === '--report' || x === '--html')
  const wantPublish = shouldPublishScan(argv, !!process.env.SKILLMOO_NO_SHARE)

  out.push('')
  if (!wantPublish) {
    out.push('  ' + c.bold('→ Full report + one-click optimize, in your browser'))
    out.push('    run  ' + c.cyan('skillmoo scan --publish') + c.dim('   creates a shareable link · anonymous derived grades/categories only'))
  }
  out.push('  ' + c.dim('·') + ' auto-fix bloat + conflicts  ' + c.cyan('→ skillmoo pro'))
  out.push('')
  console.log(out.join('\n'))

  if ((wantReport || wantPublish) && !scanComplete) {
    console.error(c.red('  Report/publish refused: scan evidence is incomplete; inspect the capped roots or bundle issues above.\n'))
  } else if (wantReport || wantPublish) {
    // Sanitize: strip home paths to `~` so a shared report carries no identity.
    // optimize stats are computed LOCALLY from the skill's content; only the
    // resulting numbers + change descriptions travel — never the raw skill text.
    const data: ReportData = {
      generatedAt: new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC',
      locations: locations.filter((l) => l.exists).map((l) => ({ source: l.source, dir: tilde(l.dir), count: l.count })),
      skills: skills.map((s, i) => {
        const o = optimizeSkill(found[i].md, s.opts)
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
  return scanComplete && nUnsafe === 0 ? 0 : 2
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
  const loaded = found.map((skill) => ({ skill, bundle: readBundle(skill.path) }))
  const incomplete = [
    ...locations.filter((location) => location.truncated).map((location) => `${location.source}: discovery was capped or unreadable`),
    ...loaded.filter(({ bundle }) => !bundle.complete).map(({ skill, bundle }) => `${skill.name}: ${bundle.issues.join('; ')}`),
  ]
  if (incomplete.length) {
    if (json) console.log(JSON.stringify({ error: 'incomplete local evidence', complete: false, issues: incomplete }, null, 2))
    else {
      console.error('\n  ' + c.red('Plan refused: installed Skill evidence is incomplete.'))
      for (const issue of incomplete) console.error('    ' + c.yellow('! ') + safeTerminalText(issue))
      console.error('')
    }
    return 2
  }
  if (found.length === 0 && !goal) {
    if (json) { console.log(JSON.stringify({ actions: [], gaps: [], summary: { total: 0 } }, null, 2)); return 0 }
    console.log('\n  ' + c.bold('◇ SkillMOO plan') + '\n\n  ' + c.dim('No skills found. Looked in:'))
    for (const l of locations) console.log('    ' + c.gray(tilde(l.dir)))
    console.log('\n  ' + c.dim('Point at a skills folder with ') + c.cyan('skillmoo plan --dir <path>') + '\n')
    return 0
  }

  const portfolioSkills = loaded.map(({ skill: s, bundle }) => {
    return {
      name: s.name,
      md: s.md,
      ...(bundle.bundle ? { bundleText: bundle.text, bundleFiles: bundle.files } : {}),
    }
  })
  const goalPlan = goal ? planPortfolioGoal(portfolioSkills, goal, MATCHABLE_SKILLS) : null
  const plan = goalPlan?.portfolio ?? composePortfolio(portfolioSkills)
  if (json) {
    const actions = plan.actions.map(({ md: _md, bundle: _bundle, ...action }) => action)
    const payload = goalPlan ? {
      ...plan,
      actions,
      setup: {
        confidence: goalPlan.setup.confidence,
        coverage: goalPlan.setup.coverage,
        abstained: goalPlan.setup.abstained,
        compositionVerified: goalPlan.setup.compositionVerified,
        selected: goalPlan.setup.selected.map((x) => ({ name: x.skill.name, installed: x.skill.source === 'installed', role: x.role, stage: x.stage, dependsOn: x.dependsOn, grade: x.skill.grade, gate: x.skill.gate, risk: x.skill.risk, source: x.skill.source, url: x.skill.url })),
      },
      recommendedChanges: goalPlan.changes.map((x) => ({ action: x.action, name: x.skill.skill.name, reason: x.reason, source: x.skill.skill.source, url: x.skill.skill.url })),
      evidence: goalPlan.evidence,
    } : { ...plan, actions }
    console.log(JSON.stringify(payload, null, 2)); return 0
  }

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
  if (goalPlan) {
    out.push('')
    out.push('  ' + c.dim('goal setup') + c.dim(`  (${goalPlan.setup.confidence} confidence · exact combination not runtime-tested)`))
    if (goalPlan.setup.abstained) {
      out.push('    ' + c.yellow('No trusted exact match — no adjacent Skill was added to pad the answer.'))
    } else {
      for (const selected of goalPlan.alreadyInstalled) {
        out.push('    ' + c.green('KEEP ') + c.bold(trunc(selected.skill.name, 28)) + c.dim(`  already installed · ${selected.role}/${selected.stage}`))
      }
      for (const change of goalPlan.changes) {
        const label = change.action === 'replace' ? c.yellow('REPLACE ') : c.cyan('ADD ')
        out.push('    ' + label + c.bold(trunc(change.skill.skill.name, 28)) + c.dim(`  ${change.skill.role}/${change.skill.stage} · ${change.skill.skill.source}`))
        if (change.skill.skill.url) out.push('        ' + c.cyan(change.skill.skill.url))
      }
      if (!goalPlan.changes.length && goalPlan.alreadyInstalled.length) out.push('    ' + c.green('✓ current trusted setup covers the matched goal'))
      out.push('    ' + c.yellow('INSPECTED') + c.dim(` · ${goalPlan.evidence.contractVersion} · verify this exact setup on your task before relying on it`))
    }
  }
  out.push('')
  out.push('  ' + c.dim('apply: ') + c.cyan('skillmoo optimize <file>') + c.dim(' per skill  ·  auto-apply all ') + c.cyan('→ skillmoo pro'))
  out.push('  ' + c.dim(trunc(plan.basis, 96)))
  out.push('')
  console.log(out.join('\n'))
  return s.drop > 0 ? 2 : 0
}

/** `skillmoo match "<goal>"` — the same deterministic trusted retrieval plan as Web.
 * Fully local: no query, catalog data, or result leaves the machine. */
function runMatch(argv: string[]): number {
  const json = argv.includes('--json')
  const invalid = (message: string) => {
    if (json) console.log(JSON.stringify({ error: message }))
    else console.error(`${safeTerminalText(message)}\nusage: skillmoo match "<goal>" [--max 1..3] [--json]`)
    return 1
  }
  let explicitGoal = ''
  let max = 3
  let sawGoal = false, sawMax = false
  const words: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--json') continue
    if (arg === '--goal') {
      if (sawGoal) return invalid('--goal may be provided only once')
      if (!argv[i + 1] || argv[i + 1].startsWith('--')) return invalid('--goal requires a value')
      explicitGoal = argv[++i]
      sawGoal = true
      continue
    }
    if (arg === '--max') {
      if (sawMax) return invalid('--max may be provided only once')
      if (!argv[i + 1] || argv[i + 1].startsWith('--')) return invalid('--max requires a value')
      const value = Number(argv[++i])
      if (!Number.isInteger(value) || value < 1 || value > 3) return invalid('--max must be an integer from 1 to 3')
      max = value
      sawMax = true
      continue
    }
    if (arg.startsWith('-')) return invalid(`unknown option: ${arg}`)
    words.push(arg)
  }
  const goal = (explicitGoal || words.join(' ')).trim()
  if (!goal) {
    return invalid('goal is required')
  }

  const conflicts = analyzePortfolio(MATCHABLE_SKILLS.map((s) => ({ name: s.name, description: s.description }))).conflicts
  const high = new Set(conflicts.filter((x) => x.severity === 'high').flatMap((x) => [`${x.a}|${x.b}`, `${x.b}|${x.a}`]))
  const plan = planGoal(goal, MATCHABLE_SKILLS, high, max)
  const artifactEntryFor = (name: string) => ARTIFACT_INDEX.entries.find((item) => item.name === name)
  const evidenceSkill = (skill: (typeof MATCHABLE_SKILLS)[number]) => {
    const entry = artifactEntryFor(skill.name)
    return entry?.status === 'pilot-ready' ? { ...skill, evidence: {
      scope: 'bundle' as const, sourceRef: entry.artifact.source.pinnedUrl,
      sourcePath: entry.artifact.source.rootPath, sha256: entry.artifact.manifest.bundleSha256,
    } } : skill
  }
  const evidence = summarizeCombinationEvidence(plan.selected.map((x) => evidenceSkill(x.skill)))
  const artifactFor = (name: string) => {
    const entry = artifactEntryFor(name)
    return entry?.status === 'pilot-ready' ? {
      status: 'complete-package-inspected', artifactId: entry.artifact.artifactId,
      pinnedUrl: entry.artifact.source.pinnedUrl,
      setup: `skillmoo catalog prepare --artifact ${entry.artifact.artifactId}`,
    } : { status: 'manifest-screened', packageEvidence: 'unknown' }
  }
  const result = {
    version: VERSION,
    engine: 'skillmoo-retrieval/2',
    goal,
    catalog: { candidates: MATCHABLE_SKILLS.length, evidenceLevel: 'manifest-screened', excludedCompletePackageGate: COMPLETE_PACKAGE_REJECTED.size, sourceCount: MATCH_CATALOG_META.count },
    constraints: {
      forbidden: [...plan.constraints.forbidden],
      forbiddenCapabilities: [...plan.constraints.forbiddenCapabilities],
    },
    confidence: plan.confidence,
    coverage: Math.round(plan.coverage * 1000) / 1000,
    abstained: plan.abstained,
    compositionVerified: plan.compositionVerified,
    evidence,
    skills: plan.selected.map((x) => ({
      name: x.skill.name,
      role: x.role,
      stage: x.stage,
      dependsOn: x.dependsOn,
      grade: x.skill.grade,
      gate: x.skill.gate,
      risk: x.skill.risk,
      tokens: x.skill.tokens,
      source: x.skill.source,
      url: x.skill.url,
      score: x.score,
      matched: x.matched,
      evidence: summarizeSkillEvidence(evidenceSkill(x.skill)),
      artifact: artifactFor(x.skill.name),
    })),
    disclaimer: 'Static recommendation only; runtime utility and composition are not verified.',
  }
  if (json) { console.log(JSON.stringify(result, null, 2)); return 0 }

  console.log('')
  console.log('  ' + c.bold('◇ SkillMOO') + c.dim(' match · local · model-free'))
  console.log('  ' + c.dim('goal       ') + c.cyan(goal))
  console.log('  ' + c.dim('catalog    ') + `${MATCHABLE_SKILLS.length} manifest-screened A/B · PASS · low-risk candidates`)
  if (result.constraints.forbidden.length || result.constraints.forbiddenCapabilities.length) {
    console.log('  ' + c.dim('excluded   ') + c.yellow([...new Set([...result.constraints.forbidden, ...result.constraints.forbiddenCapabilities])].join(', ')))
  }
  console.log('')
  if (plan.abstained) {
    console.log('  ' + c.yellow('No constraint-safe exact match.'))
    console.log('  ' + c.dim('SkillMOO refused to pad the result with adjacent skills. Try a more specific goal or inspect the Web catalog.'))
  } else {
    console.log('  ' + c.green(`✓ ${plan.selected.length} minimal match${plan.selected.length === 1 ? '' : 'es'}`) + c.dim(`  ·  ${plan.confidence} confidence  ·  ${Math.round(plan.coverage * 100)}% catalog-term coverage`))
    console.log('  ' + c.yellow('INSPECTED') + c.dim(` · ${evidence.contractVersion} · exact setup not runtime-tested`))
    for (const x of plan.selected) {
      console.log('')
      console.log('  ' + gradeBadge(x.skill.grade) + '  ' + c.bold(x.skill.name) + c.dim(`  ·  ${x.role}/${x.stage}`))
      console.log('     ' + c.green('PASS') + c.dim(` · low risk · ${x.skill.tokens.toLocaleString()} tok · ${x.skill.source}`))
      console.log('     ' + c.dim('matched: ') + x.matched.slice(0, 6).join(', '))
      const artifact = artifactFor(x.skill.name)
      if (artifact.status === 'complete-package-inspected') {
        console.log('     ' + c.green('COMPLETE PACKAGE') + c.dim(` · ${artifact.artifactId}`))
        console.log('     ' + c.cyan(artifact.pinnedUrl!))
        console.log('     ' + c.dim(`setup: ${artifact.setup}`))
      } else {
        console.log('     ' + c.yellow('MANIFEST ONLY') + c.dim(' · package contents unknown; mutable source link'))
        console.log('     ' + c.cyan(x.skill.url))
      }
    }
  }
  console.log('')
  console.log('  ' + c.dim('Static recommendation only — re-scan the complete pinned package before setup; runtime utility and composition are not verified.'))
  console.log('  ' + c.dim('Your goal stays local. No model and no network request are used.'))
  console.log('')
  return 0
}

function runReport(file?: string): number {
  if (!file) { console.error('usage: skillmoo report <SKILL.md>'); return 1 }
  const primary = readPrimarySkill(file)
  if (!primary.ok) {
    console.error('\n  ' + c.red('Report refused: ' + primary.issue) + '\n')
    return 2
  }
  const bundle = readBundle(file)
  if (!bundle.complete) {
    console.error('\n  ' + c.red('Report refused: ' + bundleIssueSummary(bundle.issues)) + '\n')
    return 2
  }
  const a = analyzeSkill(primary.md, bundleOptsFor(bundle))
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
  const primary = readPrimarySkill(file)
  if (!primary.ok) {
    console.error('\n  ' + c.red('Optimize refused: ' + primary.issue) + '\n')
    return 2
  }
  const bundle = readBundle(file)
  if (!bundle.complete) {
    console.error('\n  ' + c.red('Optimize refused: ' + bundleIssueSummary(bundle.issues)) + '\n')
    return 2
  }
  const md = primary.md

  if (!argv.includes('--pro')) {
    // Same bundle context the scan uses — so optimize's suggestions (e.g. a dangling
    // references/ link) match what `skillmoo scan` reported. Read-only.
    const o = optimizeSkill(md, bundleOptsFor(bundle))
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

  const r = await optimizePro(md, chat, bundleOptsFor(bundle))
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
    ${c.dim('--publish')}                  ${c.dim('explicitly upload a derived report for a shareable skillmoo.com/r/<id> link')}
    ${c.dim('--no-share')}                 ${c.dim('never upload — keep the scan fully local (or SKILLMOO_NO_SHARE=1)')}
    ${c.dim('--json')}                     ${c.dim('machine-readable output')}
    ${c.dim('--dir <path>')}               ${c.dim('add an extra skills root')}
  ${c.bold('skillmoo plan')}                ${c.dim('value-max action plan: keep/optimize/merge/narrow/drop + gaps')}
    ${c.dim('--goal "<text>"')}            ${c.dim('weight the plan toward what you\'re trying to build')}
  ${c.bold('skillmoo match')} ${c.dim('"<goal>"')}     ${c.dim('find a trusted minimal Skill plan (same engine as Web, fully local)')}
    ${c.dim('--max <1..3>')}               ${c.dim('maximum selected Skills; default 3, never padded')}
    ${c.dim('--json')}                     ${c.dim('machine-readable result for scripts and agents')}
  ${c.bold('skillmoo report')} ${c.dim('<file>')}       ${c.dim('full report for one SKILL.md')}
  ${c.bold('skillmoo optimize')} ${c.dim('<file>')}     ${c.dim('rule-based one-click optimize (100% local)')}
    ${c.dim('--pro')}                      ${c.dim('AI semantic rewrite, verified safe — uses YOUR model key (SKILLMOO_MODEL_KEY)')}
  ${c.bold('skillmoo verify')}              ${c.dim('paired current-vs-proposed runtime check in one declared environment')}
    ${c.dim('--suite <suite.json>')}        ${c.dim('objective, versioned task suite')}
    ${c.dim('--baseline-skill <file>')}     ${c.dim('current ordered setup; repeat for multiple Skills')}
    ${c.dim('--baseline-empty')}            ${c.dim('explicitly declare that the current setup has no Skills')}
    ${c.dim('--skill <file>')}              ${c.dim('proposed ordered setup; repeat for multiple Skills')}
    ${c.dim('--proposed-empty')}            ${c.dim('explicitly declare that the proposed setup has no Skills')}
    ${c.dim('--send-to-model')}             ${c.dim('explicitly allow suite + Skill egress to YOUR model endpoint')}
    ${c.dim('--timeout-ms <1000..300000>')} ${c.dim('per-request provider timeout; default 30000')}
    ${c.dim('--simulate')}                  ${c.dim('test the harness only; can never become verified-here')}
    ${c.dim('summary [--dir <path>]')}      ${c.dim('local self-attested receipt metrics')}
  ${c.bold('skillmoo setup')}               ${c.dim('preview, explicitly apply, rollback, or recover a local complete Skill setup')}
    ${c.dim('prepare --source <dir>')}      ${c.dim('freeze a no-mutation plan; repeat --source for a combination')}
    ${c.dim('apply --plan <file>')}         ${c.dim('requires --confirm <plan-id>; installs no remote content and runs no package code')}
    ${c.dim('status --target-root <dir>')}  ${c.dim('read-only transaction and recovery status')}
    ${c.dim('rollback --receipt <file>')}   ${c.dim('requires --confirm <receipt-id>; refuses post-install drift')}
    ${c.dim('recover --mode rollback')}     ${c.dim('requires --confirm <transaction-id>; never guesses or rolls forward')}
  ${c.bold('skillmoo catalog')}             ${c.dim('offline pinned-complete artifact pilot in the exact CLI package')}
    ${c.dim('list')}                        ${c.dim('show embedded artifact IDs, evidence, license, files, and bytes')}
    ${c.dim('prepare --artifact <sa_id>')}  ${c.dim('materialize exact bytes into private cache and create a no-target-mutation setup plan')}

  ${c.dim('Static analysis is 100% local — no model, no signup. `optimize --pro` and explicitly approved `verify` use your endpoint.')}
  ${c.dim('All static commands stay offline unless you explicitly pass `scan --publish`; --no-share always wins.')}
`)
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2)
  let code = 0
  switch (cmd) {
    case undefined:
    case 'scan': code = await runScan(rest); break
    case 'plan': code = runPlan(rest); break
    case 'match': code = runMatch(rest); break
    case 'verify': code = await runVerifyCommand(rest, VERSION); break
    case 'setup': code = runSetupCommand(rest); break
    case 'catalog': code = runCatalogCommand(rest); break
    case 'report': code = runReport(rest.find((a) => !a.startsWith('-'))); break
    case 'optimize': code = await runOptimize(rest.find((a) => !a.startsWith('-')), rest); break
    case '-v': case '--version': case 'version': console.log(VERSION); break
    case '-h': case '--help': case 'help': help(); break
    default: console.error(`unknown command: ${safeTerminalText(cmd)}\n`); help(); code = 1
  }
  process.exitCode = code
}
void main()
