/**
 * discover — find the agent skills / rule files already installed on this machine.
 *
 * Different tools keep their agent-instruction files in different places and
 * formats, but they're all the same kind of thing — text (± bundled scripts)
 * that reshapes what the agent does. We rate them all:
 *   • Claude Code / Codex   <name>/SKILL.md, *.skill.md
 *   • Cursor                .cursor/rules/*.mdc, legacy .cursorrules
 *   • GitHub Copilot        .github/copilot-instructions.md, .github/instructions/*.instructions.md
 *   • Cline                 .clinerules (file or dir of *.md), ~/Documents/Cline/Rules/*.md
 *   • Windsurf              .windsurf/rules/*.md, legacy .windsurfrules
 *
 * Each root carries its own filename matcher; single-file conventions are checked
 * directly. Pure Node fs — no model, no network. This is the free static wedge.
 */
import { readdirSync, statSync, readFileSync, realpathSync } from 'node:fs'
import { join, basename, dirname, relative } from 'node:path'
import { homedir } from 'node:os'

/** A place to look. `match` filters filenames in a walked dir; `file` means `dir` IS a single file. */
export interface Root { dir: string; source: string; match?: (e: string) => boolean; file?: boolean }
export interface FoundSkill { name: string; path: string; source: string; md: string }
export interface ScanLocation { source: string; dir: string; exists: boolean; count: number }

const SKIP = new Set(['node_modules', '.git', 'cache', '.cache', 'dist', 'build', '__pycache__', 'attachments', 'data'])
const isSkillMd = (e: string) => /^skill\.md$/i.test(e) || /\.skill\.md$/i.test(e)

function walk(dir: string, depth: number, match: (e: string) => boolean, out: string[]): void {
  if (depth < 0) return
  let entries: string[]
  try { entries = readdirSync(dir) } catch { return }
  for (const e of entries) {
    if (e.startsWith('.') && e !== '.claude' && e !== '.codex') continue
    if (SKIP.has(e)) continue
    const p = join(dir, e)
    let st
    try { st = statSync(p) } catch { continue }
    if (st.isDirectory()) walk(p, depth - 1, match, out)
    else if (match(e)) out.push(p)
  }
}

/** Standard roots across Claude Code, Codex, Cursor, Copilot, Cline, and Windsurf. */
export function defaultRoots(cwd = process.cwd()): Root[] {
  const h = homedir()
  return [
    // Claude Code + Codex — SKILL.md
    { dir: join(h, '.claude', 'skills'), source: 'Claude Code · user', match: isSkillMd },
    { dir: join(cwd, '.claude', 'skills'), source: 'Claude Code · project', match: isSkillMd },
    { dir: join(h, '.claude', 'plugins'), source: 'Claude Code · plugins', match: isSkillMd },
    { dir: join(h, '.codex', 'skills'), source: 'Codex · user', match: isSkillMd },
    { dir: join(cwd, '.codex', 'skills'), source: 'Codex · project', match: isSkillMd },
    // Cursor
    { dir: join(cwd, '.cursor', 'rules'), source: 'Cursor · rules', match: (e) => /\.mdc$/i.test(e) },
    { dir: join(cwd, '.cursorrules'), source: 'Cursor · .cursorrules', file: true },
    // GitHub Copilot
    { dir: join(cwd, '.github', 'copilot-instructions.md'), source: 'Copilot · instructions', file: true },
    { dir: join(cwd, '.github', 'instructions'), source: 'Copilot · instructions', match: (e) => /\.instructions\.md$/i.test(e) },
    // Cline — .clinerules can be a single file OR a directory of *.md
    { dir: join(cwd, '.clinerules'), source: 'Cline · rules', match: (e) => /\.md$/i.test(e) },
    { dir: join(cwd, '.clinerules'), source: 'Cline · rules', file: true },
    { dir: join(h, 'Documents', 'Cline', 'Rules'), source: 'Cline · user', match: (e) => /\.md$/i.test(e) },
    // Windsurf
    { dir: join(cwd, '.windsurf', 'rules'), source: 'Windsurf · rules', match: (e) => /\.md$/i.test(e) },
    { dir: join(cwd, '.windsurfrules'), source: 'Windsurf · .windsurfrules', file: true },
  ]
}

function skillName(file: string, md: string): string {
  const base = basename(file)
  const lower = base.toLowerCase()
  // single-file conventions → a clean, recognizable label
  if (lower === '.cursorrules') return '.cursorrules'
  if (lower === '.windsurfrules') return '.windsurfrules'
  if (lower === '.clinerules') return '.clinerules'
  if (lower === 'copilot-instructions.md') return 'copilot-instructions'
  if (/\.skill\.md$/i.test(base)) return base.replace(/\.skill\.md$/i, '')
  if (/^skill\.md$/i.test(base)) {
    const parent = basename(dirname(file))
    if (parent && parent.toLowerCase() !== 'skills') return parent
  }
  // .mdc (Cursor), .instructions.md (Copilot), .md (Cline/Windsurf) → frontmatter name or file stem
  const m = md.match(/^\s*name\s*:\s*["']?([^"'\n]+)["']?/im)
  if (m) return m[1].trim()
  return base.replace(/\.instructions\.md$/i, '').replace(/\.mdc$/i, '').replace(/\.md$/i, '')
}

// Indirect-injection defense: a SKILL.md can hide its payload in the files it tells
// the agent to read/run (references/*.md, scripts/*.sh) — a SKILL.md-only scanner is
// trivially defeated. readBundle collects those bundled files (READ-ONLY, bounded) so
// analyzeSkill's security scan sees them too. Only for real SKILL.md bundles (which
// live in their own dir); single-file rule formats (.cursorrules/.mdc/…) have no
// bundle, and their "dir" is the whole project — never walk that.
const BUNDLE_SCRIPT = /\.(sh|bash|zsh|py|python3?|js|mjs|cjs|ts|rb|pl|ps1|php)$/i
const BUNDLE_TEXT = /\.(md|markdown|mdx|txt|rst)$/i
const BUNDLE_LANG: Record<string, string> = { sh: 'bash', bash: 'bash', zsh: 'bash', py: 'python', python: 'python', python3: 'python', js: 'js', mjs: 'js', cjs: 'js', ts: 'ts', rb: 'ruby', pl: 'perl', ps1: 'powershell', php: 'php' }

export function readBundle(skillPath: string): { text: string; files: string[]; bundle: boolean } {
  // Only SKILL.md / *.skill.md have a dedicated bundle dir. `bundle` tells the caller
  // whether a bundle context exists at all (so an EMPTY files list means "the skill
  // references files that aren't there", not "single-file rule format, don't check").
  if (!isSkillMd(basename(skillPath))) return { text: '', files: [], bundle: false }
  const dir = dirname(skillPath)
  const skillReal = (() => { try { return realpathSync(skillPath) } catch { return skillPath } })()
  const out: string[] = []
  const files: string[] = []
  let total = 0
  const MAX_FILES = 40, MAX_TOTAL = 200_000, MAX_FILE = 64_000
  const collect = (d: string, depth: number): void => {
    if (depth < 0 || files.length >= MAX_FILES || total >= MAX_TOTAL) return
    let entries: string[]
    try { entries = readdirSync(d) } catch { return }
    for (const e of entries) {
      if (files.length >= MAX_FILES || total >= MAX_TOTAL) break
      if (e.startsWith('.') || SKIP.has(e)) continue
      const p = join(d, e)
      let st
      try { st = statSync(p) } catch { continue }
      if (st.isDirectory()) { collect(p, depth - 1); continue }
      const isScript = BUNDLE_SCRIPT.test(e)
      if (!isScript && !BUNDLE_TEXT.test(e)) continue
      if (isSkillMd(e)) continue // don't re-scan the SKILL.md(s) themselves
      let real: string
      try { real = realpathSync(p) } catch { real = p }
      if (real === skillReal) continue
      if (st.size > MAX_FILE) continue
      let c: string
      try { c = readFileSync(p, 'utf8') } catch { continue }
      if (isScript) {
        const ext = (e.match(BUNDLE_SCRIPT)?.[1] ?? '').toLowerCase()
        out.push('```' + (BUNDLE_LANG[ext] ?? '') + '\n' + c + '\n```')
      } else {
        out.push(c)
      }
      files.push(relative(dir, p) || e)
      total += c.length
    }
  }
  collect(dir, 3)
  return { text: out.join('\n\n'), files, bundle: true }
}

export function discover(roots: Root[]): { found: FoundSkill[]; locations: ScanLocation[] } {
  const found: FoundSkill[] = []
  const seen = new Set<string>()
  const locations: ScanLocation[] = []
  for (const r of roots) {
    // Single-file root: check the one path directly.
    if (r.file) {
      let isFile = false
      try { isFile = statSync(r.dir).isFile() } catch { isFile = false }
      if (!isFile) { locations.push({ source: r.source, dir: r.dir, exists: false, count: 0 }); continue }
      const real = (() => { try { return realpathSync(r.dir) } catch { return r.dir } })()
      if (seen.has(real)) { locations.push({ source: r.source, dir: r.dir, exists: true, count: 0 }); continue }
      seen.add(real)
      let md: string
      try { md = readFileSync(r.dir, 'utf8') } catch { locations.push({ source: r.source, dir: r.dir, exists: false, count: 0 }); continue }
      found.push({ name: skillName(r.dir, md), path: r.dir, source: r.source, md })
      locations.push({ source: r.source, dir: r.dir, exists: true, count: 1 })
      continue
    }
    // Directory root: walk it with the root's matcher (default: SKILL.md).
    let exists = true
    try { exists = statSync(r.dir).isDirectory() } catch { exists = false }
    if (!exists) { locations.push({ source: r.source, dir: r.dir, exists: false, count: 0 }); continue }
    const files: string[] = []
    walk(r.dir, 4, r.match ?? isSkillMd, files)
    let count = 0
    for (const f of files) {
      let real: string
      try { real = realpathSync(f) } catch { real = f }
      if (seen.has(real)) continue
      seen.add(real)
      let md: string
      try { md = readFileSync(f, 'utf8') } catch { continue }
      found.push({ name: skillName(f, md), path: f, source: r.source, md })
      count++
    }
    locations.push({ source: r.source, dir: r.dir, exists: true, count })
  }
  return { found, locations }
}
