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
import { lstatSync, readdirSync, readFileSync, realpathSync } from 'node:fs'
import { join, basename, dirname, isAbsolute, relative } from 'node:path'
import { homedir } from 'node:os'

/** A place to look. `match` filters filenames in a walked dir; `file` means `dir` IS a single file. */
export interface Root { dir: string; source: string; match?: (e: string) => boolean; file?: boolean }
export interface FoundSkill { name: string; path: string; source: string; md: string }
export interface ScanLocation { source: string; dir: string; exists: boolean; count: number; truncated?: boolean }

const SKIP = new Set(['node_modules', '.git', 'cache', '.cache', 'dist', 'build', '__pycache__', 'attachments', 'data'])
const isSkillMd = (e: string) => /^skill\.md$/i.test(e) || /\.skill\.md$/i.test(e)
export const MAX_PRIMARY_SKILL_BYTES = 1_048_576
const MAX_ROOT_MATCHES = 500
const MAX_TOTAL_PRIMARY_BYTES = 20 * 1024 * 1024

export function readPrimarySkill(skillPath: string): { ok: true; md: string } | { ok: false; issue: string } {
  let st
  try { st = lstatSync(skillPath) } catch { return { ok: false, issue: 'primary Skill file could not be inspected' } }
  if (st.isSymbolicLink() || !st.isFile()) return { ok: false, issue: 'primary Skill must be a regular non-symbolic file' }
  if (st.size > MAX_PRIMARY_SKILL_BYTES) return { ok: false, issue: `primary Skill exceeds ${MAX_PRIMARY_SKILL_BYTES} bytes` }
  try { return { ok: true, md: readFileSync(skillPath, 'utf8') } } catch { return { ok: false, issue: 'primary Skill file could not be read' } }
}

function walk(dir: string, rootReal: string, depth: number, match: (e: string) => boolean, out: string[]): void {
  if (depth < 0) return
  if (out.length >= MAX_ROOT_MATCHES) return
  let entries: string[]
  try { entries = readdirSync(dir) } catch { return }
  for (const e of entries) {
    if (out.length >= MAX_ROOT_MATCHES) return
    if (e.startsWith('.') && e !== '.claude' && e !== '.codex') continue
    if (SKIP.has(e)) continue
    const p = join(dir, e)
    let st
    try { st = lstatSync(p) } catch { continue }
    if (st.isSymbolicLink()) continue
    let real: string
    try { real = realpathSync(p) } catch { continue }
    const fromRoot = relative(rootReal, real)
    if (fromRoot.startsWith('..') || isAbsolute(fromRoot)) continue
    if (st.isDirectory()) walk(p, rootReal, depth - 1, match, out)
    else if (st.isFile() && match(e)) out.push(p)
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

export function readBundle(skillPath: string): { text: string; files: string[]; bundle: boolean; complete: boolean; issues: string[] } {
  // Only SKILL.md / *.skill.md have a dedicated bundle dir. `bundle` tells the caller
  // whether a bundle context exists at all (so an EMPTY files list means "the skill
  // references files that aren't there", not "single-file rule format, don't check").
  if (!isSkillMd(basename(skillPath))) return { text: '', files: [], bundle: false, complete: true, issues: [] }
  const dir = dirname(skillPath)
  const skillReal = (() => { try { return realpathSync(skillPath) } catch { return skillPath } })()
  const rootReal = (() => { try { return realpathSync(dir) } catch { return dir } })()
  const out: string[] = []
  const files: string[] = []
  const issues: string[] = []
  let total = 0
  const MAX_FILES = 40, MAX_TOTAL = 200_000, MAX_FILE = 64_000
  const issue = (value: string) => { if (!issues.includes(value)) issues.push(value) }
  const collect = (d: string, depth: number): void => {
    if (depth < 0) { issue('bundle nesting exceeds the supported depth'); return }
    let entries: string[]
    try { entries = readdirSync(d).sort((a, b) => a.localeCompare(b, 'en')) } catch { issue(`bundle directory could not be read: ${relative(dir, d) || '.'}`); return }
    for (const e of entries) {
      const p = join(d, e)
      let st
      try { st = lstatSync(p) } catch { issue(`bundle entry could not be inspected: ${relative(dir, p) || e}`); continue }
      if (e.startsWith('.') || SKIP.has(e)) {
        const eligibleFile = st.isFile() && (BUNDLE_SCRIPT.test(e) || BUNDLE_TEXT.test(e))
        const excludedDirectory = st.isDirectory() && e !== '.git'
        if (st.isSymbolicLink() || eligibleFile || excludedDirectory) issue(`bundle contains excluded content that prevents exact verification: ${relative(dir, p) || e}`)
        continue
      }
      if (st.isSymbolicLink()) { issue(`bundle contains a symbolic link: ${relative(dir, p) || e}`); continue }
      if (st.isDirectory()) { collect(p, depth - 1); continue }
      if (!st.isFile()) { issue(`bundle contains a non-regular file: ${relative(dir, p) || e}`); continue }
      const isScript = BUNDLE_SCRIPT.test(e)
      if (!isScript && !BUNDLE_TEXT.test(e)) continue
      if (isSkillMd(e)) continue // don't re-scan the SKILL.md(s) themselves
      if (files.length >= MAX_FILES) { issue(`bundle exceeds ${MAX_FILES} eligible files`); continue }
      let real: string
      try { real = realpathSync(p) } catch { issue(`bundle file could not be resolved: ${relative(dir, p) || e}`); continue }
      const fromRoot = relative(rootReal, real)
      if (fromRoot.startsWith('..') || isAbsolute(fromRoot)) { issue(`bundle file resolves outside its root: ${relative(dir, p) || e}`); continue }
      if (real === skillReal) continue
      if (st.size > MAX_FILE) { issue(`bundle file exceeds ${MAX_FILE} bytes: ${relative(dir, p) || e}`); continue }
      let c: string
      try { c = readFileSync(p, 'utf8') } catch { issue(`bundle file could not be read: ${relative(dir, p) || e}`); continue }
      const bytes = Buffer.byteLength(c)
      if (total + bytes > MAX_TOTAL) { issue(`bundle exceeds ${MAX_TOTAL} bytes of eligible content`); continue }
      if (isScript) {
        const ext = (e.match(BUNDLE_SCRIPT)?.[1] ?? '').toLowerCase()
        out.push('```' + (BUNDLE_LANG[ext] ?? '') + '\n' + c + '\n```')
      } else {
        out.push(c)
      }
      files.push(relative(dir, p) || e)
      total += bytes
    }
  }
  collect(dir, 3)
  return { text: out.join('\n\n'), files, bundle: true, complete: issues.length === 0, issues }
}

export function discover(roots: Root[]): { found: FoundSkill[]; locations: ScanLocation[] } {
  const found: FoundSkill[] = []
  const seen = new Set<string>()
  const locations: ScanLocation[] = []
  let totalPrimaryBytes = 0
  for (const r of roots) {
    // Single-file root: check the one path directly.
    if (r.file) {
      let exists = false
      let isFile = false
      let singleSize = 0
      try { const st = lstatSync(r.dir); exists = true; singleSize = st.size; isFile = st.isFile() && !st.isSymbolicLink() } catch { isFile = false }
      if (!isFile) { locations.push({ source: r.source, dir: r.dir, exists: false, count: 0 }); continue }
      if (singleSize > MAX_PRIMARY_SKILL_BYTES || totalPrimaryBytes + singleSize > MAX_TOTAL_PRIMARY_BYTES) {
        locations.push({ source: r.source, dir: r.dir, exists, count: 0, truncated: true })
        continue
      }
      const real = (() => { try { return realpathSync(r.dir) } catch { return r.dir } })()
      if (seen.has(real)) { locations.push({ source: r.source, dir: r.dir, exists: true, count: 0 }); continue }
      seen.add(real)
      let md: string
      try { md = readFileSync(r.dir, 'utf8') } catch { locations.push({ source: r.source, dir: r.dir, exists: true, count: 0, truncated: true }); continue }
      totalPrimaryBytes += singleSize
      found.push({ name: skillName(r.dir, md), path: r.dir, source: r.source, md })
      locations.push({ source: r.source, dir: r.dir, exists: true, count: 1 })
      continue
    }
    // Directory root: walk it with the root's matcher (default: SKILL.md).
    let exists = true
    let rootReal = ''
    try { const st = lstatSync(r.dir); exists = st.isDirectory() && !st.isSymbolicLink(); if (exists) rootReal = realpathSync(r.dir) } catch { exists = false }
    if (!exists) { locations.push({ source: r.source, dir: r.dir, exists: false, count: 0 }); continue }
    const files: string[] = []
    walk(r.dir, rootReal, 4, r.match ?? isSkillMd, files)
    let count = 0
    let truncated = files.length >= MAX_ROOT_MATCHES
    for (const f of files) {
      let size = 0
      try {
        const st = lstatSync(f)
        if (!st.isFile() || st.isSymbolicLink()) { truncated = true; continue }
        if (st.size > MAX_PRIMARY_SKILL_BYTES) { truncated = true; continue }
        size = st.size
      } catch { truncated = true; continue }
      if (totalPrimaryBytes + size > MAX_TOTAL_PRIMARY_BYTES) { truncated = true; break }
      let real: string
      try { real = realpathSync(f) } catch { truncated = true; continue }
      if (seen.has(real)) continue
      seen.add(real)
      let md: string
      try { md = readFileSync(f, 'utf8') } catch { truncated = true; continue }
      totalPrimaryBytes += Buffer.byteLength(md)
      found.push({ name: skillName(f, md), path: f, source: r.source, md })
      count++
    }
    locations.push({ source: r.source, dir: r.dir, exists: true, count, ...(truncated ? { truncated: true } : {}) })
  }
  return { found, locations }
}
