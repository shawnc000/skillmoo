/**
 * Crash-recoverable local Skill setup executor.
 *
 * It deliberately accepts only complete local directories and recognized
 * Codex/Claude roots. It never downloads content or executes package code.
 */
import {
  accessSync,
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  statfsSync,
  unlinkSync,
  writeFileSync,
  type Stats,
} from 'node:fs'
import { createHash, randomUUID } from 'node:crypto'
import { homedir, platform } from 'node:os'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { analyzeSkill, RUBRIC_VERSION, type Gate, type RiskLevel } from '../src/lib/analyzeSkill'
import { safeTerminalText } from './format'

export const SETUP_PROTOCOL_VERSION = 'skillmoo-setup/1.0'
export const SETUP_INSTALLER_VERSION = 'skillmoo-cli/setup-1.0'

const MAX_FILES = 200
const MAX_TOTAL_BYTES = 20 * 1024 * 1024
const MAX_FILE_BYTES = 4 * 1024 * 1024
const MAX_SCANNED_BYTES = 262_144
const MAX_DEPTH = 8
const MAX_RELATIVE_BYTES = 240
const MAX_COMPONENT_BYTES = 120
const JOURNAL_MARGIN_BYTES = 1024 * 1024
const RESERVED_NAMES = new Set(['.system', '.skillmoo'])
const MANAGER_MARKERS = new Set(['.codex-plugin', '.claude-plugin', '.skill-manager'])
const SCRIPT_EXT = /\.(?:sh|bash|zsh|py|python3?|js|mjs|cjs|ts|rb|pl|ps1|php)$/i
const TEXT_EXT = /\.(?:md|markdown|mdx|txt|rst|json|ya?ml|toml|xml|html?|css|csv|tsv)$/i

export class SetupError extends Error {
  constructor(message: string, readonly exitCode: 1 | 2 | 3 = 1) {
    super(message)
    this.name = 'SetupError'
  }
}

class SetupCrashSimulation extends Error {
  constructor(readonly point: string) { super(`simulated hard interruption at ${point}`) }
}

export interface SetupManifestEntry {
  path: string
  kind: 'directory' | 'file'
  mode: number
  size?: number
  sha256?: string
}

export interface SetupManifest {
  bundleSha256: string
  rootMode: number
  entries: SetupManifestEntry[]
  files: number
  totalBytes: number
  uninterpretedFiles: string[]
}

export interface SetupAnalysisSummary {
  grade: string
  gate: Gate
  risk: RiskLevel
  rubricVersion: string
  vector: string
  uninterpretedFiles: number
}

interface ActiveOwner {
  protocolVersion: typeof SETUP_PROTOCOL_VERSION
  name: string
  targetDir: string
  transactionId: string
  bundleSha256: string
  integritySha256: string
}

export interface SetupPlanAction {
  index: number
  name: string
  action: 'add' | 'replace'
  sourceDir: string
  targetDir: string
  source: SetupManifest
  before: SetupManifest | null
  beforeOwner: ActiveOwner | null
  analysis: SetupAnalysisSummary
}

export interface SetupTargetIdentity {
  root: string
  adminRoot: string
  harness: 'codex' | 'claude'
  scope: 'user' | 'project'
  projectRoot?: string
  device: number
}

export interface SetupPlan {
  protocolVersion: typeof SETUP_PROTOCOL_VERSION
  installerVersion: typeof SETUP_INSTALLER_VERSION
  planId: string
  createdAt: string
  target: SetupTargetIdentity
  actions: SetupPlanAction[]
  limitations: string[]
}

interface JournalAction extends SetupPlanAction {
  stageDir: string
  backupDir: string
  quarantineDir: string
  ownedAfterTransactionId: string
  status: 'pending' | 'old-moved' | 'new-visible' | 'restored'
}

interface SetupJournal {
  protocolVersion: typeof SETUP_PROTOCOL_VERSION
  installerVersion: typeof SETUP_INSTALLER_VERSION
  transactionId: string
  kind: 'apply' | 'rollback'
  planId: string
  receiptId?: string
  createdAt: string
  updatedAt: string
  state: string
  target: SetupTargetIdentity
  actions: JournalAction[]
  error?: string
  integritySha256: string
}

export interface SetupReceiptAction {
  index: number
  name: string
  action: 'add' | 'replace'
  targetDir: string
  before: SetupManifest | null
  after: SetupManifest
  beforeOwner: ActiveOwner | null
  analysis: SetupAnalysisSummary
  backupDir: string
}

export interface SetupReceipt {
  protocolVersion: typeof SETUP_PROTOCOL_VERSION
  installerVersion: typeof SETUP_INSTALLER_VERSION
  receiptId: string
  transactionId: string
  planId: string
  completedAt: string
  target: SetupTargetIdentity
  actions: SetupReceiptAction[]
  evidence: {
    status: 'inspected'
    attestation: 'local-self-attested'
    rubricVersion: string
  }
  limitations: string[]
}

export interface SetupStatus {
  targetRoot: string
  adminRoot: string
  lock: { transactionId: string; pid: number; startedAt: string } | null
  pending: Array<{ transactionId: string; kind: string; state: string; updatedAt: string }>
  receipts: number
}

export interface PrepareSetupOptions {
  sourceDirs: string[]
  targetRoot: string
  planPath: string
  projectRoot?: string
}

export interface ApplySetupOptions {
  planPath: string
  confirm: string
  /** Test-only deterministic fault injection; CLI parsing never exposes these. */
  testFailAt?: string
  /** Test-only hard-crash simulation; leaves journal/lock for recovery. */
  testCrashAt?: string
}

const sha256 = (value: string | Buffer) => createHash('sha256').update(value).digest('hex')

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b, 'en'))
      .map(([key, item]) => [key, canonicalize(item)]))
  }
  return value
}

const canonicalJson = (value: unknown) => JSON.stringify(canonicalize(value))
const digestObject = (value: unknown) => sha256(canonicalJson(value))
const without = <T extends object, K extends keyof T>(value: T, key: K): Omit<T, K> => {
  const clone = { ...value }
  delete clone[key]
  return clone
}

function fsyncDirectory(path: string): void {
  let fd: number | undefined
  try { fd = openSync(path, constants.O_RDONLY); fsyncSync(fd) }
  catch { /* Some filesystems do not support directory fsync; file fsync still holds. */ }
  finally { if (fd !== undefined) closeSync(fd) }
}

function writePrivateJsonNew(path: string, value: unknown): void {
  const fd = openSync(path, 'wx', 0o600)
  try {
    writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
    fsyncSync(fd)
  } finally { closeSync(fd) }
  chmodSync(path, 0o600)
  fsyncDirectory(dirname(path))
}

function writeDurableJson(path: string, value: unknown): void {
  const temp = `${path}.tmp-${process.pid}-${randomUUID()}`
  const fd = openSync(temp, 'wx', 0o600)
  try {
    writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
    fsyncSync(fd)
  } finally { closeSync(fd) }
  renameSync(temp, path)
  chmodSync(path, 0o600)
  fsyncDirectory(dirname(path))
}

function readJson(path: string): unknown {
  try { return JSON.parse(readFileSync(path, 'utf8')) }
  catch (error) { throw new SetupError(`invalid or unreadable JSON: ${path}: ${(error as Error).message}`, 3) }
}

function realDirectory(path: string, label: string): string {
  const absolute = resolve(path)
  let st
  try { st = lstatSync(absolute) } catch { throw new SetupError(`${label} does not exist: ${absolute}`) }
  if (st.isSymbolicLink() || !st.isDirectory()) throw new SetupError(`${label} must be a real directory: ${absolute}`)
  try { return realpathSync(absolute) } catch { throw new SetupError(`${label} cannot be resolved: ${absolute}`) }
}

function prospectiveFile(path: string, label: string): string {
  const absolute = resolve(path)
  const parent = realDirectory(dirname(absolute), `${label} parent`)
  return join(parent, basename(absolute))
}

const normalizedKey = (value: string) => value.normalize('NFC').toLocaleLowerCase('en-US')
const pathWithin = (child: string, parent: string) => child === parent || (!relative(parent, child).startsWith(`..${sep}`) && relative(parent, child) !== '..' && !isAbsolute(relative(parent, child)))
const pathsOverlap = (a: string, b: string) => pathWithin(a, b) || pathWithin(b, a)

function currentUid(): number | undefined { return typeof process.getuid === 'function' ? process.getuid() : undefined }

function assertSupportedRuntime(forMutation: boolean): void {
  if (platform() !== 'darwin' && platform() !== 'linux') throw new SetupError('setup v1 supports local macOS/Linux filesystems only')
  if (forMutation && typeof process.geteuid === 'function' && process.geteuid() === 0) throw new SetupError('setup refuses to mutate as root/sudo')
}

function assertOwnedWritableDirectory(path: string, label: string): void {
  const st = lstatSync(path)
  const uid = currentUid()
  if (st.isSymbolicLink() || !st.isDirectory()) throw new SetupError(`${label} must be a real directory: ${path}`)
  if (uid !== undefined && st.uid !== uid) throw new SetupError(`${label} is not owned by the current user: ${path}`)
  try { accessSync(path, constants.R_OK | constants.W_OK | constants.X_OK) }
  catch { throw new SetupError(`${label} must be readable, writable, and searchable: ${path}`) }
}

function targetIdentity(targetInput: string, projectInput?: string): SetupTargetIdentity {
  assertSupportedRuntime(false)
  const root = realDirectory(targetInput, 'target root')
  const configDir = dirname(root)
  const rootName = basename(root)
  const configName = basename(configDir)
  if (rootName !== 'skills' || (configName !== '.codex' && configName !== '.claude')) {
    throw new SetupError('target root must be an exact .codex/skills or .claude/skills directory')
  }
  const scopeRoot = dirname(configDir)
  const userHome = realDirectory(homedir(), 'home directory')
  let scope: 'user' | 'project'
  let projectRoot: string | undefined
  if (scopeRoot === userHome) scope = 'user'
  else {
    const approvedProject = projectInput ? realDirectory(projectInput, 'project root') : realDirectory(process.cwd(), 'current working directory')
    if (scopeRoot !== approvedProject) throw new SetupError('project target must belong to the current directory or explicit --project-root')
    scope = 'project'
    projectRoot = approvedProject
  }
  const configStat = lstatSync(configDir)
  if (configStat.isSymbolicLink() || !configStat.isDirectory()) throw new SetupError(`harness config directory must be a real directory: ${configDir}`)
  const rootStat = lstatSync(root)
  const rootId = sha256(root).slice(0, 16)
  const adminRoot = join(configDir, '.skillmoo', 'setup', rootId)
  return { root, adminRoot, harness: configName === '.codex' ? 'codex' : 'claude', scope, ...(projectRoot ? { projectRoot } : {}), device: rootStat.dev }
}

function validateRecordedTarget(target: SetupTargetIdentity): SetupTargetIdentity {
  const actual = targetIdentity(target.root, target.projectRoot)
  if (canonicalJson(actual) !== canonicalJson(target)) throw new SetupError('target identity drifted since preview', 2)
  return actual
}

function safeMode(st: Stats, kind: 'directory' | 'file'): number {
  if (kind === 'directory') return 0o700
  return (st.mode & 0o111) !== 0 ? 0o700 : 0o600
}

interface ManifestResult { manifest: SetupManifest; skillMd: string; scannedText: string; allFiles: string[] }

export interface InspectedSetupSource {
  manifest: SetupManifest
  analysis: SetupAnalysisSummary
}

function manifestDirectory(root: string, normalizeModes: boolean): ManifestResult {
  const rootReal = realDirectory(root, 'Skill directory')
  const rootStat = lstatSync(rootReal)
  const entries: SetupManifestEntry[] = []
  const allFiles: string[] = []
  const uninterpretedFiles: string[] = []
  const scanned: string[] = []
  let scannedBytes = 0
  let files = 0
  let totalBytes = 0

  const walk = (dir: string, depth: number): void => {
    if (depth > MAX_DEPTH) throw new SetupError(`Skill tree exceeds depth ${MAX_DEPTH}: ${rootReal}`)
    let names: string[]
    try { names = readdirSync(dir).sort((a, b) => a.localeCompare(b, 'en')) }
    catch { throw new SetupError(`Skill directory is unreadable: ${dir}`) }
    for (const rawName of names) {
      if (rawName === '.git' || rawName === '.skillmoo') throw new SetupError(`reserved metadata is not installable: ${join(dir, rawName)}`)
      if (MANAGER_MARKERS.has(rawName)) throw new SetupError(`external manager marker requires manual handling: ${join(dir, rawName)}`)
      if (Buffer.byteLength(rawName) > MAX_COMPONENT_BYTES) throw new SetupError(`path component exceeds ${MAX_COMPONENT_BYTES} bytes: ${rawName}`)
      const path = join(dir, rawName)
      const rel = relative(rootReal, path).split(sep).join('/')
      if (!rel || rel.startsWith('../') || isAbsolute(rel)) throw new SetupError(`path escapes Skill root: ${path}`)
      if (Buffer.byteLength(rel) > MAX_RELATIVE_BYTES) throw new SetupError(`relative path exceeds ${MAX_RELATIVE_BYTES} bytes: ${rel}`)
      let st
      try { st = lstatSync(path) } catch { throw new SetupError(`Skill entry cannot be inspected: ${path}`) }
      if (st.isSymbolicLink()) throw new SetupError(`symbolic links are not installable: ${rel}`)
      if (st.isDirectory()) {
        entries.push({ path: rel, kind: 'directory', mode: normalizeModes ? 0o700 : st.mode & 0o777 })
        walk(path, depth + 1)
        continue
      }
      if (!st.isFile()) throw new SetupError(`non-regular entry is not installable: ${rel}`)
      if (st.nlink > 1) throw new SetupError(`multiply linked file is not installable: ${rel}`)
      if (st.size > 0 && typeof st.blocks === 'number' && st.blocks === 0) throw new SetupError(`sparse file is not installable: ${rel}`)
      if (st.size > MAX_FILE_BYTES) throw new SetupError(`file exceeds ${MAX_FILE_BYTES} bytes: ${rel}`)
      if (++files > MAX_FILES) throw new SetupError(`Skill exceeds ${MAX_FILES} files`)
      totalBytes += st.size
      if (totalBytes > MAX_TOTAL_BYTES) throw new SetupError(`Skill exceeds ${MAX_TOTAL_BYTES} total bytes`)
      let bytes: Buffer
      try { bytes = readFileSync(path) } catch { throw new SetupError(`Skill file is unreadable: ${rel}`) }
      const mode = normalizeModes ? safeMode(st, 'file') : st.mode & 0o777
      if ((st.mode & 0o111) !== 0 && !SCRIPT_EXT.test(rawName)) throw new SetupError(`unsupported executable file: ${rel}`)
      if (rel === 'SKILL.md' && bytes.length > MAX_SCANNED_BYTES) throw new SetupError(`SKILL.md exceeds ${MAX_SCANNED_BYTES} analyzed bytes`)
      entries.push({ path: rel, kind: 'file', mode, size: bytes.length, sha256: sha256(bytes) })
      allFiles.push(rel)
      if (rel !== 'SKILL.md' && (SCRIPT_EXT.test(rawName) || TEXT_EXT.test(rawName))) {
        if (bytes.includes(0)) throw new SetupError(`declared text/script file contains binary data: ${rel}`)
        const chunk = `\n--- ${rel} ---\n${bytes.toString('utf8')}`
        scannedBytes += Buffer.byteLength(chunk)
        if (scannedBytes > MAX_SCANNED_BYTES) throw new SetupError(`eligible text/script content exceeds ${MAX_SCANNED_BYTES} analyzed bytes`)
        scanned.push(chunk)
      } else if (rel !== 'SKILL.md') uninterpretedFiles.push(rel)
    }
  }
  walk(rootReal, 0)
  const skillEntry = entries.find((entry) => entry.path === 'SKILL.md')
  if (!skillEntry || skillEntry.kind !== 'file') throw new SetupError(`top-level regular SKILL.md is required: ${rootReal}`)
  const skillMd = readFileSync(join(rootReal, 'SKILL.md'), 'utf8')
  const manifestCore = { rootMode: normalizeModes ? 0o700 : rootStat.mode & 0o777, entries, files, totalBytes, uninterpretedFiles }
  return { manifest: { bundleSha256: digestObject(manifestCore), ...manifestCore }, skillMd, scannedText: scanned.join('\n'), allFiles }
}

function analyzeInstallable(result: ManifestResult, expectedName: string): SetupAnalysisSummary {
  const analysis = analyzeSkill(result.skillMd, { bundleText: result.scannedText, bundleFiles: result.allFiles })
  const declared = analysis.frontmatter.name?.normalize('NFC')
  if (!declared || declared !== expectedName) throw new SetupError(`frontmatter name must exactly match source directory basename: expected ${expectedName}`)
  if (!['A', 'B'].includes(analysis.overall.grade) || analysis.overall.gate !== 'pass' || analysis.risk.level !== 'low') {
    throw new SetupError(`Skill ${expectedName} is not installable: requires A/B + PASS + low risk; got ${analysis.overall.grade}/${analysis.overall.gate}/${analysis.risk.level}`)
  }
  return {
    grade: analysis.overall.grade,
    gate: analysis.overall.gate,
    risk: analysis.risk.level,
    rubricVersion: RUBRIC_VERSION,
    vector: analysis.vector.string,
    uninterpretedFiles: result.manifest.uninterpretedFiles.length,
  }
}

/** The single complete-package gate shared by local setup and Catalog v2 generation. */
export function inspectSetupSource(sourceDir: string): InspectedSetupSource {
  const root = realDirectory(sourceDir, 'Skill directory')
  const name = basename(root).normalize('NFC')
  assertSafeDestinationName(name)
  const result = manifestDirectory(root, true)
  return { manifest: result.manifest, analysis: analyzeInstallable(result, name) }
}

function manifestEquals(a: SetupManifest | null, b: SetupManifest | null): boolean {
  return a === null ? b === null : b !== null && a.bundleSha256 === b.bundleSha256 && canonicalJson(a) === canonicalJson(b)
}

function snapshotDestination(path: string): SetupManifest | null {
  if (!existsSync(path)) return null
  const st = lstatSync(path)
  if (st.isSymbolicLink() || !st.isDirectory()) throw new SetupError(`destination is not a replaceable real Skill directory: ${path}`)
  if (!existsSync(join(path, 'SKILL.md'))) throw new SetupError(`existing destination is not a Skill directory: ${path}`)
  return manifestDirectory(path, false).manifest
}

function validatePlanShape(raw: unknown): SetupPlan {
  if (!raw || typeof raw !== 'object') throw new SetupError('setup plan must be an object', 1)
  const plan = raw as SetupPlan
  if (plan.protocolVersion !== SETUP_PROTOCOL_VERSION || plan.installerVersion !== SETUP_INSTALLER_VERSION || !Array.isArray(plan.actions) || !plan.actions.length || typeof plan.planId !== 'string') {
    throw new SetupError('unsupported or malformed setup plan', 1)
  }
  const expected = digestObject(without(plan, 'planId'))
  if (expected !== plan.planId) throw new SetupError('setup plan integrity check failed', 2)
  return plan
}

function assertSafeDestinationName(name: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/.test(name) || RESERVED_NAMES.has(normalizedKey(name))) throw new SetupError(`unsafe or reserved Skill destination name: ${name}`)
}

function validatePlanSemantics(plan: SetupPlan): void {
  const target = validateRecordedTarget(plan.target)
  const names = new Set<string>()
  for (let index = 0; index < plan.actions.length; index++) {
    const action = plan.actions[index]!
    assertSafeDestinationName(action.name)
    const key = normalizedKey(action.name)
    if (names.has(key)) throw new SetupError(`duplicate/case-folded plan destination: ${action.name}`, 2)
    names.add(key)
    if (action.index !== index || action.targetDir !== join(target.root, action.name)) throw new SetupError(`plan action target is outside its approved root: ${action.name}`, 2)
    if ((action.action === 'add') !== (action.before === null)) throw new SetupError(`plan action/before-state mismatch: ${action.name}`, 2)
    validateActiveOwnerValue(action.beforeOwner, target, action.name, action.before, 'plan')
    if (pathsOverlap(action.sourceDir, target.root) || pathsOverlap(action.sourceDir, target.adminRoot)) throw new SetupError(`plan source overlaps target/admin state: ${action.sourceDir}`, 2)
  }
}

function readPlan(path: string): SetupPlan {
  const resolved = resolve(path)
  let raw: unknown
  try {
    raw = JSON.parse(readFileSync(resolved, 'utf8'))
  } catch {
    throw new SetupError(`setup plan is missing or unreadable: ${resolved}`, 1)
  }
  return validatePlanShape(raw)
}

export function prepareSetup(options: PrepareSetupOptions): SetupPlan {
  assertSupportedRuntime(false)
  if (!options.sourceDirs.length) throw new SetupError('prepare requires at least one --source directory')
  const target = targetIdentity(options.targetRoot, options.projectRoot)
  const planPath = prospectiveFile(options.planPath, 'plan')
  if (existsSync(planPath)) throw new SetupError(`plan path already exists: ${planPath}`)
  const sources = options.sourceDirs.map((source) => realDirectory(source, 'source directory'))
  const sourceKeys = new Set<string>()
  const actions: SetupPlanAction[] = []
  const existingNames = new Map<string, string>()
  for (const name of readdirSync(target.root)) existingNames.set(normalizedKey(name), name)
  for (let index = 0; index < sources.length; index++) {
    const sourceDir = sources[index]!
    const name = basename(sourceDir).normalize('NFC')
    assertSafeDestinationName(name)
    const key = normalizedKey(name)
    if (sourceKeys.has(key)) throw new SetupError(`duplicate/case-folded destination: ${name}`)
    sourceKeys.add(key)
    const caseExisting = existingNames.get(key)
    if (caseExisting && caseExisting !== name) throw new SetupError(`destination collides by case/Unicode normalization: ${name} vs ${caseExisting}`)
    const targetDir = join(target.root, name)
    if (pathsOverlap(sourceDir, target.root) || pathsOverlap(sourceDir, target.adminRoot) || pathsOverlap(sourceDir, targetDir)) throw new SetupError(`source overlaps target or admin state: ${sourceDir}`)
    for (const other of sources.slice(0, index)) if (pathsOverlap(sourceDir, other)) throw new SetupError(`source directories overlap: ${sourceDir} and ${other}`)
    const inspected = inspectSetupSource(sourceDir)
    const before = snapshotDestination(targetDir)
    const beforeOwner = readActiveOwner(target, name)
    actions.push({ index, name, action: before ? 'replace' : 'add', sourceDir, targetDir, source: inspected.manifest, before, beforeOwner, analysis: inspected.analysis })
  }
  for (const source of sources) if (pathWithin(planPath, source)) throw new SetupError('plan path must be outside every source directory')
  if (pathWithin(planPath, dirname(target.root)) || pathWithin(planPath, target.adminRoot)) throw new SetupError('plan path must be outside target, harness config, and admin trees')
  const draft: Omit<SetupPlan, 'planId'> = {
    protocolVersion: SETUP_PROTOCOL_VERSION,
    installerVersion: SETUP_INSTALLER_VERSION,
    createdAt: new Date().toISOString(),
    target,
    actions,
    limitations: [
      'Local self-attested static inspection; installation is not runtime efficacy.',
      'Binary and unsupported assets are byte-manifested but not semantically interpreted.',
      'Replace and multi-Skill commits are crash recoverable, not instantaneously atomic.',
    ],
  }
  const plan: SetupPlan = { ...draft, planId: digestObject(draft) }
  writePrivateJsonNew(planPath, plan)
  return plan
}

function ensurePrivateDirectory(path: string): void {
  if (!existsSync(path)) mkdirSync(path, { mode: 0o700 })
  const st = lstatSync(path)
  const uid = currentUid()
  if (st.isSymbolicLink() || !st.isDirectory()) throw new SetupError(`private state path must be a real directory: ${path}`, 3)
  if (uid !== undefined && st.uid !== uid) throw new SetupError(`private state is not owned by current user: ${path}`, 3)
  if ((st.mode & 0o077) !== 0) throw new SetupError(`private state permissions are too broad (require 0700): ${path}`, 3)
}

function ensureAdmin(target: SetupTargetIdentity): void {
  assertOwnedWritableDirectory(target.root, 'target root')
  const configDir = dirname(target.root)
  assertOwnedWritableDirectory(configDir, 'harness config directory')
  const state = join(configDir, '.skillmoo')
  const setup = join(state, 'setup')
  ensurePrivateDirectory(state)
  ensurePrivateDirectory(setup)
  ensurePrivateDirectory(target.adminRoot)
  ensurePrivateDirectory(join(target.adminRoot, 'transactions'))
  ensurePrivateDirectory(join(target.adminRoot, 'receipts'))
  ensurePrivateDirectory(join(target.adminRoot, 'active'))
  if (lstatSync(target.adminRoot).dev !== lstatSync(target.root).dev) throw new SetupError('admin state and target root must be on the same device')
}

const activeOwnerPath = (target: SetupTargetIdentity, name: string) => join(target.adminRoot, 'active', `${sha256(normalizedKey(name)).slice(0, 24)}.json`)

function readActiveOwner(target: SetupTargetIdentity, name: string): ActiveOwner | null {
  const path = activeOwnerPath(target, name)
  if (!existsSync(path)) return null
  const st = lstatSync(path)
  if (st.isSymbolicLink() || !st.isFile() || (st.mode & 0o077) !== 0) throw new SetupError(`active setup ownership marker is unsafe: ${path}`, 3)
  const raw = readJson(path) as ActiveOwner
  if (!raw || raw.protocolVersion !== SETUP_PROTOCOL_VERSION || raw.name !== name || raw.targetDir !== join(target.root, name) || !/^[0-9a-f-]{36}$/i.test(raw.transactionId) || !/^[0-9a-f]{64}$/i.test(raw.bundleSha256)) throw new SetupError(`active setup ownership marker is malformed: ${path}`, 3)
  if (raw.integritySha256 !== digestObject(without(raw, 'integritySha256'))) throw new SetupError(`active setup ownership marker integrity failed: ${path}`, 3)
  return raw
}

function validateActiveOwnerValue(owner: ActiveOwner | null, target: SetupTargetIdentity, name: string, before: SetupManifest | null, label: string): void {
  if (!owner) return
  if (owner.protocolVersion !== SETUP_PROTOCOL_VERSION || owner.name !== name || owner.targetDir !== join(target.root, name) || !/^[0-9a-f-]{36}$/i.test(owner.transactionId) || owner.bundleSha256 !== before?.bundleSha256 || owner.integritySha256 !== digestObject(without(owner, 'integritySha256'))) {
    throw new SetupError(`${label} ownership generation is malformed: ${name}`, 3)
  }
}

function ownerEquals(a: ActiveOwner | null, b: ActiveOwner | null): boolean { return canonicalJson(a) === canonicalJson(b) }

function writeActiveOwner(target: SetupTargetIdentity, owner: Omit<ActiveOwner, 'integritySha256'>): void {
  const marker: ActiveOwner = { ...owner, integritySha256: digestObject(owner) }
  writeDurableJson(activeOwnerPath(target, owner.name), marker)
}

function restoreActiveOwner(target: SetupTargetIdentity, action: JournalAction): void {
  const path = activeOwnerPath(target, action.name)
  const current = readActiveOwner(target, action.name)
  const currentIsExpectedAfter = current?.transactionId === action.ownedAfterTransactionId && current.bundleSha256 === action.source.bundleSha256
  if (current && !currentIsExpectedAfter && !ownerEquals(current, action.beforeOwner)) throw new SetupError(`active ownership changed during recovery: ${action.name}`, 3)
  if (action.beforeOwner) {
    writeDurableJson(path, action.beforeOwner)
    return
  }
  if (!existsSync(path)) return
  const destination = join(dirname(action.quarantineDir), `active-${action.name}-${Date.now()}.json`)
  if (existsSync(destination)) throw new SetupError(`active marker quarantine already exists: ${destination}`, 3)
  renameSync(path, destination)
  fsyncDirectory(dirname(path))
  fsyncDirectory(dirname(destination))
}

const journalPath = (target: SetupTargetIdentity, transactionId: string) => join(target.adminRoot, 'transactions', transactionId, 'journal.json')

function updateJournal(path: string, journal: SetupJournal, state: string, error?: string): void {
  journal.state = state
  journal.updatedAt = new Date().toISOString()
  if (error) journal.error = error.slice(0, 500)
  journal.integritySha256 = digestObject(without(journal, 'integritySha256'))
  writeDurableJson(path, journal)
}

function readJournal(path: string): SetupJournal {
  const raw = readJson(path) as SetupJournal
  if (!raw || raw.protocolVersion !== SETUP_PROTOCOL_VERSION || raw.installerVersion !== SETUP_INSTALLER_VERSION || typeof raw.transactionId !== 'string' || !Array.isArray(raw.actions)) {
    throw new SetupError(`unsupported or malformed transaction journal: ${path}`, 3)
  }
  if (!/^[0-9a-f-]{36}$/i.test(raw.transactionId) || raw.integritySha256 !== digestObject(without(raw, 'integritySha256'))) throw new SetupError(`transaction journal integrity check failed: ${path}`, 3)
  const target = validateRecordedTarget(raw.target)
  if (resolve(path) !== journalPath(target, raw.transactionId)) throw new SetupError(`journal path does not match its transaction identity: ${path}`, 3)
  const txRoot = join(target.adminRoot, 'transactions', raw.transactionId)
  for (let index = 0; index < raw.actions.length; index++) {
    const action = raw.actions[index]!
    assertSafeDestinationName(action.name)
    if (action.index !== index || action.targetDir !== join(target.root, action.name)) throw new SetupError(`journal action target escapes approved root: ${action.name}`, 3)
    if (!/^[0-9a-f-]{36}$/i.test(action.ownedAfterTransactionId)) throw new SetupError(`journal ownership generation is malformed: ${action.name}`, 3)
    validateActiveOwnerValue(action.beforeOwner, target, action.name, action.before, 'journal')
    if (action.stageDir !== join(txRoot, 'stage', action.name) || action.quarantineDir !== join(txRoot, 'quarantine', action.name)) throw new SetupError(`journal private path escapes its transaction: ${action.name}`, 3)
    const transactionsRoot = join(target.adminRoot, 'transactions')
    if (!pathWithin(action.backupDir, transactionsRoot) || basename(action.backupDir) !== action.name || basename(dirname(action.backupDir)) !== 'backup') throw new SetupError(`journal backup path escapes private state: ${action.name}`, 3)
  }
  return raw
}

function readLock(target: SetupTargetIdentity): SetupStatus['lock'] {
  const path = join(target.adminRoot, 'lock')
  if (!existsSync(path)) return null
  const raw = readJson(path) as SetupStatus['lock']
  if (!raw || typeof raw.transactionId !== 'string' || typeof raw.pid !== 'number' || typeof raw.startedAt !== 'string') throw new SetupError(`invalid setup lock: ${path}`, 3)
  return raw
}

function acquireLock(target: SetupTargetIdentity, transactionId: string): void {
  const path = join(target.adminRoot, 'lock')
  try { writePrivateJsonNew(path, { transactionId, pid: process.pid, startedAt: new Date().toISOString() }) }
  catch (error) {
    if (existsSync(path)) throw new SetupError(`target root is locked by another SkillMOO transaction: ${readLock(target)?.transactionId ?? 'unknown'}`, 2)
    throw error
  }
}

function releaseLock(target: SetupTargetIdentity, transactionId: string): void {
  const path = join(target.adminRoot, 'lock')
  if (!existsSync(path)) return
  const lock = readLock(target)
  if (lock?.transactionId !== transactionId) throw new SetupError('refusing to remove a lock owned by another transaction', 3)
  unlinkSync(path)
  fsyncDirectory(dirname(path))
}

function releaseOwnLock(target: SetupTargetIdentity, transactionId: string): void {
  const lock = readLock(target)
  if (lock?.transactionId === transactionId) releaseLock(target, transactionId)
}

const terminalJournal = (state: string) => ['committed', 'rolled-back', 'already-rolled-back'].includes(state)

export function readSetupStatus(targetRoot: string): SetupStatus {
  assertSupportedRuntime(false)
  const root = realDirectory(targetRoot, 'target root')
  const configDir = dirname(root)
  if (basename(root) !== 'skills' || !['.codex', '.claude'].includes(basename(configDir))) throw new SetupError('status target must be a .codex/skills or .claude/skills root')
  const adminRoot = join(configDir, '.skillmoo', 'setup', sha256(root).slice(0, 16))
  if (!existsSync(adminRoot)) return { targetRoot: root, adminRoot, lock: null, pending: [], receipts: 0 }
  const target: SetupTargetIdentity = { root, adminRoot, harness: basename(configDir) === '.codex' ? 'codex' : 'claude', scope: 'project', device: lstatSync(root).dev }
  const transactions = join(adminRoot, 'transactions')
  const pending: SetupStatus['pending'] = []
  if (existsSync(transactions)) for (const id of readdirSync(transactions).sort()) {
    const path = join(transactions, id, 'journal.json')
    if (!existsSync(path)) throw new SetupError(`transaction is missing its journal: ${join(transactions, id)}`, 3)
    const journal = readJournal(path)
    if (!terminalJournal(journal.state)) pending.push({ transactionId: journal.transactionId, kind: journal.kind, state: journal.state, updatedAt: journal.updatedAt })
  }
  const receipts = join(adminRoot, 'receipts')
  const lock = readLock(target)
  if (lock && !pending.some((item) => item.transactionId === lock.transactionId)) {
    const lockedJournal = join(transactions, lock.transactionId, 'journal.json')
    if (!existsSync(lockedJournal)) throw new SetupError(`lock has no durable transaction journal: ${lock.transactionId}`, 3)
    const journal = readJournal(lockedJournal)
    pending.push({ transactionId: journal.transactionId, kind: journal.kind, state: `${journal.state}:lock-held`, updatedAt: journal.updatedAt })
  }
  return { targetRoot: root, adminRoot, lock, pending, receipts: existsSync(receipts) ? readdirSync(receipts).filter((name) => name.endsWith('.json')).length : 0 }
}

function assertNoPending(target: SetupTargetIdentity): void {
  if (!existsSync(target.adminRoot)) return
  const status = readSetupStatus(target.root)
  if (status.pending.length || status.lock) throw new SetupError(`target has an incomplete transaction; run setup status/recover first`, 3)
}

function assertNoOtherPending(target: SetupTargetIdentity, transactionId: string): void {
  const status = readSetupStatus(target.root)
  const others = status.pending.filter((item) => item.transactionId !== transactionId)
  if (others.length) throw new SetupError(`another incomplete transaction must be recovered first: ${others[0]!.transactionId}`, 3)
}

function assertCapacity(target: SetupTargetIdentity, bytes: number): void {
  const stats = statfsSync(target.root)
  const available = Number(stats.bavail) * Number(stats.bsize)
  if (!Number.isFinite(available) || available < bytes + JOURNAL_MARGIN_BYTES) throw new SetupError(`insufficient target filesystem capacity for staging (${bytes + JOURNAL_MARGIN_BYTES} bytes required)`)
}

function copyManifestTree(sourceRoot: string, targetRoot: string, manifest: SetupManifest): void {
  mkdirSync(targetRoot, { mode: 0o700 })
  chmodSync(targetRoot, 0o700)
  for (const entry of manifest.entries.filter((item) => item.kind === 'directory')) {
    const path = join(targetRoot, ...entry.path.split('/'))
    mkdirSync(path, { recursive: true, mode: 0o700 })
    chmodSync(path, 0o700)
  }
  for (const entry of manifest.entries.filter((item) => item.kind === 'file')) {
    const source = join(sourceRoot, ...entry.path.split('/'))
    const target = join(targetRoot, ...entry.path.split('/'))
    copyFileSync(source, target, constants.COPYFILE_EXCL)
    chmodSync(target, entry.mode)
    const fd = openSync(target, constants.O_RDONLY)
    try { fsyncSync(fd) } finally { closeSync(fd) }
  }
  fsyncDirectory(targetRoot)
}

function maybeFault(options: ApplySetupOptions, point: string): void {
  if (options.testCrashAt === point) throw new SetupCrashSimulation(point)
  if (options.testFailAt === point) throw new SetupError(`injected setup failure at ${point}`)
}

function currentManifest(path: string): SetupManifest | null {
  return existsSync(path) ? manifestDirectory(path, false).manifest : null
}

function moveKnownTargetToQuarantine(action: JournalAction, suffix = ''): void {
  const current = currentManifest(action.targetDir)
  if (!current) return
  if (!manifestEquals(current, action.source)) throw new SetupError(`target contains unexpected post-plan changes: ${action.targetDir}`, 3)
  const quarantine = `${action.quarantineDir}${suffix}`
  if (existsSync(quarantine)) throw new SetupError(`quarantine destination already exists: ${quarantine}`, 3)
  renameSync(action.targetDir, quarantine)
  fsyncDirectory(dirname(action.targetDir))
  fsyncDirectory(dirname(quarantine))
}

function restoreBefore(journal: SetupJournal, path: string): void {
  updateJournal(path, journal, 'compensating')
  try {
    for (const action of [...journal.actions].reverse()) {
      const current = currentManifest(action.targetDir)
      if (current && manifestEquals(current, action.before)) {
        restoreActiveOwner(journal.target, action)
        action.status = 'restored'
        updateJournal(path, journal, `compensating:${action.index}`)
        continue
      }
      if (current) moveKnownTargetToQuarantine(action, `-${Date.now()}`)
      if (action.before) {
        if (!existsSync(action.backupDir)) throw new SetupError(`required backup is missing: ${action.backupDir}`, 3)
        let backup: SetupManifest
        try { backup = manifestDirectory(action.backupDir, false).manifest }
        catch (error) { throw new SetupError(`required backup is unreadable or damaged: ${action.backupDir}: ${(error as Error).message}`, 3) }
        if (!manifestEquals(backup, action.before)) throw new SetupError(`required backup is damaged: ${action.backupDir}`, 3)
        if (existsSync(action.targetDir)) throw new SetupError(`target unexpectedly reappeared during recovery: ${action.targetDir}`, 3)
        renameSync(action.backupDir, action.targetDir)
        fsyncDirectory(dirname(action.targetDir))
        fsyncDirectory(dirname(action.backupDir))
      }
      restoreActiveOwner(journal.target, action)
      action.status = 'restored'
      updateJournal(path, journal, `compensating:${action.index}`)
    }
    updateJournal(path, journal, 'rolled-back')
  } catch (error) {
    updateJournal(path, journal, 'needs-attention', (error as Error).message)
    if (error instanceof SetupError) throw error
    throw new SetupError(`recovery needs manual attention: ${(error as Error).message}`, 3)
  }
}

function quarantineReceiptsForTransaction(target: SetupTargetIdentity, transactionId: string, quarantineRoot: string): void {
  const receipts = join(target.adminRoot, 'receipts')
  if (!existsSync(receipts)) return
  for (const name of readdirSync(receipts)) {
    const path = join(receipts, name)
    try {
      const receipt = readSetupReceipt(path)
      if (receipt.transactionId === transactionId) {
        const destination = join(quarantineRoot, `invalid-${name}`)
        if (existsSync(destination)) throw new SetupError(`receipt quarantine already exists: ${destination}`, 3)
        renameSync(path, destination)
        fsyncDirectory(receipts)
        fsyncDirectory(quarantineRoot)
      }
    } catch (error) {
      if (error instanceof SetupError && error.message.startsWith('receipt quarantine')) throw error
      // An independently malformed receipt is left untouched for manual inspection.
    }
  }
}

function receiptDraft(plan: SetupPlan, journal: SetupJournal): SetupReceipt {
  const draft: Omit<SetupReceipt, 'receiptId'> = {
    protocolVersion: SETUP_PROTOCOL_VERSION,
    installerVersion: SETUP_INSTALLER_VERSION,
    transactionId: journal.transactionId,
    planId: plan.planId,
    completedAt: new Date().toISOString(),
    target: plan.target,
    actions: journal.actions.map((action): SetupReceiptAction => ({
      index: action.index,
      name: action.name,
      action: action.action,
      targetDir: action.targetDir,
      before: action.before,
      after: action.source,
      beforeOwner: action.beforeOwner,
      analysis: action.analysis,
      backupDir: action.backupDir,
    })),
    evidence: { status: 'inspected' as const, attestation: 'local-self-attested' as const, rubricVersion: RUBRIC_VERSION },
    limitations: plan.limitations,
  }
  return { ...draft, receiptId: `sr_${digestObject(draft).slice(0, 24)}` }
}

export function applySetup(options: ApplySetupOptions): string {
  assertSupportedRuntime(true)
  const plan = readPlan(options.planPath)
  if (options.confirm !== plan.planId) throw new SetupError(`confirmation must exactly match plan ID ${plan.planId}`, 2)
  validatePlanSemantics(plan)
  const target = validateRecordedTarget(plan.target)
  assertOwnedWritableDirectory(target.root, 'target root')
  assertNoPending(target)
  for (const action of plan.actions) {
    const source = manifestDirectory(action.sourceDir, true)
    const analysis = analyzeInstallable(source, action.name)
    if (canonicalJson(analysis) !== canonicalJson(action.analysis)) throw new SetupError(`static analysis drifted after preview: ${action.sourceDir}`, 2)
    if (!manifestEquals(source.manifest, action.source)) throw new SetupError(`source drifted after preview: ${action.sourceDir}`, 2)
    const before = snapshotDestination(action.targetDir)
    if (!manifestEquals(before, action.before)) throw new SetupError(`target drifted after preview: ${action.targetDir}`, 2)
    if (!ownerEquals(readActiveOwner(target, action.name), action.beforeOwner)) throw new SetupError(`target ownership generation drifted after preview: ${action.targetDir}`, 2)
  }
  assertCapacity(target, plan.actions.reduce((sum, action) => sum + action.source.totalBytes, 0))
  ensureAdmin(target)
  const transactionId = randomUUID()
  const txRoot = join(target.adminRoot, 'transactions', transactionId)
  ensurePrivateDirectory(txRoot)
  ensurePrivateDirectory(join(txRoot, 'stage'))
  ensurePrivateDirectory(join(txRoot, 'backup'))
  ensurePrivateDirectory(join(txRoot, 'quarantine'))
  const actions: JournalAction[] = plan.actions.map((action) => ({
    ...action,
    stageDir: join(txRoot, 'stage', action.name),
    backupDir: join(txRoot, 'backup', action.name),
    quarantineDir: join(txRoot, 'quarantine', action.name),
    ownedAfterTransactionId: transactionId,
    status: 'pending',
  }))
  const journal: SetupJournal = {
    protocolVersion: SETUP_PROTOCOL_VERSION,
    installerVersion: SETUP_INSTALLER_VERSION,
    transactionId,
    kind: 'apply',
    planId: plan.planId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    state: 'planned',
    target,
    actions,
    integritySha256: '',
  }
  const jPath = journalPath(target, transactionId)
  journal.integritySha256 = digestObject(without(journal, 'integritySha256'))
  writePrivateJsonNew(jPath, journal)
  maybeFault(options, 'after-initial-journal')
  let lockAcquired = false
  try {
    acquireLock(target, transactionId)
    lockAcquired = true
    assertNoOtherPending(target, transactionId)
    updateJournal(jPath, journal, 'staging')
    for (const action of actions) {
      copyManifestTree(action.sourceDir, action.stageDir, action.source)
      const staged = manifestDirectory(action.stageDir, false)
      analyzeInstallable(staged, action.name)
      if (!manifestEquals(staged.manifest, action.source)) throw new SetupError(`staged content does not match frozen source: ${action.name}`, 3)
    }
    updateJournal(jPath, journal, 'prepared')
    for (const action of actions) {
      const immediatelyBefore = snapshotDestination(action.targetDir)
      if (!manifestEquals(immediatelyBefore, action.before)) throw new SetupError(`target changed immediately before commit: ${action.targetDir}`, 2)
      if (!ownerEquals(readActiveOwner(target, action.name), action.beforeOwner)) throw new SetupError(`target ownership changed immediately before commit: ${action.targetDir}`, 2)
      if (action.before) {
        updateJournal(jPath, journal, `backing-up:${action.index}`)
        renameSync(action.targetDir, action.backupDir)
        fsyncDirectory(dirname(action.targetDir))
        fsyncDirectory(dirname(action.backupDir))
        action.status = 'old-moved'
        updateJournal(jPath, journal, `old-moved:${action.index}`)
        maybeFault(options, `after-old-moved:${action.index}`)
      }
      updateJournal(jPath, journal, `activating:${action.index}`)
      if (existsSync(action.targetDir)) throw new SetupError(`destination unexpectedly exists during activation: ${action.targetDir}`, 3)
      renameSync(action.stageDir, action.targetDir)
      fsyncDirectory(dirname(action.targetDir))
      fsyncDirectory(dirname(action.stageDir))
      action.status = 'new-visible'
      updateJournal(jPath, journal, `new-visible:${action.index}`)
      writeActiveOwner(target, { protocolVersion: SETUP_PROTOCOL_VERSION, name: action.name, targetDir: action.targetDir, transactionId, bundleSha256: action.source.bundleSha256 })
      maybeFault(options, `after-new-visible:${action.index}`)
    }
    updateJournal(jPath, journal, 'validating')
    for (const action of actions) {
      const after = currentManifest(action.targetDir)
      if (!manifestEquals(after, action.source)) throw new SetupError(`installed target failed digest validation: ${action.targetDir}`, 3)
    }
    const receipt = receiptDraft(plan, journal)
    const pendingReceipt = join(txRoot, 'receipt.json')
    writePrivateJsonNew(pendingReceipt, receipt)
    updateJournal(jPath, journal, 'receipt-prepared')
    const receiptPath = join(target.adminRoot, 'receipts', `${receipt.receiptId}.json`)
    renameSync(pendingReceipt, receiptPath)
    fsyncDirectory(dirname(pendingReceipt))
    fsyncDirectory(dirname(receiptPath))
    maybeFault(options, 'after-receipt-visible')
    updateJournal(jPath, journal, 'committed')
    maybeFault(options, 'after-committed')
    releaseLock(target, transactionId)
    return receiptPath
  } catch (error) {
    if (error instanceof SetupCrashSimulation) throw error
    if (!lockAcquired) {
      updateJournal(jPath, journal, 'rolled-back', (error as Error).message)
      if (error instanceof SetupError) throw error
      throw new SetupError(`setup failed before lock acquisition: ${(error as Error).message}`)
    }
    try {
      restoreBefore(journal, jPath)
      quarantineReceiptsForTransaction(target, transactionId, join(txRoot, 'quarantine'))
      releaseOwnLock(target, transactionId)
    } catch (recoveryError) {
      if (recoveryError instanceof SetupError) throw recoveryError
      throw new SetupError(`setup failed and compensation needs attention: ${(recoveryError as Error).message}`, 3)
    }
    if (error instanceof SetupError) throw error
    throw new SetupError(`setup failed: ${(error as Error).message}`)
  }
}

export function readSetupReceipt(path: string): SetupReceipt {
  const resolvedPath = resolve(path)
  const receiptStat = lstatSync(resolvedPath)
  if (receiptStat.isSymbolicLink() || !receiptStat.isFile()) throw new SetupError(`setup receipt must be a real regular file: ${path}`, 3)
  const raw = readJson(resolvedPath) as SetupReceipt
  if (!raw || raw.protocolVersion !== SETUP_PROTOCOL_VERSION || raw.installerVersion !== SETUP_INSTALLER_VERSION || typeof raw.receiptId !== 'string' || !Array.isArray(raw.actions)) throw new SetupError(`unsupported or malformed setup receipt: ${path}`, 3)
  const expected = `sr_${digestObject(without(raw, 'receiptId')).slice(0, 24)}`
  if (expected !== raw.receiptId) throw new SetupError(`setup receipt integrity check failed: ${path}`, 3)
  if (!/^[0-9a-f-]{36}$/i.test(raw.transactionId) || !/^[0-9a-f]{64}$/i.test(raw.planId)) throw new SetupError(`setup receipt identities are malformed: ${path}`, 3)
  const target = validateRecordedTarget(raw.target)
  const managedPath = join(target.adminRoot, 'receipts', `${raw.receiptId}.json`)
  if (resolvedPath !== managedPath) throw new SetupError(`setup receipt must be the managed original: ${managedPath}`, 3)
  const expectedBackupRoot = join(target.adminRoot, 'transactions', raw.transactionId, 'backup')
  for (let index = 0; index < raw.actions.length; index++) {
    const action = raw.actions[index]!
    assertSafeDestinationName(action.name)
    if (action.index !== index || action.targetDir !== join(target.root, action.name) || action.backupDir !== join(expectedBackupRoot, action.name)) throw new SetupError(`setup receipt action escapes approved state: ${action.name}`, 3)
    validateActiveOwnerValue(action.beforeOwner, target, action.name, action.before, 'receipt')
  }
  return raw
}

export function rollbackSetup(options: { receiptPath: string; confirm: string }): { transactionId: string; state: 'rolled-back' | 'already-rolled-back' } {
  assertSupportedRuntime(true)
  const receipt = readSetupReceipt(options.receiptPath)
  if (options.confirm !== receipt.receiptId) throw new SetupError(`confirmation must exactly match receipt ID ${receipt.receiptId}`, 2)
  const target = validateRecordedTarget(receipt.target)
  assertNoPending(target)
  let allBefore = true
  for (const action of receipt.actions) {
    const current = currentManifest(action.targetDir)
    const owner = readActiveOwner(target, action.name)
    const ownedByReceipt = owner?.transactionId === receipt.transactionId && owner.bundleSha256 === action.after.bundleSha256
    if (!ownedByReceipt) {
      if (manifestEquals(current, action.before) && ownerEquals(owner, action.beforeOwner)) continue
      if (manifestEquals(current, action.after)) throw new SetupError(`rollback refused because a newer setup generation owns the target: ${action.targetDir}`, 2)
      throw new SetupError(`rollback refused because target changed after install: ${action.targetDir}`, 2)
    }
    allBefore = false
    if (!manifestEquals(current, action.after)) throw new SetupError(`rollback refused because the active setup bytes changed after install: ${action.targetDir}`, 2)
    if (action.before) {
      if (!existsSync(action.backupDir)) throw new SetupError(`rollback backup is missing: ${action.backupDir}`, 3)
      let backup: SetupManifest
      try { backup = manifestDirectory(action.backupDir, false).manifest }
      catch (error) { throw new SetupError(`rollback backup is unreadable or damaged: ${action.backupDir}: ${(error as Error).message}`, 3) }
      if (!manifestEquals(backup, action.before)) throw new SetupError(`rollback backup is damaged: ${action.backupDir}`, 3)
    }
  }
  if (allBefore) return { transactionId: receipt.transactionId, state: 'already-rolled-back' }
  ensureAdmin(target)
  const transactionId = randomUUID()
  const txRoot = join(target.adminRoot, 'transactions', transactionId)
  ensurePrivateDirectory(txRoot)
  ensurePrivateDirectory(join(txRoot, 'stage'))
  ensurePrivateDirectory(join(txRoot, 'backup'))
  ensurePrivateDirectory(join(txRoot, 'quarantine'))
  const actions: JournalAction[] = receipt.actions.map((action) => ({
    index: action.index,
    name: action.name,
    action: action.action,
    sourceDir: '',
    targetDir: action.targetDir,
    source: action.after,
    before: action.before,
    beforeOwner: action.beforeOwner,
    analysis: action.analysis,
    stageDir: join(txRoot, 'stage', action.name),
    backupDir: action.backupDir,
    quarantineDir: join(txRoot, 'quarantine', action.name),
    ownedAfterTransactionId: receipt.transactionId,
    status: 'pending',
  }))
  const journal: SetupJournal = {
    protocolVersion: SETUP_PROTOCOL_VERSION,
    installerVersion: SETUP_INSTALLER_VERSION,
    transactionId,
    kind: 'rollback',
    planId: receipt.planId,
    receiptId: receipt.receiptId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    state: 'planned',
    target,
    actions,
    integritySha256: '',
  }
  const jPath = journalPath(target, transactionId)
  journal.integritySha256 = digestObject(without(journal, 'integritySha256'))
  writePrivateJsonNew(jPath, journal)
  let lockAcquired = false
  try {
    acquireLock(target, transactionId)
    lockAcquired = true
    assertNoOtherPending(target, transactionId)
    restoreBefore(journal, jPath)
    releaseLock(target, transactionId)
    return { transactionId, state: 'rolled-back' }
  } catch (error) {
    if (!lockAcquired) updateJournal(jPath, journal, 'rolled-back', (error as Error).message)
    if (readLock(target)?.transactionId === transactionId && terminalJournal(journal.state)) releaseLock(target, transactionId)
    if (error instanceof SetupError) throw error
    throw new SetupError(`rollback needs attention: ${(error as Error).message}`, 3)
  }
}

export function recoverSetup(options: { targetRoot: string; mode: 'rollback'; confirm: string }): { transactionId: string; state: 'rolled-back' } {
  assertSupportedRuntime(true)
  if (options.mode !== 'rollback') throw new SetupError('setup recover v1 supports only --mode rollback')
  const status = readSetupStatus(options.targetRoot)
  const pending = status.pending.find((item) => item.transactionId === options.confirm)
  if (!pending) throw new SetupError('confirmation must match a pending transaction ID', 2)
  const path = join(status.adminRoot, 'transactions', pending.transactionId, 'journal.json')
  const journal = readJournal(path)
  const target = validateRecordedTarget(journal.target)
  ensureAdmin(target)
  const lock = readLock(target)
  if (lock && lock.transactionId !== journal.transactionId) throw new SetupError(`another transaction owns the root lock: ${lock.transactionId}`, 2)
  if (lock && lock.pid !== process.pid) {
    try { process.kill(lock.pid, 0); throw new SetupError(`transaction owner process is still alive (pid ${lock.pid}); recovery refused`, 2) }
    catch (error) { if (error instanceof SetupError) throw error; if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw new SetupError(`cannot prove transaction owner is stale (pid ${lock.pid})`, 2) }
  }
  if (!lock) acquireLock(target, journal.transactionId)
  if (journal.kind === 'apply' && journal.state === 'planned') {
    for (const action of journal.actions) {
      if (!manifestEquals(currentManifest(action.targetDir), action.before) || !ownerEquals(readActiveOwner(target, action.name), action.beforeOwner)) {
        updateJournal(path, journal, 'needs-attention', `pre-lock target drift: ${action.targetDir}`)
        releaseLock(target, journal.transactionId)
        throw new SetupError(`pre-lock transaction made no writes, but target changed independently: ${action.targetDir}`, 3)
      }
    }
    updateJournal(path, journal, 'rolled-back')
    releaseLock(target, journal.transactionId)
    return { transactionId: journal.transactionId, state: 'rolled-back' }
  }
  restoreBefore(journal, path)
  quarantineReceiptsForTransaction(target, journal.transactionId, join(dirname(path), 'quarantine'))
  releaseLock(target, journal.transactionId)
  return { transactionId: journal.transactionId, state: 'rolled-back' }
}

function parseSetupOptions(argv: string[], allowed: Record<string, 'single' | 'repeatable'>): Map<string, string[]> {
  const parsed = new Map<string, string[]>()
  for (let index = 0; index < argv.length; index++) {
    const key = argv[index]!, mode = allowed[key]
    if (!mode) throw new SetupError(`unknown setup option: ${key}`)
    const value = argv[++index]
    if (!value || value.startsWith('--')) throw new SetupError(`${key} requires a value`)
    const values = parsed.get(key) ?? []
    if (mode === 'single' && values.length) throw new SetupError(`${key} may be provided only once`)
    values.push(value); parsed.set(key, values)
  }
  return parsed
}

function setupHelp(): void {
  console.log(`
  skillmoo setup prepare --source <dir> [--source <dir>...] --target-root <dir> --out <plan.json> [--project-root <dir>]
  skillmoo setup apply --plan <plan.json> --confirm <plan-id>
  skillmoo setup status --target-root <dir>
  skillmoo setup rollback --receipt <receipt.json> --confirm <receipt-id>
  skillmoo setup recover --target-root <dir> --mode rollback --confirm <transaction-id>

  Local complete directories only. No download, hooks, dependency install, sudo, or package code execution.
  Apply/rollback/recover are explicit-confirm, drift-checked, and crash recoverable; installation remains inspected evidence.
`)
}

export function runSetupCommand(argv: string[]): number {
  try {
    const [subcommand, ...rest] = argv
    if (!subcommand || subcommand === 'help' || subcommand === '--help' || subcommand === '-h') { setupHelp(); return 0 }
    if (subcommand === 'prepare') {
      const parsed = parseSetupOptions(rest, { '--source': 'repeatable', '--target-root': 'single', '--out': 'single', '--project-root': 'single' })
      const sourceDirs = parsed.get('--source') ?? []
      const targetRoot = parsed.get('--target-root')?.[0]
      const planPath = parsed.get('--out')?.[0]
      if (!targetRoot || !planPath) throw new SetupError('prepare requires --target-root and --out')
      const plan = prepareSetup({ sourceDirs, targetRoot, planPath, projectRoot: parsed.get('--project-root')?.[0] })
      console.log(JSON.stringify({ planId: plan.planId, planPath: resolve(planPath), targetRoot: plan.target.root, actions: plan.actions.map((a) => ({ name: a.name, action: a.action, files: a.source.files, bytes: a.source.totalBytes, grade: a.analysis.grade, gate: a.analysis.gate, risk: a.analysis.risk, uninterpretedFiles: a.analysis.uninterpretedFiles })) }, null, 2))
      return 0
    }
    if (subcommand === 'apply') {
      const parsed = parseSetupOptions(rest, { '--plan': 'single', '--confirm': 'single' })
      const planPath = parsed.get('--plan')?.[0], confirm = parsed.get('--confirm')?.[0]
      if (!planPath || !confirm) throw new SetupError('apply requires --plan and --confirm')
      const receiptPath = applySetup({ planPath, confirm })
      console.log(JSON.stringify({ state: 'committed', receiptPath, evidence: 'inspected', next: 'Run skillmoo verify for environment-backed evidence, then restart/reload your Agent.' }, null, 2))
      return 0
    }
    if (subcommand === 'status') {
      const targetRoot = parseSetupOptions(rest, { '--target-root': 'single' }).get('--target-root')?.[0]
      if (!targetRoot) throw new SetupError('status requires --target-root')
      console.log(JSON.stringify(readSetupStatus(targetRoot), null, 2)); return 0
    }
    if (subcommand === 'rollback') {
      const parsed = parseSetupOptions(rest, { '--receipt': 'single', '--confirm': 'single' })
      const receiptPath = parsed.get('--receipt')?.[0], confirm = parsed.get('--confirm')?.[0]
      if (!receiptPath || !confirm) throw new SetupError('rollback requires --receipt and --confirm')
      console.log(JSON.stringify(rollbackSetup({ receiptPath, confirm }), null, 2)); return 0
    }
    if (subcommand === 'recover') {
      const parsed = parseSetupOptions(rest, { '--target-root': 'single', '--confirm': 'single', '--mode': 'single' })
      const targetRoot = parsed.get('--target-root')?.[0], confirm = parsed.get('--confirm')?.[0], mode = parsed.get('--mode')?.[0]
      if (!targetRoot || !confirm || mode !== 'rollback') throw new SetupError('recover requires --target-root, --mode rollback, and --confirm')
      console.log(JSON.stringify(recoverSetup({ targetRoot, mode, confirm }), null, 2)); return 0
    }
    throw new SetupError(`unknown setup command: ${subcommand}`)
  } catch (error) {
    if (error instanceof SetupError) { console.error(`setup: ${safeTerminalText(error.message)}`); return error.exitCode }
    console.error(`setup: ${safeTerminalText((error as Error).message)}`)
    return 1
  }
}
