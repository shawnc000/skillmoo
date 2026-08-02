import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { randomUUID } from 'node:crypto'
import { homedir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { ARTIFACT_INDEX } from '../src/data/artifactIndex'
import { ARTIFACT_PAYLOADS } from './artifactPayloads'
import {
  canonicalJson,
  validateArtifactIndex,
  validateArtifactPayload,
  type ArtifactDescriptor,
  type ArtifactIndex,
  type ArtifactPayload,
} from './catalogArtifact'
import { inspectSetupSource, prepareSetup, SetupError, type SetupPlan } from './setup'
import { safeTerminalText } from './format'

const INDEX = ARTIFACT_INDEX as unknown as ArtifactIndex
let indexValidated = false

function ensureIndex(): void {
  if (!indexValidated) { validateArtifactIndex(INDEX); indexValidated = true }
}

function assertMutationUser(): void {
  if (typeof process.geteuid === 'function' && process.geteuid() === 0) throw new SetupError('catalog materialization refuses to run as root/sudo')
}

function ensurePrivateDirectory(path: string): void {
  if (!existsSync(path)) {
    try { mkdirSync(path, { mode: 0o700 }) }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error }
  }
  const st = lstatSync(path)
  const uid = typeof process.getuid === 'function' ? process.getuid() : undefined
  if (st.isSymbolicLink() || !st.isDirectory()) throw new SetupError(`artifact cache path must be a real directory: ${path}`, 3)
  if (uid !== undefined && st.uid !== uid) throw new SetupError(`artifact cache path is not owned by the current user: ${path}`, 3)
  if ((st.mode & 0o077) !== 0) throw new SetupError(`artifact cache permissions are too broad (require 0700): ${path}`, 3)
}

function defaultCacheRoot(): string {
  const home = resolve(homedir())
  const st = lstatSync(home)
  if (st.isSymbolicLink() || !st.isDirectory() || realpathSync(home) !== home) throw new SetupError('current user home must be a real canonical directory')
  const state = join(home, '.skillmoo')
  const artifacts = join(state, 'artifacts')
  const version = join(artifacts, 'v1')
  ensurePrivateDirectory(state)
  ensurePrivateDirectory(artifacts)
  ensurePrivateDirectory(version)
  return version
}

function writePrivateFile(path: string, bytes: Buffer, mode: 0o600 | 0o700): void {
  const fd = openSync(path, 'wx', mode)
  try { writeFileSync(fd, bytes); fsyncSync(fd) } finally { closeSync(fd) }
  chmodSync(path, mode)
}

function ensureRelativeParents(root: string, relativePath: string): string {
  const parts = relativePath.split('/')
  let current = root
  for (const part of parts.slice(0, -1)) {
    current = join(current, part)
    ensurePrivateDirectory(current)
  }
  return join(root, ...parts)
}

function descriptorFor(id: string): ArtifactDescriptor {
  ensureIndex()
  const entry = INDEX.entries.find((item) => item.status === 'pilot-ready' && item.artifact.artifactId === id)
  if (!entry || entry.status !== 'pilot-ready') throw new SetupError(`unknown or link-only artifact ID: ${id}`)
  return entry.artifact
}

function artifactEvidence(descriptor: ArtifactDescriptor): Record<string, unknown> {
  return {
    name: descriptor.name,
    artifactId: descriptor.artifactId,
    source: {
      repository: descriptor.source.repository,
      repositoryId: descriptor.source.repositoryId,
      commit: descriptor.source.commit,
      rootTreeOid: descriptor.source.rootTreeOid,
      rootPath: descriptor.source.rootPath,
      pinnedUrl: descriptor.source.pinnedUrl,
    },
    package: {
      files: descriptor.manifest.files,
      bytes: descriptor.manifest.totalBytes,
      bundleSha256: descriptor.manifest.bundleSha256,
      payloadSha256: descriptor.payloadSha256,
    },
    assessment: descriptor.assessment,
    license: descriptor.license,
    evidence: descriptor.evidence,
    limitations: descriptor.limitations,
  }
}

function verifyMaterialized(path: string, descriptor: ArtifactDescriptor, payload: ArtifactPayload): void {
  const topLevel = readdirSync(path).sort((a, b) => a.localeCompare(b, 'en'))
  const expectedTopLevel = ['artifact.json', descriptor.name].sort((a, b) => a.localeCompare(b, 'en'))
  if (canonicalJson(topLevel) !== canonicalJson(expectedTopLevel)) throw new SetupError(`artifact cache contains unexpected or missing entries: ${path}`, 3)
  const skillRoot = join(path, descriptor.name)
  if (!existsSync(skillRoot)) throw new SetupError(`artifact cache is incomplete: ${path}`, 3)
  let inspected: ReturnType<typeof inspectSetupSource>
  try { inspected = inspectSetupSource(skillRoot) }
  catch (error) { throw new SetupError(`artifact cache cannot be inspected: ${path}: ${(error as Error).message}`, 3) }
  if (canonicalJson(inspected.manifest) !== canonicalJson(descriptor.manifest) || canonicalJson(inspected.analysis) !== canonicalJson(descriptor.assessment)) throw new SetupError(`artifact cache failed manifest/assessment validation: ${path}`, 3)
  const licensePath = join(skillRoot, descriptor.license.installPath)
  const descriptorPath = join(path, 'artifact.json')
  if (!existsSync(licensePath) || !lstatSync(licensePath).isFile() || readFileSync(licensePath).toString('base64') !== payload.license.base64) throw new SetupError(`artifact cache license evidence is missing or damaged: ${path}`, 3)
  try {
    if (!lstatSync(descriptorPath).isFile() || canonicalJson(JSON.parse(readFileSync(descriptorPath, 'utf8'))) !== canonicalJson(descriptor)) throw new Error('descriptor mismatch')
  } catch {
    throw new SetupError(`artifact cache descriptor evidence is missing or damaged: ${path}`, 3)
  }
}

export function materializeCatalogArtifact(
  artifactId: string,
  options: { cacheRoot?: string; payloads?: Record<string, ArtifactPayload> } = {},
): { descriptor: ArtifactDescriptor; sourceDir: string; cacheHit: boolean } {
  assertMutationUser()
  const descriptor = descriptorFor(artifactId)
  const payload = (options.payloads ?? ARTIFACT_PAYLOADS)[artifactId]
  if (!payload) throw new SetupError(`embedded artifact payload is missing: ${artifactId}`, 3)
  try { validateArtifactPayload(descriptor, payload) }
  catch (error) { throw new SetupError(`embedded artifact payload failed integrity: ${(error as Error).message}`, 3) }
  const cacheRoot = options.cacheRoot ? resolve(options.cacheRoot) : defaultCacheRoot()
  if (options.cacheRoot) ensurePrivateDirectory(cacheRoot)
  const destination = join(cacheRoot, artifactId)
  if (existsSync(destination)) {
    ensurePrivateDirectory(destination)
    verifyMaterialized(destination, descriptor, payload)
    return { descriptor, sourceDir: join(destination, descriptor.name), cacheHit: true }
  }
  const stage = join(cacheRoot, `.stage-${artifactId}-${randomUUID()}`)
  ensurePrivateDirectory(stage)
  try {
    const skillRoot = join(stage, descriptor.name)
    ensurePrivateDirectory(skillRoot)
    for (const file of payload.files) {
      const path = ensureRelativeParents(skillRoot, file.path)
      writePrivateFile(path, Buffer.from(file.base64, 'base64'), file.mode)
    }
    writePrivateFile(join(skillRoot, descriptor.license.installPath), Buffer.from(payload.license.base64, 'base64'), 0o600)
    writePrivateFile(join(stage, 'artifact.json'), Buffer.from(`${JSON.stringify(descriptor, null, 2)}\n`), 0o600)
    verifyMaterialized(stage, descriptor, payload)
    try { renameSync(stage, destination) }
    catch (error) {
      if (!existsSync(destination)) throw error
      ensurePrivateDirectory(destination)
      verifyMaterialized(destination, descriptor, payload)
      rmSync(stage, { recursive: true, force: true })
      return { descriptor, sourceDir: join(destination, descriptor.name), cacheHit: true }
    }
  } catch (error) {
    if (existsSync(stage) && basename(stage).startsWith(`.stage-${artifactId}-`) && dirname(stage) === cacheRoot) rmSync(stage, { recursive: true, force: true })
    if (error instanceof SetupError) throw error
    throw new SetupError(`artifact materialization failed: ${(error as Error).message}`, 3)
  }
  return { descriptor, sourceDir: join(destination, descriptor.name), cacheHit: false }
}

export function prepareCatalogSetup(options: {
  artifactIds: string[]
  targetRoot: string
  planPath: string
  projectRoot?: string
  cacheRoot?: string
  payloads?: Record<string, ArtifactPayload>
}): { plan: SetupPlan; artifacts: { artifactId: string; name: string; cacheHit: boolean }[] } {
  if (!options.artifactIds.length) throw new SetupError('catalog prepare requires at least one --artifact ID')
  const unique = new Set(options.artifactIds)
  if (unique.size !== options.artifactIds.length) throw new SetupError('catalog prepare rejects duplicate artifact IDs')
  const materialized = options.artifactIds.map((artifactId) => materializeCatalogArtifact(artifactId, { cacheRoot: options.cacheRoot, payloads: options.payloads }))
  const plan = prepareSetup({ sourceDirs: materialized.map((item) => item.sourceDir), targetRoot: options.targetRoot, planPath: options.planPath, projectRoot: options.projectRoot })
  return { plan, artifacts: materialized.map((item) => ({ artifactId: item.descriptor.artifactId, name: item.descriptor.name, cacheHit: item.cacheHit })) }
}

function parseOptions(argv: string[], allowed: Record<string, 'single' | 'repeatable'>): Map<string, string[]> {
  const parsed = new Map<string, string[]>()
  for (let index = 0; index < argv.length; index++) {
    const key = argv[index]!, mode = allowed[key]
    if (!mode) throw new SetupError(`unknown catalog option: ${key}`)
    const value = argv[++index]
    if (!value || value.startsWith('--')) throw new SetupError(`${key} requires a value`)
    const values = parsed.get(key) ?? []
    if (mode === 'single' && values.length) throw new SetupError(`${key} may be provided only once`)
    values.push(value); parsed.set(key, values)
  }
  return parsed
}

function help(): void {
  const readyCount = INDEX.entries.filter((entry) => entry.status === 'pilot-ready').length
  console.log(`
  skillmoo catalog list
  skillmoo catalog inspect --artifact <sa_id> [--artifact <sa_id>...]
  skillmoo catalog prepare --artifact <sa_id> [--artifact <sa_id>...] --target-root <dir> --out <plan.json> [--project-root <dir>]

  Catalog v2.1 embeds ${readyCount} MIT pilot artifacts in this exact CLI package. Materialization is offline,
  runs no package code, writes no target-root content, and reuses setup apply/rollback/recover.
  Entries remain inspected exact-version evidence, not runtime verification or revocation-current certification.
`)
}

export function runCatalogCommand(argv: string[]): number {
  try {
    ensureIndex()
    const [subcommand, ...rest] = argv
    if (!subcommand || ['help', '--help', '-h'].includes(subcommand)) { help(); return 0 }
    if (subcommand === 'list') {
      if (rest.length) throw new SetupError(`catalog list accepts no options: ${rest.join(' ')}`)
      const ready = INDEX.entries.flatMap((entry) => entry.status === 'pilot-ready' ? [{
        name: entry.name, artifactId: entry.artifact.artifactId, files: entry.artifact.manifest.files,
        bytes: entry.artifact.manifest.totalBytes, grade: entry.artifact.assessment.grade,
        license: entry.artifact.license.spdx, evidence: entry.artifact.evidence,
      }] : [])
      const reasonCounts = Object.fromEntries([...new Set(INDEX.entries.flatMap((entry) => entry.status === 'link-only' ? [entry.reason] : []))]
        .sort((a, b) => a.localeCompare(b, 'en'))
        .map((reason) => [reason, INDEX.entries.filter((entry) => entry.status === 'link-only' && entry.reason === reason).length]))
      console.log(JSON.stringify({ cliVersion: INDEX.cliVersion, catalogSha256: INDEX.catalogSha256, ready, linkOnly: INDEX.entries.length - ready.length, reasonCounts }, null, 2))
      return 0
    }
    if (subcommand === 'inspect') {
      const parsed = parseOptions(rest, { '--artifact': 'repeatable' })
      const artifactIds = parsed.get('--artifact') ?? []
      if (!artifactIds.length || new Set(artifactIds).size !== artifactIds.length) throw new SetupError('catalog inspect requires unique --artifact IDs')
      console.log(JSON.stringify({ cliVersion: INDEX.cliVersion, catalogSha256: INDEX.catalogSha256, artifacts: artifactIds.map((id) => artifactEvidence(descriptorFor(id))) }, null, 2))
      return 0
    }
    if (subcommand === 'prepare') {
      const parsed = parseOptions(rest, { '--artifact': 'repeatable', '--target-root': 'single', '--out': 'single', '--project-root': 'single' })
      const artifactIds = parsed.get('--artifact') ?? []
      const targetRoot = parsed.get('--target-root')?.[0], planPath = parsed.get('--out')?.[0]
      if (!targetRoot || !planPath) throw new SetupError('catalog prepare requires --artifact, --target-root, and --out')
      const result = prepareCatalogSetup({ artifactIds, targetRoot, planPath, projectRoot: parsed.get('--project-root')?.[0] })
      console.log(JSON.stringify({
        state: 'prepared', planId: result.plan.planId, planPath: resolve(planPath), targetRoot: result.plan.target.root,
        artifacts: result.artifacts.map((artifact) => ({ ...artifact, evidence: artifactEvidence(descriptorFor(artifact.artifactId)) })),
        next: `Review the plan, then run skillmoo setup apply --plan ${resolve(planPath)} --confirm ${result.plan.planId}`,
      }, null, 2))
      return 0
    }
    throw new SetupError(`unknown catalog command: ${subcommand}`)
  } catch (error) {
    if (error instanceof SetupError) { console.error(`catalog: ${safeTerminalText(error.message)}`); return error.exitCode }
    console.error(`catalog: ${safeTerminalText((error as Error).message)}`)
    return 1
  }
}
