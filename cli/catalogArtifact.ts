import { createHash } from 'node:crypto'
import type { SetupAnalysisSummary, SetupManifest } from './setup'

export const ARTIFACT_PROTOCOL_VERSION = 'skillmoo-artifact/1.0' as const
export const ARTIFACT_INDEX_VERSION = 'skillmoo-artifact-index/1.0' as const
export const ARTIFACT_PAYLOAD_VERSION = 'skillmoo-artifact-payload/1.0' as const
export const ARTIFACT_LIMITATIONS = [
  'Complete pinned bytes and deterministic static inspection; not runtime efficacy.',
  'Upstream maintainer signature and online revocation freshness are not claimed.',
] as const

export type ArtifactLinkOnlyReason =
  | 'not-in-v2.1-pilot'
  | 'source-policy-mismatch'
  | 'unsupported-tree'
  | 'bounds-failed'
  | 'full-gate-failed'
  | 'license-policy-failed'

export interface ArtifactSourceFile {
  path: string
  sourcePath: string
  gitMode: '100644' | '100755'
  gitBlobOid: string
  size: number
  sha256: string
}

export interface ArtifactDescriptor {
  protocolVersion: typeof ARTIFACT_PROTOCOL_VERSION
  artifactId: string
  name: string
  sourceGroup: string
  source: {
    provider: 'github'
    repository: string
    repositoryId: string
    commit: string
    rootTreeOid: string
    rootPath: string
    sourceUrl: string
    pinnedUrl: string
  }
  license: {
    spdx: 'MIT'
    policy: 'reviewed-embedded-pilot'
    sourcePath: string
    installPath: 'LICENSE.upstream.txt'
    sha256: string
  }
  files: ArtifactSourceFile[]
  manifest: SetupManifest
  assessment: SetupAnalysisSummary
  payloadSha256: string
  availability: 'embedded' | 'unavailable' | 'quarantined' | 'revoked'
  evidence: 'inspected-exact-version'
  limitations: string[]
}

export interface ArtifactReadyEntry {
  name: string
  sourceUrl: string
  status: 'pilot-ready'
  artifact: ArtifactDescriptor
}

export interface ArtifactLinkOnlyEntry {
  name: string
  sourceUrl: string
  status: 'link-only'
  reason: ArtifactLinkOnlyReason
}

export type ArtifactIndexEntry = ArtifactReadyEntry | ArtifactLinkOnlyEntry

export interface ArtifactIndex {
  protocolVersion: typeof ARTIFACT_INDEX_VERSION
  cliVersion: string
  catalogSha256: string
  entries: ArtifactIndexEntry[]
}

export interface ArtifactPayloadFile {
  path: string
  mode: 384 | 448
  size: number
  sha256: string
  base64: string
}

export interface ArtifactPayload {
  protocolVersion: typeof ARTIFACT_PAYLOAD_VERSION
  artifactId: string
  name: string
  files: ArtifactPayloadFile[]
  license: { path: string; sha256: string; base64: string }
  payloadSha256: string
}

const sha256 = (value: string | Buffer) => createHash('sha256').update(value).digest('hex')

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize)
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => a.localeCompare(b, 'en')).map(([key, item]) => [key, canonicalize(item)]))
  return value
}

export const canonicalJson = (value: unknown): string => JSON.stringify(canonicalize(value))
export const digestObject = (value: unknown): string => sha256(canonicalJson(value))
const without = <T extends object, K extends keyof T>(value: T, key: K): Omit<T, K> => {
  const copy = { ...value }; delete copy[key]; return copy
}

function safeRelativePath(path: string): boolean {
  if (!path || path !== path.normalize('NFC') || path.startsWith('/') || path.includes('\\') || [...path].some((character) => {
    const code = character.codePointAt(0) ?? 0
    return code <= 31 || code === 127
  })) return false
  const parts = path.split('/')
  if (parts.some((part) => !part || part === '.' || part === '..' || part.endsWith(' ') || part.endsWith('.'))) return false
  const reserved = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i
  return !parts.some((part) => reserved.test(part))
}

const gitOid = (value: string) => /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(value)
const hex64 = (value: string) => /^[0-9a-f]{64}$/.test(value)
const LINK_ONLY_REASONS = new Set<ArtifactLinkOnlyReason>(['not-in-v2.1-pilot', 'source-policy-mismatch', 'unsupported-tree', 'bounds-failed', 'full-gate-failed', 'license-policy-failed'])

function validateSetupManifest(manifest: SetupManifest): void {
  if (manifest.rootMode !== 0o700 || !hex64(manifest.bundleSha256) || !Array.isArray(manifest.entries)) throw new Error('artifact manifest header is malformed')
  let files = 0, totalBytes = 0
  const keys = new Set<string>()
  let previous = ''
  for (const entry of manifest.entries) {
    if (!safeRelativePath(entry.path) || entry.path.localeCompare(previous, 'en') < 0) throw new Error(`artifact manifest path is unsafe or unsorted: ${entry.path}`)
    const parts = entry.path.split('/')
    if (Buffer.byteLength(entry.path, 'utf8') > 240 || parts.length > 8 || parts.some((part) => Buffer.byteLength(part, 'utf8') > 120)) throw new Error(`artifact manifest path exceeds setup bounds: ${entry.path}`)
    previous = entry.path
    const key = entry.path.normalize('NFC').toLocaleLowerCase('en-US')
    if (keys.has(key)) throw new Error(`artifact manifest path collides: ${entry.path}`)
    keys.add(key)
    if (entry.kind === 'directory') {
      if (entry.mode !== 0o700 || entry.size !== undefined || entry.sha256 !== undefined) throw new Error(`artifact directory entry is malformed: ${entry.path}`)
    } else {
      if (![0o600, 0o700].includes(entry.mode) || !Number.isSafeInteger(entry.size) || (entry.size ?? -1) < 0 || !hex64(entry.sha256 ?? '')) throw new Error(`artifact file entry is malformed: ${entry.path}`)
      if ((entry.size ?? 0) > 4 * 1024 * 1024) throw new Error(`artifact file exceeds setup bounds: ${entry.path}`)
      files++; totalBytes += entry.size ?? 0
    }
  }
  if (files > 200 || totalBytes > 20 * 1024 * 1024) throw new Error('artifact manifest exceeds setup bounds')
  if (files !== manifest.files || totalBytes !== manifest.totalBytes || !Array.isArray(manifest.uninterpretedFiles)) throw new Error('artifact manifest totals are malformed')
  if (manifest.uninterpretedFiles.some((path) => !safeRelativePath(path) || !keys.has(path.normalize('NFC').toLocaleLowerCase('en-US')))) throw new Error('artifact uninterpreted-file coverage is malformed')
  const core = { rootMode: manifest.rootMode, entries: manifest.entries, files, totalBytes, uninterpretedFiles: manifest.uninterpretedFiles }
  if (digestObject(core) !== manifest.bundleSha256) throw new Error('artifact manifest bundle digest mismatch')
}

export function artifactIdFor(descriptor: Omit<ArtifactDescriptor, 'artifactId'>): string {
  return `sa_${digestObject(descriptor).slice(0, 32)}`
}

export function payloadDigest(payload: Omit<ArtifactPayload, 'artifactId' | 'payloadSha256'>): string {
  return digestObject(payload)
}

export function validateArtifactDescriptor(descriptor: ArtifactDescriptor): void {
  if (descriptor.protocolVersion !== ARTIFACT_PROTOCOL_VERSION || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(descriptor.name)) throw new Error('artifact identity is malformed')
  if (descriptor.source.provider !== 'github' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(descriptor.source.repository) || !descriptor.source.repositoryId || !gitOid(descriptor.source.commit) || !gitOid(descriptor.source.rootTreeOid)) throw new Error(`artifact source identity is malformed: ${descriptor.name}`)
  if (!safeRelativePath(descriptor.source.rootPath) || descriptor.source.rootPath.split('/').at(-1) !== descriptor.name) throw new Error(`artifact root path is malformed: ${descriptor.name}`)
  const pinned = `https://github.com/${descriptor.source.repository}/tree/${descriptor.source.commit}/${descriptor.source.rootPath}`
  if (descriptor.source.pinnedUrl !== pinned || !descriptor.source.sourceUrl.startsWith(`https://github.com/${descriptor.source.repository}/blob/`)) throw new Error(`artifact source URL is malformed: ${descriptor.name}`)
  if (descriptor.license.spdx !== 'MIT' || descriptor.license.policy !== 'reviewed-embedded-pilot' || !safeRelativePath(descriptor.license.sourcePath) || descriptor.license.installPath !== 'LICENSE.upstream.txt' || !hex64(descriptor.license.sha256)) throw new Error(`artifact license is malformed: ${descriptor.name}`)
  validateSetupManifest(descriptor.manifest)
  if (!['A', 'B'].includes(descriptor.assessment.grade) || descriptor.assessment.gate !== 'pass' || descriptor.assessment.risk !== 'low') throw new Error(`artifact assessment is not setup-ready: ${descriptor.name}`)
  if (!hex64(descriptor.payloadSha256) || descriptor.availability !== 'embedded' || descriptor.evidence !== 'inspected-exact-version') throw new Error(`artifact evidence is malformed: ${descriptor.name}`)
  if (canonicalJson(descriptor.limitations) !== canonicalJson(ARTIFACT_LIMITATIONS)) throw new Error(`artifact claim limitations are malformed: ${descriptor.name}`)
  const manifestFiles = new Map(descriptor.manifest.entries.filter((entry) => entry.kind === 'file').map((entry) => [entry.path, entry]))
  const licenseManifest = manifestFiles.get(descriptor.license.installPath)
  if (!licenseManifest || licenseManifest.mode !== 0o600 || licenseManifest.sha256 !== descriptor.license.sha256 || descriptor.files.length + 1 !== descriptor.manifest.files) throw new Error(`artifact file/license coverage mismatch: ${descriptor.name}`)
  const sourcePaths = new Set<string>()
  let previous = ''
  for (const file of descriptor.files) {
    if (!safeRelativePath(file.path) || !safeRelativePath(file.sourcePath) || file.path.localeCompare(previous, 'en') < 0 || !['100644', '100755'].includes(file.gitMode) || !gitOid(file.gitBlobOid) || !hex64(file.sha256)) throw new Error(`artifact source file is malformed: ${descriptor.name}/${file.path}`)
    previous = file.path
    const sourceKey = file.sourcePath.normalize('NFC').toLocaleLowerCase('en-US')
    if (sourcePaths.has(sourceKey) || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > 4 * 1024 * 1024) throw new Error(`artifact source file is duplicated or out of bounds: ${descriptor.name}/${file.path}`)
    sourcePaths.add(sourceKey)
    const manifest = manifestFiles.get(file.path)
    const expectedMode = file.gitMode === '100755' ? 0o700 : 0o600
    if (!manifest || manifest.mode !== expectedMode || manifest.size !== file.size || manifest.sha256 !== file.sha256) throw new Error(`artifact source/manifest mismatch: ${descriptor.name}/${file.path}`)
  }
  if (descriptor.artifactId !== artifactIdFor(without(descriptor, 'artifactId'))) throw new Error(`artifact ID mismatch: ${descriptor.name}`)
}

export function catalogDigest(index: Omit<ArtifactIndex, 'catalogSha256'>): string { return digestObject(index) }

export function validateArtifactIndex(index: ArtifactIndex): void {
  if (index.protocolVersion !== ARTIFACT_INDEX_VERSION || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(index.cliVersion) || !Array.isArray(index.entries)) throw new Error('artifact index header is malformed')
  if (index.catalogSha256 !== catalogDigest(without(index, 'catalogSha256'))) throw new Error('artifact index digest mismatch')
  const names = new Set<string>(), ids = new Set<string>()
  let previous = ''
  for (const entry of index.entries) {
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(entry.name) || entry.name.localeCompare(previous, 'en') < 0 || names.has(entry.name) || !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/blob\/[^/]+\/.+\/SKILL\.md$/.test(entry.sourceUrl)) throw new Error(`artifact index entry is malformed: ${entry.name}`)
    previous = entry.name; names.add(entry.name)
    if (entry.status === 'pilot-ready') {
      validateArtifactDescriptor(entry.artifact)
      if (entry.artifact.name !== entry.name || entry.artifact.source.sourceUrl !== entry.sourceUrl || ids.has(entry.artifact.artifactId)) throw new Error(`artifact index ready entry mismatch: ${entry.name}`)
      ids.add(entry.artifact.artifactId)
    } else if (entry.status !== 'link-only' || !LINK_ONLY_REASONS.has(entry.reason)) throw new Error(`artifact index status is malformed: ${entry.name}`)
  }
}

export function validateArtifactPayload(descriptor: ArtifactDescriptor, payload: ArtifactPayload): void {
  if (payload.protocolVersion !== ARTIFACT_PAYLOAD_VERSION || payload.artifactId !== descriptor.artifactId || payload.name !== descriptor.name || payload.payloadSha256 !== descriptor.payloadSha256) throw new Error(`artifact payload identity mismatch: ${descriptor.name}`)
  const core = { protocolVersion: payload.protocolVersion, name: payload.name, files: payload.files, license: payload.license }
  if (payloadDigest(core) !== payload.payloadSha256) throw new Error(`artifact payload digest mismatch: ${descriptor.name}`)
  const licenseBytes = Buffer.from(payload.license.base64, 'base64')
  if (licenseBytes.length > 1024 * 1024 || licenseBytes.toString('base64') !== payload.license.base64 || payload.license.path !== descriptor.license.sourcePath || payload.license.sha256 !== descriptor.license.sha256 || sha256(licenseBytes) !== payload.license.sha256) throw new Error(`artifact license payload mismatch: ${descriptor.name}`)
  if (payload.files.length !== descriptor.files.length) throw new Error(`artifact payload file coverage mismatch: ${descriptor.name}`)
  for (let index = 0; index < payload.files.length; index++) {
    const file = payload.files[index]!, source = descriptor.files[index]!
    const bytes = Buffer.from(file.base64, 'base64')
    const header = Buffer.from(`blob ${bytes.length}\0`)
    const objectOid = createHash(source.gitBlobOid.length === 64 ? 'sha256' : 'sha1').update(header).update(bytes).digest('hex')
    if (bytes.toString('base64') !== file.base64 || file.path !== source.path || file.mode !== (source.gitMode === '100755' ? 0o700 : 0o600) || file.size !== source.size || file.sha256 !== source.sha256 || bytes.length !== file.size || sha256(bytes) !== file.sha256 || objectOid !== source.gitBlobOid) throw new Error(`artifact payload file mismatch: ${descriptor.name}/${file.path}`)
  }
}
