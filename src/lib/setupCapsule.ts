import {
  VERIFICATION_PROTOCOL_VERSION,
  canonicalJson,
  receiptPayload,
  sha256Text,
  validateVerificationReceipt,
  verifyReceiptIntegrity,
  type VerificationDerived,
  type VerificationReceipt,
} from './verificationProtocol'
import { parseStrictJson } from './strictJson'

export const SETUP_CAPSULE_VERSION = 'skillmoo-setup-capsule/1.0' as const
export const MAX_SETUP_CAPSULE_BYTES = 1_048_576

type ArtifactAssessment = {
  grade: string
  gate: string
  risk: string
  rubricVersion: string
  vector: string
  uninterpretedFiles: number
}

type ArtifactManifestEntry = {
  path: string
  kind: 'directory' | 'file'
  mode: number
  size?: number
  sha256?: string
}

type ReadyArtifact = {
  protocolVersion: string
  artifactId: string
  name: string
  source: {
    repository: string
    commit: string
    rootTreeOid: string
    rootPath: string
    pinnedUrl: string
  }
  license: { spdx: string; sha256: string; installPath: string }
  manifest: {
    bundleSha256: string
    rootMode: number
    entries: readonly ArtifactManifestEntry[]
    files: number
    totalBytes: number
    uninterpretedFiles: readonly string[]
  }
  assessment: ArtifactAssessment
  payloadSha256: string
  availability: 'embedded' | 'unavailable' | 'quarantined' | 'revoked'
  evidence: string
  limitations: readonly string[]
}

export interface CapsuleArtifactIndex {
  protocolVersion: string
  cliVersion: string
  catalogSha256: string
  entries: readonly ({ name: string; status: 'pilot-ready'; artifact: ReadyArtifact } | { name: string; status: 'link-only'; reason: string })[]
}

export interface SetupCapsuleArtifact {
  name: string
  artifactId: string
  verificationSha256: string
  bundleSha256: string
  payloadSha256: string
  files: number
  totalBytes: number
  source: {
    repository: string
    commit: string
    rootTreeOid: string
    rootPath: string
    pinnedUrl: string
  }
  assessment: ArtifactAssessment
  license: { spdx: string; sha256: string; installPath: string }
  evidence: string
  limitations: string[]
}

export interface SetupCapsule {
  protocolVersion: typeof SETUP_CAPSULE_VERSION
  capsuleId: string
  createdAt: string
  setup: {
    catalogProtocolVersion: string
    cliVersion: string
    catalogSha256: string
    setupSha256: string
    orderedArtifacts: SetupCapsuleArtifact[]
  }
  senderEvidence: {
    verificationProtocolVersion: typeof VERIFICATION_PROTOCOL_VERSION
    sourceReceiptPayloadSha256: string
    suiteSha256: string
    verifierSha256: string
    goalSha256: string
    environmentSha256: string
    attestation: 'local-self-attested'
    authentication: 'none'
    localValidation: 'receipt-schema-ledger-and-integrity-only'
    result: VerificationDerived
  }
  replay: {
    setup: 'exact-catalog-artifacts'
    experiment: 'unavailable-private-suite'
    artifactIds: string[]
  }
  limitations: string[]
  integrity: { algorithm: 'sha256'; payloadSha256: string }
}

export interface CapsuleValidation {
  ok: boolean
  errors: string[]
  catalogCompatible: boolean
  capsule?: SetupCapsule
}

export async function parseVerificationReceiptBytes(bytes: Uint8Array): Promise<VerificationReceipt> {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  const validation = validateVerificationReceipt(parseStrictJson(text))
  if (!validation.ok || !validation.receipt) throw new Error(validation.errors[0] ?? 'invalid receipt')
  if (!await verifyReceiptIntegrity(validation.receipt)) throw new Error('integrity mismatch')
  return validation.receipt
}

const CAPSULE_LIMITATIONS = [
  'The exact ordered catalog setup is replayable; the private verification experiment is not included.',
  'Sender evidence is local-self-attested, not SkillMOO-signed or independently authenticated.',
  'A result applies only to the sender-declared environment and does not transfer to the recipient.',
  'Offline inspection cannot assert current online revocation status.',
] as const

const isRecord = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value)
const sha = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
const keysAre = (value: Record<string, unknown>, keys: readonly string[]): boolean => {
  const actual = Object.keys(value).sort((a, b) => a.localeCompare(b, 'en'))
  const expected = [...keys].sort((a, b) => a.localeCompare(b, 'en'))
  return canonicalJson(actual) === canonicalJson(expected)
}

function without<T extends object, K extends keyof T>(value: T, key: K): Omit<T, K> {
  const copy = { ...value }
  delete copy[key]
  return copy
}

function readyArtifacts(index: CapsuleArtifactIndex): Map<string, ReadyArtifact> {
  return new Map(index.entries.flatMap((entry) => entry.status === 'pilot-ready' ? [[entry.name, entry.artifact] as const] : []))
}

export async function verificationShaForArtifact(artifact: ReadyArtifact): Promise<string> {
  const manifest = [
    { path: '.', kind: 'directory' as const, mode: artifact.manifest.rootMode },
    ...artifact.manifest.entries.map((entry) => entry.kind === 'directory'
      ? { path: entry.path, kind: 'directory' as const, mode: entry.mode }
      : { path: entry.path, kind: 'file' as const, mode: entry.mode, size: entry.size!, sha256: entry.sha256! }),
  ]
  return sha256Text(canonicalJson({ manifest }))
}

async function projectArtifact(artifact: ReadyArtifact): Promise<SetupCapsuleArtifact> {
  return {
    name: artifact.name,
    artifactId: artifact.artifactId,
    verificationSha256: await verificationShaForArtifact(artifact),
    bundleSha256: artifact.manifest.bundleSha256,
    payloadSha256: artifact.payloadSha256,
    files: artifact.manifest.files,
    totalBytes: artifact.manifest.totalBytes,
    source: {
      repository: artifact.source.repository,
      commit: artifact.source.commit,
      rootTreeOid: artifact.source.rootTreeOid,
      rootPath: artifact.source.rootPath,
      pinnedUrl: artifact.source.pinnedUrl,
    },
    assessment: { ...artifact.assessment },
    license: { spdx: artifact.license.spdx, sha256: artifact.license.sha256, installPath: artifact.license.installPath },
    evidence: artifact.evidence,
    limitations: [...artifact.limitations],
  }
}

function eligibleResult(receipt: VerificationReceipt): boolean {
  return receipt.providerKind === 'real'
    && receipt.result.runStatus === 'complete'
    && receipt.result.evidenceStatus === 'verified-here'
    && receipt.result.goalPassed === true
    && (receipt.result.experimentOutcome === 'improved' || receipt.result.experimentOutcome === 'unchanged')
}

export async function createSetupCapsule(receipt: VerificationReceipt, index: CapsuleArtifactIndex): Promise<SetupCapsule> {
  const schema = validateVerificationReceipt(receipt)
  if (!schema.ok || !schema.receipt) throw new Error(`receipt schema/ledger is invalid: ${schema.errors[0] ?? 'unknown error'}`)
  if (!await verifyReceiptIntegrity(schema.receipt)) throw new Error('receipt integrity is invalid')
  if (!eligibleResult(schema.receipt)) throw new Error('receipt is not an eligible completed, goal-passing, non-regressed real-provider result')
  const proposed = schema.receipt.setups.proposed.orderedSkills
  if (!proposed.length || proposed.length > 3) throw new Error('capsule setup must contain 1–3 ordered Skills')

  const byName = readyArtifacts(index)
  const artifacts: SetupCapsuleArtifact[] = []
  const seen = new Set<string>()
  for (const skill of proposed) {
    const key = skill.name.normalize('NFC').toLocaleLowerCase('en-US')
    if (seen.has(key)) throw new Error(`duplicate proposed Skill: ${skill.name}`)
    seen.add(key)
    const artifact = byName.get(skill.name)
    if (!artifact || artifact.availability !== 'embedded') throw new Error(`Skill is not an exact embedded catalog artifact: ${skill.name}`)
    const projected = await projectArtifact(artifact)
    if (projected.verificationSha256 !== skill.sha256 || projected.files !== skill.files) throw new Error(`receipt and catalog artifact identity differ: ${skill.name}`)
    if (artifact.assessment.grade !== skill.grade || artifact.assessment.gate !== skill.gate || artifact.assessment.risk !== skill.risk) throw new Error(`receipt and catalog assessment differ: ${skill.name}`)
    artifacts.push(projected)
  }

  const body = {
    protocolVersion: SETUP_CAPSULE_VERSION,
    createdAt: schema.receipt.completedAt,
    setup: {
      catalogProtocolVersion: index.protocolVersion,
      cliVersion: index.cliVersion,
      catalogSha256: index.catalogSha256,
      setupSha256: schema.receipt.setups.proposed.sha256,
      orderedArtifacts: artifacts,
    },
    senderEvidence: {
      verificationProtocolVersion: VERIFICATION_PROTOCOL_VERSION as typeof VERIFICATION_PROTOCOL_VERSION,
      sourceReceiptPayloadSha256: await sha256Text(canonicalJson(receiptPayload(schema.receipt))),
      suiteSha256: schema.receipt.suite.sha256,
      verifierSha256: schema.receipt.suite.verifierSha256,
      goalSha256: schema.receipt.suite.goalSha256,
      environmentSha256: schema.receipt.environment.sha256,
      attestation: 'local-self-attested' as const,
      authentication: 'none' as const,
      localValidation: 'receipt-schema-ledger-and-integrity-only' as const,
      result: { ...schema.receipt.result },
    },
    replay: {
      setup: 'exact-catalog-artifacts' as const,
      experiment: 'unavailable-private-suite' as const,
      artifactIds: artifacts.map((artifact) => artifact.artifactId),
    },
    limitations: [...CAPSULE_LIMITATIONS],
  }
  const identitySha = await sha256Text(canonicalJson(body))
  const draft = { ...body, capsuleId: `sc_${identitySha.slice(0, 32)}` }
  const payloadSha256 = await sha256Text(canonicalJson(draft))
  return { ...draft, integrity: { algorithm: 'sha256', payloadSha256 } }
}

function structurallyValidArtifact(value: unknown): value is SetupCapsuleArtifact {
  if (!isRecord(value) || !keysAre(value, ['name', 'artifactId', 'verificationSha256', 'bundleSha256', 'payloadSha256', 'files', 'totalBytes', 'source', 'assessment', 'license', 'evidence', 'limitations'])) return false
  if (typeof value.name !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value.name) || typeof value.artifactId !== 'string' || !/^sa_[a-f0-9]{32}$/.test(value.artifactId) || !sha(value.verificationSha256) || !sha(value.bundleSha256) || !sha(value.payloadSha256)) return false
  if (!Number.isSafeInteger(value.files) || Number(value.files) < 1 || Number(value.files) > 200 || !Number.isSafeInteger(value.totalBytes) || Number(value.totalBytes) < 1 || Number(value.totalBytes) > 20 * 1024 * 1024) return false
  if (!isRecord(value.source) || !keysAre(value.source, ['repository', 'commit', 'rootTreeOid', 'rootPath', 'pinnedUrl']) || typeof value.source.repository !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value.source.repository) || typeof value.source.commit !== 'string' || !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/.test(value.source.commit) || typeof value.source.rootTreeOid !== 'string' || !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/.test(value.source.rootTreeOid) || typeof value.source.rootPath !== 'string' || value.source.rootPath.includes('..') || value.source.rootPath.startsWith('/') || typeof value.source.pinnedUrl !== 'string' || !value.source.pinnedUrl.startsWith(`https://github.com/${value.source.repository}/tree/${value.source.commit}/`)) return false
  if (!isRecord(value.assessment) || !keysAre(value.assessment, ['grade', 'gate', 'risk', 'rubricVersion', 'vector', 'uninterpretedFiles']) || !['A', 'B'].includes(String(value.assessment.grade)) || value.assessment.gate !== 'pass' || value.assessment.risk !== 'low' || typeof value.assessment.rubricVersion !== 'string' || !value.assessment.rubricVersion.startsWith('skillmoo-static/') || typeof value.assessment.vector !== 'string' || !value.assessment.vector.startsWith('SMV:') || !Number.isSafeInteger(value.assessment.uninterpretedFiles) || Number(value.assessment.uninterpretedFiles) < 0 || Number(value.assessment.uninterpretedFiles) > Number(value.files)) return false
  if (!isRecord(value.license) || !keysAre(value.license, ['spdx', 'sha256', 'installPath']) || value.license.spdx !== 'MIT' || !sha(value.license.sha256) || value.license.installPath !== 'LICENSE.upstream.txt') return false
  return value.evidence === 'inspected-exact-version' && Array.isArray(value.limitations) && value.limitations.length > 0 && value.limitations.length <= 10 && value.limitations.every((item) => typeof item === 'string' && item.length > 0 && item.length <= 500)
}

function structurallyValidResult(value: unknown): value is VerificationDerived {
  if (!isRecord(value) || !keysAre(value, ['runStatus', 'evidenceStatus', 'experimentOutcome', 'goalPassed', 'baselinePassRate', 'proposedPassRate', 'liftPoints', 'baselineAvgTokens', 'proposedAvgTokens', 'tokenDeltaPct', 'baselineAvgDurationMs', 'proposedAvgDurationMs', 'durationDeltaPct'])) return false
  if (value.runStatus !== 'complete' || value.evidenceStatus !== 'verified-here' || (value.experimentOutcome !== 'improved' && value.experimentOutcome !== 'unchanged') || value.goalPassed !== true) return false
  const numeric = ['baselinePassRate', 'proposedPassRate', 'liftPoints', 'baselineAvgTokens', 'proposedAvgTokens', 'tokenDeltaPct', 'baselineAvgDurationMs', 'proposedAvgDurationMs', 'durationDeltaPct'] as const
  if (numeric.some((key) => typeof value[key] !== 'number' || !Number.isFinite(value[key]))) return false
  const round = (number: number) => Number(number.toFixed(3))
  const delta = (baseline: number, proposed: number) => baseline ? round(((proposed - baseline) / baseline) * 100) : 0
  const baselinePass = Number(value.baselinePassRate), proposedPass = Number(value.proposedPassRate), lift = Number(value.liftPoints)
  const baselineTokens = Number(value.baselineAvgTokens), proposedTokens = Number(value.proposedAvgTokens)
  const baselineDuration = Number(value.baselineAvgDurationMs), proposedDuration = Number(value.proposedAvgDurationMs)
  return baselinePass >= 0 && proposedPass >= 0 && proposedPass <= 100
    && baselineTokens >= 0 && proposedTokens >= 0 && baselineDuration >= 0 && proposedDuration >= 0
    && lift === round(proposedPass - baselinePass) && lift >= 0 && baselinePass < 95
    && ((value.experimentOutcome === 'improved' && lift > 0) || (value.experimentOutcome === 'unchanged' && lift === 0))
    && Number(value.tokenDeltaPct) === delta(baselineTokens, proposedTokens)
    && Number(value.durationDeltaPct) === delta(baselineDuration, proposedDuration)
}

export async function validateSetupCapsule(raw: unknown, index: CapsuleArtifactIndex): Promise<CapsuleValidation> {
  const errors: string[] = []
  if (!isRecord(raw)) return { ok: false, errors: ['capsule must be a JSON object'], catalogCompatible: false }
  if (!keysAre(raw, ['protocolVersion', 'capsuleId', 'createdAt', 'setup', 'senderEvidence', 'replay', 'limitations', 'integrity'])) errors.push('capsule contains missing or unknown top-level fields')
  if (raw.protocolVersion !== SETUP_CAPSULE_VERSION) errors.push(`protocolVersion must be ${SETUP_CAPSULE_VERSION}`)
  if (typeof raw.capsuleId !== 'string' || !/^sc_[a-f0-9]{32}$/.test(raw.capsuleId)) errors.push('capsuleId is invalid')
  if (typeof raw.createdAt !== 'string' || !Number.isFinite(Date.parse(raw.createdAt))) errors.push('createdAt is invalid')
  if (!isRecord(raw.setup) || !keysAre(raw.setup, ['catalogProtocolVersion', 'cliVersion', 'catalogSha256', 'setupSha256', 'orderedArtifacts']) || !sha(raw.setup.catalogSha256) || !sha(raw.setup.setupSha256) || typeof raw.setup.catalogProtocolVersion !== 'string' || typeof raw.setup.cliVersion !== 'string' || !Array.isArray(raw.setup.orderedArtifacts) || raw.setup.orderedArtifacts.length < 1 || raw.setup.orderedArtifacts.length > 3 || !raw.setup.orderedArtifacts.every(structurallyValidArtifact)) errors.push('setup projection is invalid')
  if (!isRecord(raw.senderEvidence) || !keysAre(raw.senderEvidence, ['verificationProtocolVersion', 'sourceReceiptPayloadSha256', 'suiteSha256', 'verifierSha256', 'goalSha256', 'environmentSha256', 'attestation', 'authentication', 'localValidation', 'result']) || raw.senderEvidence.verificationProtocolVersion !== VERIFICATION_PROTOCOL_VERSION || !sha(raw.senderEvidence.sourceReceiptPayloadSha256) || !sha(raw.senderEvidence.suiteSha256) || !sha(raw.senderEvidence.verifierSha256) || !sha(raw.senderEvidence.goalSha256) || !sha(raw.senderEvidence.environmentSha256) || raw.senderEvidence.attestation !== 'local-self-attested' || raw.senderEvidence.authentication !== 'none' || raw.senderEvidence.localValidation !== 'receipt-schema-ledger-and-integrity-only' || !structurallyValidResult(raw.senderEvidence.result)) errors.push('sender evidence projection is invalid')
  if (!isRecord(raw.replay) || !keysAre(raw.replay, ['setup', 'experiment', 'artifactIds']) || raw.replay.setup !== 'exact-catalog-artifacts' || raw.replay.experiment !== 'unavailable-private-suite' || !Array.isArray(raw.replay.artifactIds) || raw.replay.artifactIds.some((id) => typeof id !== 'string')) errors.push('replay state is invalid')
  if (!Array.isArray(raw.limitations) || canonicalJson(raw.limitations) !== canonicalJson(CAPSULE_LIMITATIONS)) errors.push('capsule limitations are invalid')
  if (!isRecord(raw.integrity) || !keysAre(raw.integrity, ['algorithm', 'payloadSha256']) || raw.integrity.algorithm !== 'sha256' || !sha(raw.integrity.payloadSha256)) errors.push('integrity is invalid')
  if (errors.length) return { ok: false, errors, catalogCompatible: false }

  const capsule = raw as unknown as SetupCapsule
  const identityBody = without(without(capsule, 'integrity'), 'capsuleId')
  const [identitySha, payloadSha] = await Promise.all([
    sha256Text(canonicalJson(identityBody)),
    sha256Text(canonicalJson(without(capsule, 'integrity'))),
  ])
  if (capsule.capsuleId !== `sc_${identitySha.slice(0, 32)}`) errors.push('capsuleId does not match canonical content')
  if (capsule.integrity.payloadSha256 !== payloadSha) errors.push('capsule integrity does not match canonical content')
  const artifacts = capsule.setup.orderedArtifacts
  if (new Set(artifacts.map((item) => item.name)).size !== artifacts.length || new Set(artifacts.map((item) => item.artifactId)).size !== artifacts.length) errors.push('capsule artifacts must be unique')
  if (canonicalJson(capsule.replay.artifactIds) !== canonicalJson(artifacts.map((item) => item.artifactId))) errors.push('replay artifact order differs from setup order')
  const verificationSetupSha = await sha256Text(canonicalJson(artifacts.map((item) => ({
    name: item.name,
    sha256: item.verificationSha256,
    files: item.files,
    grade: item.assessment.grade,
    gate: item.assessment.gate,
    risk: item.assessment.risk,
  }))))
  if (capsule.setup.setupSha256 !== verificationSetupSha) errors.push('setup identity differs from the ordered artifact bridge')

  const compatible = capsule.setup.catalogProtocolVersion === index.protocolVersion && capsule.setup.cliVersion === index.cliVersion && capsule.setup.catalogSha256 === index.catalogSha256
  if (compatible) {
    const byName = readyArtifacts(index)
    for (const projected of artifacts) {
      const artifact = byName.get(projected.name)
      if (!artifact || artifact.availability !== 'embedded') { errors.push(`artifact is unavailable in this catalog: ${projected.name}`); continue }
      const expected = await projectArtifact(artifact)
      if (canonicalJson(projected) !== canonicalJson(expected)) errors.push(`artifact projection differs from this catalog: ${projected.name}`)
    }
  }
  return { ok: errors.length === 0, errors, catalogCompatible: compatible, ...(errors.length ? {} : { capsule }) }
}
