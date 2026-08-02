import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { ARTIFACT_INDEX } from '../src/data/artifactIndex'
import { ARTIFACT_PAYLOADS } from '../cli/artifactPayloads'
import {
  SETUP_CAPSULE_VERSION,
  createSetupCapsule,
  parseVerificationReceiptBytes,
  validateSetupCapsule,
  verificationShaForArtifact,
  type CapsuleArtifactIndex,
  type SetupCapsule,
} from '../src/lib/setupCapsule'
import {
  VERIFICATION_PROTOCOL_VERSION,
  VERIFICATION_RUNNER_VERSION,
  canonicalJson,
  deriveVerificationResult,
  receiptPayload,
  sha256Text,
  type VerificationEnvironmentIdentity,
  type VerificationObservation,
  type VerificationReceipt,
} from '../src/lib/verificationProtocol'
import { inspectSetupCapsule, prepareCapsuleSetup, runCapsuleCommand } from '../cli/capsule'
import { parseStrictJson } from '../src/lib/strictJson'

let passed = 0
const failures: string[] = []
const ok = (condition: unknown, name: string) => condition ? passed++ : failures.push(name)

const index = ARTIFACT_INDEX as unknown as CapsuleArtifactIndex
const ready = index.entries.find((entry) => entry.status === 'pilot-ready')
if (!ready || ready.status !== 'pilot-ready') throw new Error('capsule fixture requires a ready artifact')
const artifact = ready.artifact
const proposedSkillSha = await verificationShaForArtifact(artifact)
const baselineSkills: VerificationReceipt['setups']['baseline']['orderedSkills'] = []
const proposedSkills: VerificationReceipt['setups']['proposed']['orderedSkills'] = [{
  name: artifact.name,
  sha256: proposedSkillSha,
  files: artifact.manifest.files,
  grade: artifact.assessment.grade,
  gate: artifact.assessment.gate,
  risk: artifact.assessment.risk,
}]
const baselineSha = await sha256Text(canonicalJson(baselineSkills))
const proposedSha = await sha256Text(canonicalJson(proposedSkills))
const environmentPayload: Omit<VerificationEnvironmentIdentity, 'sha256'> = {
  adapter: 'openai-compatible-chat', runnerVersion: VERIFICATION_RUNNER_VERSION,
  providerOrigin: 'https://api.example.test', model: 'fixture-model', node: '22.0.0', os: 'darwin', arch: 'arm64',
  temperature: 0, maxTokens: 128, timeoutMs: 30_000, trials: 3, seeds: [1, 2, 3],
}
const environmentSha = await sha256Text(canonicalJson(environmentPayload))
const suiteSha = 'a'.repeat(64), verifierSha = 'b'.repeat(64), goalSha = 'c'.repeat(64)
const observations: VerificationObservation[] = []
for (const seed of [1, 2, 3]) {
  observations.push({ taskId: 'private-task', seed, arm: 'baseline', status: 'ok', pass: false, tokens: 10, durationMs: 20, suiteSha256: suiteSha, environmentSha256: environmentSha, setupSha256: baselineSha })
  observations.push({ taskId: 'private-task', seed, arm: 'proposed', status: 'ok', pass: true, tokens: 12, durationMs: 25, suiteSha256: suiteSha, environmentSha256: environmentSha, setupSha256: proposedSha })
}
const result = deriveVerificationResult('real', 0.8, observations)
const invocationId = '00000000-0000-4000-8000-000000000100'
const completedAt = '2026-08-02T10:00:01.000Z'
const receiptIdSha = await sha256Text(canonicalJson({ invocationId, completedAt, suite: suiteSha, baseline: baselineSha, proposed: proposedSha, environment: environmentSha }))
const draft: VerificationReceipt = {
  protocolVersion: VERIFICATION_PROTOCOL_VERSION,
  receiptId: `vr_${receiptIdSha.slice(0, 24)}`,
  invocationId,
  startedAt: '2026-08-02T10:00:00.000Z', completedAt,
  attestation: 'local-self-attested', providerKind: 'real',
  suite: { sha256: suiteSha, verifierSha256: verifierSha, goalSha256: goalSha, title: 'PRIVATE-GOAL-CANARY', taskIds: ['private-task'], goalPassRate: 0.8 },
  setups: { baseline: { sha256: baselineSha, orderedSkills: baselineSkills }, proposed: { sha256: proposedSha, orderedSkills: proposedSkills } },
  environment: { sha256: environmentSha, ...environmentPayload }, observations, result,
  limitations: ['PRIVATE-LIMITATION-CANARY'], integrity: { algorithm: 'sha256', payloadSha256: '0'.repeat(64) },
}
const receipt: VerificationReceipt = { ...draft, integrity: { algorithm: 'sha256', payloadSha256: await sha256Text(canonicalJson(receiptPayload(draft))) } }

async function sealReceipt(value: VerificationReceipt): Promise<VerificationReceipt> {
  const baselineSha = await sha256Text(canonicalJson(value.setups.baseline.orderedSkills))
  const proposedSha = await sha256Text(canonicalJson(value.setups.proposed.orderedSkills))
  const { sha256: _environmentSha, ...environmentPayload } = value.environment
  const environmentSha = await sha256Text(canonicalJson(environmentPayload))
  const sealedObservations = value.observations.map((item) => ({
    ...item,
    suiteSha256: value.suite.sha256,
    environmentSha256: environmentSha,
    setupSha256: item.arm === 'baseline' ? baselineSha : proposedSha,
  }))
  const sealedResult = deriveVerificationResult(value.providerKind, value.suite.goalPassRate, sealedObservations)
  const receiptIdSha = await sha256Text(canonicalJson({ invocationId: value.invocationId, completedAt: value.completedAt, suite: value.suite.sha256, baseline: baselineSha, proposed: proposedSha, environment: environmentSha }))
  const sealedDraft: VerificationReceipt = {
    ...value,
    receiptId: `vr_${receiptIdSha.slice(0, 24)}`,
    setups: {
      baseline: { sha256: baselineSha, orderedSkills: value.setups.baseline.orderedSkills },
      proposed: { sha256: proposedSha, orderedSkills: value.setups.proposed.orderedSkills },
    },
    environment: { sha256: environmentSha, ...environmentPayload },
    observations: sealedObservations,
    result: sealedResult,
    integrity: { algorithm: 'sha256', payloadSha256: '0'.repeat(64) },
  }
  return { ...sealedDraft, integrity: { algorithm: 'sha256', payloadSha256: await sha256Text(canonicalJson(receiptPayload(sealedDraft))) } }
}

async function resealCapsule(value: SetupCapsule): Promise<SetupCapsule> {
  const { integrity: _integrity, capsuleId: _capsuleId, ...body } = value
  const identitySha = await sha256Text(canonicalJson(body))
  const capsuleId = `sc_${identitySha.slice(0, 32)}`
  const payload = { ...body, capsuleId }
  return { ...payload, integrity: { algorithm: 'sha256', payloadSha256: await sha256Text(canonicalJson(payload)) } } as SetupCapsule
}

const capsuleA = await createSetupCapsule(receipt, index)
const capsuleB = await createSetupCapsule(receipt, index)
ok(capsuleA.protocolVersion === SETUP_CAPSULE_VERSION && canonicalJson(capsuleA) === canonicalJson(capsuleB), 'same receipt and catalog produce byte-identical semantic capsule')
ok(capsuleA.createdAt === completedAt && /^sc_[a-f0-9]{32}$/.test(capsuleA.capsuleId), 'capsule identity is deterministic and receipt-timestamped')
ok((await validateSetupCapsule(capsuleA, index)).ok, 'generated capsule validates')
const serialized = JSON.stringify(capsuleA)
for (const canary of ['PRIVATE-GOAL-CANARY', 'private-task', 'PRIVATE-LIMITATION-CANARY', 'fixture-model', 'https://api.example.test', invocationId, receipt.receiptId]) ok(!serialized.includes(canary), `capsule excludes private canary: ${canary}`)
ok(capsuleA.replay.setup === 'exact-catalog-artifacts' && capsuleA.replay.experiment === 'unavailable-private-suite', 'setup and experiment replay states remain separate')
ok(capsuleA.senderEvidence.attestation === 'local-self-attested' && capsuleA.senderEvidence.authentication === 'none', 'capsule cannot imply platform authentication')

const tampered = structuredClone(capsuleA)
tampered.setup.orderedArtifacts[0]!.assessment.grade = 'F'
ok(!(await validateSetupCapsule(tampered, index)).ok, 'capsule mutation breaks validation')
const forgedSetup = structuredClone(capsuleA)
forgedSetup.setup.setupSha256 = 'f'.repeat(64)
ok(!(await validateSetupCapsule(await resealCapsule(forgedSetup), index)).ok, 'resealed setup identity drift is rejected')
const impossibleResult = structuredClone(capsuleA)
impossibleResult.senderEvidence.result = { ...impossibleResult.senderEvidence.result, baselinePassRate: 100, proposedPassRate: 0, liftPoints: 999, experimentOutcome: 'improved' }
ok(!(await validateSetupCapsule(await resealCapsule(impossibleResult), index)).ok, 'resealed arithmetically impossible sender result is rejected')
const unknown = { ...capsuleA, certificate: true }
ok(!(await validateSetupCapsule(unknown, index)).ok, 'unknown top-level claims are rejected')
const resultUnknown = structuredClone(capsuleA) as SetupCapsule & { senderEvidence: SetupCapsule['senderEvidence'] & { result: VerificationReceipt['result'] & { certified?: boolean } } }
resultUnknown.senderEvidence.result.certified = true
ok(!(await validateSetupCapsule(resultUnknown, index)).ok, 'unknown nested result claims are rejected')
const incompatibleIndex = { ...index, cliVersion: '99.0.0' }
const incompatible = await validateSetupCapsule(capsuleA, incompatibleIndex)
ok(incompatible.ok && !incompatible.catalogCompatible, 'valid capsule remains inspectable when local catalog differs')
let strictTopLevel = false, strictNested = false
try { parseStrictJson('{"a":1,"a":2}') } catch { strictTopLevel = true }
try { parseStrictJson('{"outer":{"a":1,"a":2}}') } catch { strictNested = true }
ok(strictTopLevel && strictNested, 'shared Web/CLI strict JSON rejects top-level and nested duplicate keys')
let webDuplicateRejected = false, webUtf8Rejected = false
try { await parseVerificationReceiptBytes(new TextEncoder().encode(JSON.stringify(receipt).replace('{', '{"protocolVersion":"duplicate",'))) } catch { webDuplicateRejected = true }
try { await parseVerificationReceiptBytes(new Uint8Array([0xff, 0xfe, 0x7b, 0x7d])) } catch { webUtf8Rejected = true }
ok(webDuplicateRejected && webUtf8Rejected, 'Web receipt ingestion rejects duplicate keys and invalid UTF-8')

const goalFailureObservations = receipt.observations.map((item) => item.arm === 'proposed' && item.seed === 3 ? { ...item, pass: false } : item)
const validGoalFailure = await sealReceipt({ ...receipt, observations: goalFailureObservations })
let goalFailureRejected = false
try { await createSetupCapsule(validGoalFailure, index) } catch { goalFailureRejected = true }
ok(goalFailureRejected, 'integrity-correct goal-failed receipt is ineligible')
const regressedObservations = receipt.observations.map((item) => ({ ...item, pass: item.arm === 'baseline' }))
const validRegression = await sealReceipt({ ...receipt, observations: regressedObservations })
let validRegressionRejected = false
try { await createSetupCapsule(validRegression, index) } catch { validRegressionRejected = true }
ok(validRegressionRejected, 'integrity-correct regressed receipt is ineligible')
const validIdentityDrift = await sealReceipt({ ...receipt, setups: { ...receipt.setups, proposed: { ...receipt.setups.proposed, orderedSkills: [{ ...proposedSkills[0]!, sha256: 'f'.repeat(64) }] } } })
let validIdentityDriftRejected = false
try { await createSetupCapsule(validIdentityDrift, index) } catch { validIdentityDriftRejected = true }
ok(validIdentityDriftRejected, 'integrity-correct artifact identity drift is rejected')

const threeReady = index.entries.filter((entry): entry is Extract<(typeof index.entries)[number], { status: 'pilot-ready' }> => entry.status === 'pilot-ready').slice(0, 3)
const threeSkills = await Promise.all(threeReady.map(async ({ artifact }) => ({ name: artifact.name, sha256: await verificationShaForArtifact(artifact), files: artifact.manifest.files, grade: artifact.assessment.grade, gate: artifact.assessment.gate, risk: artifact.assessment.risk })))
const threeReceipt = await sealReceipt({ ...receipt, setups: { ...receipt.setups, proposed: { ...receipt.setups.proposed, orderedSkills: threeSkills } } })
const threeCapsule = await createSetupCapsule(threeReceipt, index)
ok(canonicalJson(threeCapsule.setup.orderedArtifacts.map((item) => item.name)) === canonicalJson(threeSkills.map((item) => item.name)), 'three-artifact capsule preserves proposed order')
const reversedReceipt = await sealReceipt({ ...threeReceipt, setups: { ...threeReceipt.setups, proposed: { ...threeReceipt.setups.proposed, orderedSkills: [...threeSkills].reverse() } } })
const reversedCapsule = await createSetupCapsule(reversedReceipt, index)
ok(reversedCapsule.capsuleId !== threeCapsule.capsuleId && canonicalJson(reversedCapsule.setup.orderedArtifacts.map((item) => item.name)) === canonicalJson([...threeSkills].reverse().map((item) => item.name)), 'changing artifact order changes identity and preserves new order')
const duplicateReceipt = await sealReceipt({ ...receipt, setups: { ...receipt.setups, proposed: { ...receipt.setups.proposed, orderedSkills: [proposedSkills[0]!, proposedSkills[0]!] } } })
let duplicateSkillRejected = false
try { await createSetupCapsule(duplicateReceipt, index) } catch { duplicateSkillRejected = true }
ok(duplicateSkillRejected, 'integrity-correct duplicate Skill setup is rejected')

for (const [name, changed] of [
  ['simulation', { ...receipt, providerKind: 'simulated' as const }],
  ['goal failure', { ...receipt, result: { ...receipt.result, goalPassed: false } }],
  ['regression', { ...receipt, result: { ...receipt.result, experimentOutcome: 'regressed' as const } }],
  ['identity drift', { ...receipt, setups: { ...receipt.setups, proposed: { ...receipt.setups.proposed, orderedSkills: [{ ...proposedSkills[0]!, sha256: 'f'.repeat(64) }] } } }],
] as const) {
  let rejected = false
  try { await createSetupCapsule(changed as VerificationReceipt, index) } catch { rejected = true }
  ok(rejected, `${name} receipt is rejected`)
}

const temp = mkdtempSync(join(tmpdir(), 'skillmoo-capsule-test-'))
const keepFixture = process.env.SKILLMOO_KEEP_CAPSULE_FIXTURE === '1'
try {
  const receiptPath = join(temp, 'receipt.json'), capsulePath = join(temp, 'capsule.json')
  writeFileSync(receiptPath, JSON.stringify(receipt))
  ok(await runCapsuleCommand(['create', '--receipt', receiptPath, '--out', capsulePath]) === 0, 'CLI creates capsule')
  const cliCapsule = JSON.parse(readFileSync(capsulePath, 'utf8'))
  ok(canonicalJson(cliCapsule) === canonicalJson(capsuleA), 'CLI and shared Web-safe core produce identical capsule')
  const beforeInspect = canonicalJson(readdirSync(temp))
  const inspected = await inspectSetupCapsule(capsulePath)
  ok(inspected.compatible && canonicalJson(readdirSync(temp)) === beforeInspect, 'inspect validates without filesystem writes')

  const duplicatePath = join(temp, 'duplicate.json')
  writeFileSync(duplicatePath, '{"protocolVersion":"x","protocolVersion":"y"}')
  ok(await runCapsuleCommand(['inspect', '--capsule', duplicatePath]) !== 0, 'CLI rejects duplicate JSON object keys')
  const utf8Path = join(temp, 'invalid-utf8.json')
  writeFileSync(utf8Path, Buffer.from([0xff, 0xfe, 0x7b, 0x7d]))
  ok(await runCapsuleCommand(['inspect', '--capsule', utf8Path]) !== 0, 'CLI rejects invalid UTF-8 before JSON parsing')
  const fifoPath = join(temp, 'input.fifo')
  if (spawnSync('mkfifo', [fifoPath]).status === 0) ok(await runCapsuleCommand(['inspect', '--capsule', fifoPath]) !== 0, 'CLI rejects FIFO input without blocking')

  const scope = join(temp, 'scope'), targetRoot = join(scope, '.claude', 'skills'), cacheRoot = join(temp, 'cache'), planPath = join(temp, 'plan.json')
  mkdirSync(targetRoot, { recursive: true }); mkdirSync(cacheRoot, { mode: 0o700 })
  const targetBefore = canonicalJson(readdirSync(targetRoot))
  const prepared = await prepareCapsuleSetup({ capsulePath, targetRoot, planPath, projectRoot: scope, cacheRoot, payloads: ARTIFACT_PAYLOADS })
  ok(prepared.plan.actions.length === 1 && canonicalJson(readdirSync(targetRoot)) === targetBefore, 'prepare writes an immutable plan/cache but does not mutate Agent root')
  ok(prepared.plan.actions[0]?.source.bundleSha256 === artifact.manifest.bundleSha256, 'prepared source is the exact capsule artifact')
} finally {
  if (keepFixture) console.log(`capsule fixture retained: ${temp}`)
  else rmSync(temp, { recursive: true, force: true })
}

if (failures.length) {
  console.error(`capsule evaluation failed (${failures.length}):`)
  for (const failure of failures) console.error(`- ${failure}`)
  process.exitCode = 1
} else console.log(`capsule evaluation passed (${passed} checks)`)
