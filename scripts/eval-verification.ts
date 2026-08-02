import {
  VERIFICATION_PROTOCOL_VERSION,
  VERIFICATION_RUNNER_VERSION,
  VERIFICATION_SUITE_VERSION,
  canonicalJson,
  deriveVerificationResult,
  gradeVerificationOutput,
  parseVerificationSuite,
  receiptPayload,
  sha256Text,
  summarizeVerificationReceipts,
  validateVerificationReceipt,
  verifyReceiptIntegrity,
  type VerificationObservation,
  type VerificationReceipt,
  type VerificationEnvironmentIdentity,
} from '../src/lib/verificationProtocol'
import {
  createVerificationEnvironment,
  createOpenAICompatibleChat,
  loadVerificationSetup,
  persistVerificationReceipt,
  readVerificationSummary,
  runPairedVerification,
  runVerifyCommand,
} from '../cli/verify'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

let passed = 0
const failures: string[] = []
const ok = (condition: unknown, name: string) => {
  if (condition) passed++
  else failures.push(name)
}

const suiteRaw = {
  version: VERIFICATION_SUITE_VERSION,
  title: 'Strict extraction',
  goal: 'Return machine-readable order data',
  baseSystem: 'You are a helpful assistant.',
  goalPassRate: 0.8,
  tasks: [
    { id: 'order', prompt: 'Return order 42 as JSON.', check: { kind: 'json-equals', value: { order: 42 } } },
  ],
}

const parsed = parseVerificationSuite(suiteRaw)
ok(parsed.ok, 'valid suite parses')
ok(!parseVerificationSuite({ ...suiteRaw, tasks: [...suiteRaw.tasks, suiteRaw.tasks[0]] }).ok, 'duplicate task ids rejected')
ok(!parseVerificationSuite({ ...suiteRaw, tasks: [{ id: 'x', prompt: 'x', check: { kind: 'regex', value: '.*' } }] }).ok, 'arbitrary regex grader rejected')
ok(!parseVerificationSuite({ ...suiteRaw, tasks: [] }).ok, 'empty suite rejected')
ok(!parseVerificationSuite({ ...suiteRaw, goalPassRate: 0 }).ok, 'zero goal threshold rejected')
ok(gradeVerificationOutput({ kind: 'exact', value: 'yes' }, ' yes\n'), 'exact grader normalizes edges')
ok(gradeVerificationOutput({ kind: 'json-equals', value: { b: 2, a: 1 } }, '{"a":1,"b":2}'), 'JSON grader is key-order independent')
ok(!gradeVerificationOutput({ kind: 'json-equals', value: { a: 1 } }, '```json\n{"a":1}\n```'), 'JSON grader rejects fenced output')
ok(gradeVerificationOutput({ kind: 'contains', all: ['alpha'], none: ['secret'] }, 'Alpha result'), 'contains grader applies required and forbidden terms')

const shaA = 'a'.repeat(64)
const skillSha = 'd'.repeat(64)
const baselineSkills: VerificationReceipt['setups']['baseline']['orderedSkills'] = []
const proposedSkills: VerificationReceipt['setups']['proposed']['orderedSkills'] = [{ name: 'json-output', sha256: skillSha, files: 1, grade: 'A', gate: 'pass', risk: 'low' }]
const shaC = await sha256Text(canonicalJson(baselineSkills))
const shaD = await sha256Text(canonicalJson(proposedSkills))
const environmentPayload: Omit<VerificationEnvironmentIdentity, 'sha256'> = {
  adapter: 'openai-compatible-chat' as const,
  runnerVersion: VERIFICATION_RUNNER_VERSION,
  providerOrigin: 'https://api.example.test',
  model: 'test-model',
  node: '22.0.0',
  os: 'darwin',
  arch: 'arm64',
  temperature: 0,
  maxTokens: 256,
  timeoutMs: 30_000,
  trials: 3,
  seeds: [1, 2, 3],
}
const shaB = await sha256Text(canonicalJson(environmentPayload))
const observations: VerificationObservation[] = []
for (const seed of [1, 2, 3]) {
  observations.push({ taskId: 'order', seed, arm: 'baseline', status: 'ok', pass: seed === 1, tokens: 10, durationMs: 20, suiteSha256: shaA, environmentSha256: shaB, setupSha256: shaC })
  observations.push({ taskId: 'order', seed, arm: 'proposed', status: 'ok', pass: true, tokens: 12, durationMs: 25, suiteSha256: shaA, environmentSha256: shaB, setupSha256: shaD })
}

const realResult = deriveVerificationResult('real', 0.8, observations)
ok(realResult.evidenceStatus === 'verified-here' && realResult.experimentOutcome === 'improved' && realResult.goalPassed === true, 'complete real pair becomes verified improved goal success')
const simulatedResult = deriveVerificationResult('simulated', 0.8, observations)
ok(simulatedResult.evidenceStatus === 'inspected' && simulatedResult.experimentOutcome === 'inconclusive' && simulatedResult.goalPassed === 'unknown', 'simulation never becomes verified evidence')
const errored = observations.map((x, i) => i === 0 ? { ...x, status: 'provider-error' as const, pass: false, errorCode: 'provider-error' as const } : x)
ok(deriveVerificationResult('real', 0.8, errored).experimentOutcome === 'error', 'provider error is not a task failure')
const ceiling = observations.map((x) => ({ ...x, pass: true }))
ok(deriveVerificationResult('real', 0.8, ceiling).experimentOutcome === 'inconclusive', 'ceiling baseline withholds causal lift claim')
const ceilingRegression = observations.map((x) => ({ ...x, pass: x.arm === 'baseline' }))
ok(deriveVerificationResult('real', 0.3, ceilingRegression).experimentOutcome === 'regressed', 'material regression is not hidden by the baseline ceiling rule')

const fixtureInvocationId = '00000000-0000-4000-8000-000000000001'
const fixtureCompletedAt = '2026-08-02T00:00:01.000Z'
const fixtureReceiptHash = await sha256Text(canonicalJson({ invocationId: fixtureInvocationId, completedAt: fixtureCompletedAt, suite: shaA, baseline: shaC, proposed: shaD, environment: shaB }))
const receiptBase: VerificationReceipt = {
  protocolVersion: VERIFICATION_PROTOCOL_VERSION,
  receiptId: `vr_${fixtureReceiptHash.slice(0, 24)}`,
  invocationId: fixtureInvocationId,
  startedAt: '2026-08-02T00:00:00.000Z',
  completedAt: fixtureCompletedAt,
  attestation: 'local-self-attested',
  providerKind: 'real',
  suite: { sha256: shaA, verifierSha256: shaA, goalSha256: shaB, title: 'Strict extraction', taskIds: ['order'], goalPassRate: 0.8 },
  setups: {
    baseline: { sha256: shaC, orderedSkills: baselineSkills },
    proposed: { sha256: shaD, orderedSkills: proposedSkills },
  },
  environment: { sha256: shaB, ...environmentPayload },
  observations,
  result: realResult,
  limitations: ['Applies only to this declared environment.'],
  integrity: { algorithm: 'sha256', payloadSha256: shaA },
}

const integrityHash = await sha256Text(canonicalJson(receiptPayload(receiptBase)))
const receipt: VerificationReceipt = { ...receiptBase, integrity: { algorithm: 'sha256', payloadSha256: integrityHash } }
ok(validateVerificationReceipt(receipt).ok, 'complete receipt schema and ledger validate')
ok(await verifyReceiptIntegrity(receipt), 'receipt integrity validates')
ok(!await verifyReceiptIntegrity({ ...receipt, limitations: ['tampered'] }), 'receipt mutation breaks integrity')
const reboundEnvironment = { ...receipt.environment, model: 'different-model' }
const reboundDraft = { ...receipt, environment: reboundEnvironment }
const reboundIntegrity = await sha256Text(canonicalJson(receiptPayload(reboundDraft)))
ok(!await verifyReceiptIntegrity({ ...reboundDraft, integrity: { algorithm: 'sha256', payloadSha256: reboundIntegrity } }), 'environment identity must match its disclosed fields even after payload rehash')
ok(!validateVerificationReceipt({ ...receipt, observations: observations.slice(1) }).ok, 'one-sided/incomplete ledger rejected')
ok(!validateVerificationReceipt({ ...receipt, observations: observations.map((x, i) => i === 0 ? { ...x, arm: 'shadow' } : x) }).ok, 'unknown arm cannot substitute for a paired baseline or proposed observation')
ok(!validateVerificationReceipt({ ...receipt, observations: observations.map((x, i) => i === 0 ? { ...x, environmentSha256: shaD } : x) }).ok, 'arm environment drift rejected')
ok(!validateVerificationReceipt({ ...receipt, setups: { baseline: receipt.setups.baseline, proposed: { ...receipt.setups.proposed, sha256: receipt.setups.baseline.sha256 } } }).ok, 'identical setup identities rejected')
ok(!validateVerificationReceipt({ ...receipt, raw: { prompt: 'secret task' } }).ok, 'raw prompt field rejected')
ok(!validateVerificationReceipt({ ...receipt, limitations: {} }).ok, 'non-array limitations rejected before Web rendering')
ok(!validateVerificationReceipt({ ...receipt, limitations: [`${' '.repeat(501)}x`] }).ok, 'raw padded limitations cannot bypass display length limits')
ok(!validateVerificationReceipt({ ...receipt, environment: { ...receipt.environment, model: '' } }).ok, 'empty environment identity fields rejected')
ok(!validateVerificationReceipt({ ...receipt, environment: { ...receipt.environment, providerOrigin: 'simulation://local', model: 'deterministic-harness-stub' } }).ok, 'real receipts cannot reuse simulation environment markers')
ok(!validateVerificationReceipt({ ...receipt, environment: { ...receipt.environment, providerOrigin: 'https://user:password@example.test/v1?api_key=secret#x' } }).ok, 'receipt provider identity cannot contain credentials, query strings, or fragments')
ok(!validateVerificationReceipt({ ...receipt, result: { ...receipt.result, goalPassed: false } }).ok, 'derived result tamper rejected')

const errorMetricReceipt = { ...receipt, receiptId: `vr_${'2'.repeat(24)}`, invocationId: '00000000-0000-4000-8000-000000000002', result: { ...receipt.result, runStatus: 'error' as const, evidenceStatus: 'inspected' as const, experimentOutcome: 'error' as const, goalPassed: 'unknown' as const } }
const simulatedMetricReceipt = { ...receipt, receiptId: `vr_${'3'.repeat(24)}`, invocationId: '00000000-0000-4000-8000-000000000003', providerKind: 'simulated' as const, result: simulatedResult }
const metric = summarizeVerificationReceipts([
  receipt,
  receipt,
  errorMetricReceipt,
  simulatedMetricReceipt,
], 2, 3)
ok(metric.validRealAttempts === 2 && metric.verifiedGoalSuccesses === 1 && metric.localVssrPct === 50, 'local VSSR keeps started errors in denominator')
ok(metric.simulations === 1 && metric.invalidFiles === 2 && metric.duplicateFiles === 1 && metric.skippedFiles === 3, 'metric excludes duplicate receipts and discloses invalid, duplicate, and skipped files')

const temp = mkdtempSync(join(tmpdir(), 'skillmoo-verification-test-'))
try {
  const skillDir = join(temp, 'json-output')
  const refDir = join(skillDir, 'references')
  mkdirSync(refDir, { recursive: true })
  const skillPath = join(skillDir, 'SKILL.md')
  const privateInstruction = 'PRIVATE-SKILL-CONTENT-DO-NOT-PERSIST'
  writeFileSync(skillPath, `---\nname: json-output\ndescription: Return exact machine-readable JSON without prose. Use when the user explicitly asks for strict JSON output.\n---\n\n# JSON output\n\n${privateInstruction}\n\nReturn only the requested JSON object.\nRead references/format.md for the output rules.\n`)
  writeFileSync(join(refDir, 'format.md'), 'Never wrap JSON in a Markdown fence.\n')
  const baselineSetup = await loadVerificationSetup([])
  const proposedSetup = await loadVerificationSetup([skillPath])
  ok(proposedSetup.identity.orderedSkills[0]?.files === 2, 'setup identity covers the full bundle')
  ok(proposedSetup.identity.orderedSkills[0]?.gate === 'pass', 'setup identity records the static trust gate')
  writeFileSync(join(skillDir, 'asset.bin'), Buffer.from([1, 2, 3]))
  const binarySetupA = await loadVerificationSetup([skillPath])
  writeFileSync(join(skillDir, 'asset.bin'), Buffer.from([1, 2, 4, 5]))
  const binarySetupB = await loadVerificationSetup([skillPath])
  ok(binarySetupA.identity.sha256 !== binarySetupB.identity.sha256 && binarySetupB.identity.orderedSkills[0]?.files === 3, 'exact setup identity binds every regular file including binary assets')
  chmodSync(join(skillDir, 'asset.bin'), 0o700)
  const executableSetup = await loadVerificationSetup([skillPath])
  ok(executableSetup.identity.sha256 !== binarySetupB.identity.sha256, 'exact setup identity binds executable and permission mode changes')
  for (let index = 0; index < 42; index++) writeFileSync(join(skillDir, `asset-${index}.bin`), Buffer.from([index]))
  const manyAssetSetup = await loadVerificationSetup([skillPath])
  ok((manyAssetSetup.identity.orderedSkills[0]?.files ?? 0) > 41, 'exact identity and receipt schema support bounded packages with more than 41 regular assets')
  let duplicateSetupRejected = false
  try { await loadVerificationSetup([skillPath, skillPath]) } catch { duplicateSetupRejected = true }
  ok(duplicateSetupRejected, 'verification rejects duplicate Skill paths in an ordered setup')
  const caseDir = join(temp, 'case-duplicate'); mkdirSync(caseDir)
  const casePath = join(caseDir, 'SKILL.md')
  writeFileSync(casePath, readFileSync(skillPath, 'utf8').replace('name: json-output', 'name: JSON-OUTPUT'))
  let caseDuplicateRejected = false
  try { await loadVerificationSetup([skillPath, casePath]) } catch { caseDuplicateRejected = true }
  ok(caseDuplicateRejected, 'verification rejects case-folded duplicate Skill names that cannot form an installable setup')

  const outsideSecret = join(temp, 'outside-secret.md')
  writeFileSync(outsideSecret, 'CREDENTIAL-MUST-NOT-LEAVE-BUNDLE')
  const linkedSkillDir = join(temp, 'linked-skill')
  mkdirSync(join(linkedSkillDir, 'references'), { recursive: true })
  const linkedSkillPath = join(linkedSkillDir, 'SKILL.md')
  writeFileSync(linkedSkillPath, readFileSync(skillPath, 'utf8'))
  symlinkSync(outsideSecret, join(linkedSkillDir, 'references', 'credentials.md'))
  let linkedBundleRejected = false
  try { await loadVerificationSetup([linkedSkillPath]) } catch { linkedBundleRejected = true }
  ok(linkedBundleRejected, 'verification rejects bundle symlinks instead of reading files outside the Skill root')

  const specialSkillDir = join(temp, 'special-skill')
  mkdirSync(join(specialSkillDir, 'references'), { recursive: true })
  const specialSkillPath = join(specialSkillDir, 'SKILL.md')
  writeFileSync(specialSkillPath, readFileSync(skillPath, 'utf8'))
  const fifoPath = join(specialSkillDir, 'references', 'hang.md')
  const fifoCreated = spawnSync('mkfifo', [fifoPath]).status === 0
  let specialFileRejected = false
  if (fifoCreated) try { await loadVerificationSetup([specialSkillPath]) } catch { specialFileRejected = true }
  ok(!fifoCreated || specialFileRejected, 'verification rejects non-regular bundle files instead of blocking on them')
  const specialEntryDir = join(temp, 'special-entry')
  mkdirSync(specialEntryDir)
  const specialEntryPath = join(specialEntryDir, 'SKILL.md')
  const entryFifoCreated = spawnSync('mkfifo', [specialEntryPath]).status === 0
  let specialEntryRejected = false
  if (entryFifoCreated) try { await loadVerificationSetup([specialEntryPath]) } catch { specialEntryRejected = true }
  ok(!entryFifoCreated || specialEntryRejected, 'verification rejects a non-regular SKILL.md entry point before reading it')

  const excludedSkillDir = join(temp, 'excluded-content-skill')
  mkdirSync(join(excludedSkillDir, 'data'), { recursive: true })
  const excludedSkillPath = join(excludedSkillDir, 'SKILL.md')
  writeFileSync(excludedSkillPath, `${readFileSync(skillPath, 'utf8')}\nRead .hidden.md and data/rules.md.\n`)
  writeFileSync(join(excludedSkillDir, '.hidden.md'), 'HIDDEN-INSTRUCTION')
  writeFileSync(join(excludedSkillDir, 'data', 'rules.md'), 'DATA-INSTRUCTION')
  let excludedContentRejected = false
  try { await loadVerificationSetup([excludedSkillPath]) } catch { excludedContentRejected = true }
  ok(excludedContentRejected, 'verification fails closed when eligible content sits in an excluded hidden or skipped path')

  const oversizedBundleDir = join(temp, 'oversized-bundle')
  mkdirSync(join(oversizedBundleDir, 'references'), { recursive: true })
  const oversizedBundleSkill = join(oversizedBundleDir, 'SKILL.md')
  writeFileSync(oversizedBundleSkill, readFileSync(skillPath, 'utf8'))
  for (let index = 0; index < 41; index++) writeFileSync(join(oversizedBundleDir, 'references', `f${String(index).padStart(2, '0')}.md`), `reference ${index}`)
  let truncatedBundleRejected = false
  try { await loadVerificationSetup([oversizedBundleSkill]) } catch { truncatedBundleRejected = true }
  ok(truncatedBundleRejected, 'verification fails closed instead of hashing a silently truncated bundle')
  const directoryFlood = join(temp, 'directory-flood')
  mkdirSync(directoryFlood)
  const directoryFloodSkill = join(directoryFlood, 'SKILL.md')
  writeFileSync(directoryFloodSkill, readFileSync(skillPath, 'utf8'))
  for (let index = 0; index < 205; index++) mkdirSync(join(directoryFlood, `z${String(index).padStart(3, '0')}`))
  let directoryFloodRejected = false
  try { await loadVerificationSetup([directoryFloodSkill]) } catch { directoryFloodRejected = true }
  ok(directoryFloodRejected, 'exact package manifest bounds empty directories and total entries')
  const suite = parsed.ok ? parsed.suite : (() => { throw new Error('suite fixture failed') })()
  const suiteSha = await sha256Text(canonicalJson(suite))
  const verifierSha = await sha256Text(canonicalJson({ goalPassRate: suite.goalPassRate, tasks: suite.tasks.map((task) => ({ id: task.id, check: task.check })) }))
  const goalSha = await sha256Text(suite.goal)
  const environment = await createVerificationEnvironment({ providerOrigin: 'https://api.example.test', model: 'test-model', trials: 3, temperature: 0, maxTokens: 128 })
  const sequence: boolean[] = []
  const times = [new Date('2026-08-02T00:00:00.000Z'), new Date('2026-08-02T00:00:01.000Z')]
  const run = await runPairedVerification({
    suite,
    suiteSha256: suiteSha,
    verifierSha256: verifierSha,
    goalSha256: goalSha,
    baseline: baselineSetup,
    proposed: proposedSetup,
    environment,
    providerKind: 'real',
    invocationId: '00000000-0000-4000-8000-000000000002',
    now: () => times.shift() ?? new Date('2026-08-02T00:00:01.000Z'),
    chat: async ({ system }) => {
      const assisted = system.includes('Installed Skill: json-output')
      sequence.push(assisted)
      return { text: assisted ? '{"order":42}' : 'not json', tokens: assisted ? 12 : 8 }
    },
  })
  ok(canonicalJson(sequence) === canonicalJson([false, true, true, false, false, true]), 'paired schedule alternates AB/BA by seed')
  ok(run.receipt.result.evidenceStatus === 'verified-here' && run.receipt.result.goalPassed === true, 'runner produces scoped verified goal success')
  ok(validateVerificationReceipt(run.receipt).ok && await verifyReceiptIntegrity(run.receipt), 'runner receipt passes schema, ledger, and integrity checks')
  const serialized = JSON.stringify(run.receipt)
  ok(!serialized.includes(privateInstruction) && !serialized.includes('Return order 42') && !serialized.includes(skillPath), 'receipt excludes raw Skill content, prompts, and local paths')
  const receiptDir = join(temp, 'receipts')
  const firstPath = persistVerificationReceipt(run.receipt, receiptDir)
  const original = readFileSync(firstPath, 'utf8')
  let duplicateBlocked = false
  try { persistVerificationReceipt(run.receipt, receiptDir) } catch { duplicateBlocked = true }
  ok(duplicateBlocked && readFileSync(firstPath, 'utf8') === original, 'append-only persistence refuses overwrite and preserves the original')
  const summaryFifo = join(receiptDir, 'hang.json')
  const summaryFifoCreated = spawnSync('mkfifo', [summaryFifo]).status === 0
  symlinkSync(firstPath, join(receiptDir, 'linked.json'))
  const hardenedSummary = await readVerificationSummary(receiptDir)
  ok(hardenedSummary.invalidFiles >= (summaryFifoCreated ? 2 : 1), 'summary rejects symlink and FIFO receipt entries without following or blocking on them')

  let failingProviderCalls = 0
  const failedRun = await runPairedVerification({
    suite,
    suiteSha256: suiteSha,
    verifierSha256: verifierSha,
    goalSha256: goalSha,
    baseline: baselineSetup,
    proposed: proposedSetup,
    environment,
    providerKind: 'real',
    chat: async () => { failingProviderCalls++; throw new Error('quota exhausted') },
  })
  ok(failingProviderCalls === 1 && failedRun.providerErrors === 6, 'provider circuit breaker avoids a per-observation retry storm')
  ok(failedRun.receipt.observations.length === 6 && validateVerificationReceipt(failedRun.receipt).ok, 'provider circuit breaker still finalizes a complete error ledger')

  const suitePath = join(temp, 'suite.json')
  writeFileSync(suitePath, JSON.stringify(suiteRaw))
  let fetchCalls = 0
  const previousFetch = globalThis.fetch
  const previousError = console.error
  const previousLog = console.log
  globalThis.fetch = (async () => { fetchCalls++; throw new Error('unexpected network') }) as typeof fetch
  console.error = () => undefined
  console.log = () => undefined
  const omittedArm = await runVerifyCommand(['--suite', suitePath, '--skill', skillPath, '--simulate'], 'test')
  const unknownFlag = await runVerifyCommand(['--suite', suitePath, '--baseline-empty', '--skill', skillPath, '--simluate'], 'test')
  const duplicateSuite = await runVerifyCommand(['--suite', suitePath, '--suite', suitePath, '--baseline-empty', '--skill', skillPath, '--simulate'], 'test')
  const ignoredSummaryOption = await runVerifyCommand(['summary', '--suite', suitePath], 'test')
  const tooManySkills = await runVerifyCommand(['--suite', suitePath, '--baseline-empty', ...Array.from({ length: 51 }, () => ['--skill', skillPath]).flat(), '--simulate'], 'test')
  const refused = await runVerifyCommand(['--suite', suitePath, '--baseline-empty', '--skill', skillPath], 'test')
  const simulatedDir = join(temp, 'simulated')
  const simulated = await runVerifyCommand(['--suite', suitePath, '--baseline-empty', '--skill', skillPath, '--simulate', '--out-dir', simulatedDir, '--json'], 'test')
  const budgetSuitePath = join(temp, 'budget-suite.json')
  writeFileSync(budgetSuitePath, JSON.stringify({ ...suiteRaw, tasks: [...suiteRaw.tasks, { ...suiteRaw.tasks[0], id: 'order-2' }] }))
  const overBudget = await runVerifyCommand(['--suite', budgetSuitePath, '--baseline-empty', '--skill', skillPath, '--simulate', '--max-tokens', '32768'], 'test')
  globalThis.fetch = previousFetch
  console.error = previousError
  console.log = previousLog
  ok(omittedArm === 1 && fetchCalls === 0, 'CLI rejects an accidentally omitted baseline instead of inferring an empty setup')
  ok(unknownFlag === 1 && fetchCalls === 0, 'CLI rejects unknown flags instead of silently changing experiment semantics')
  ok(duplicateSuite === 1 && fetchCalls === 0, 'CLI rejects duplicate single-value options instead of silently choosing one')
  ok(ignoredSummaryOption === 1 && fetchCalls === 0, 'summary rejects run-only options instead of silently ignoring them')
  ok(tooManySkills === 1 && fetchCalls === 0, 'CLI rejects setup sizes that cannot produce a valid receipt')
  ok(refused === 1 && fetchCalls === 0, 'CLI refuses before egress without --send-to-model')
  ok(simulated === 3 && fetchCalls === 0, 'CLI simulation is a distinct non-verified exit state with no network')
  ok(overBudget === 1 && fetchCalls === 0, 'aggregate verification budget rejects excessive output exposure before egress')
  const simulatedSummary = await readVerificationSummary(simulatedDir)
  ok(simulatedSummary.simulations === 1 && simulatedSummary.validRealAttempts === 0 && simulatedSummary.localVssrPct === null, 'simulated receipt is excluded from local VSSR')

  const previousVerifyUrl = process.env.SKILLMOO_VERIFY_URL
  const previousVerifyKey = process.env.SKILLMOO_VERIFY_KEY
  const previousVerifyModel = process.env.SKILLMOO_VERIFY_MODEL
  process.env.SKILLMOO_VERIFY_URL = 'http://provider.example.test/v1'
  process.env.SKILLMOO_VERIFY_KEY = 'test-only-key'
  process.env.SKILLMOO_VERIFY_MODEL = 'test-model'
  const insecurePreviousError = console.error
  console.error = () => undefined
  const insecureEndpoint = await runVerifyCommand(['--suite', suitePath, '--baseline-empty', '--skill', skillPath, '--send-to-model'], 'test')
  console.error = insecurePreviousError
  if (previousVerifyUrl === undefined) delete process.env.SKILLMOO_VERIFY_URL; else process.env.SKILLMOO_VERIFY_URL = previousVerifyUrl
  if (previousVerifyKey === undefined) delete process.env.SKILLMOO_VERIFY_KEY; else process.env.SKILLMOO_VERIFY_KEY = previousVerifyKey
  if (previousVerifyModel === undefined) delete process.env.SKILLMOO_VERIFY_MODEL; else process.env.SKILLMOO_VERIFY_MODEL = previousVerifyModel
  ok(insecureEndpoint === 1 && fetchCalls === 0, 'CLI rejects remote plaintext HTTP before sending credentials or Skill contents')

  let timeoutFetchCalls = 0
  globalThis.fetch = (async (_url, init) => {
    timeoutFetchCalls++
    return await new Promise<Response>((_resolve, reject) => {
      const fallback = setTimeout(() => reject(new Error('timeout test did not abort')), 200)
      init?.signal?.addEventListener('abort', () => { clearTimeout(fallback); reject(new Error('aborted')) }, { once: true })
    })
  }) as typeof fetch
  const timeoutChat = createOpenAICompatibleChat('https://api.example.test', 'test-key', 'test-model', 5)
  let timedOut = false
  try { await timeoutChat({ system: 's', user: 'u', seed: 1, temperature: 0, maxTokens: 8 }) } catch { timedOut = true }
  ok(timedOut && timeoutFetchCalls === 3, 'provider calls time out after bounded retries instead of hanging forever')

  let oversizedResponseCalls = 0
  let redirectPolicy = ''
  globalThis.fetch = (async (_url, init) => {
    oversizedResponseCalls++
    redirectPolicy = String(init?.redirect)
    return new Response('{}', { status: 200, headers: { 'content-length': String(2_000_000), 'content-type': 'application/json' } })
  }) as typeof fetch
  const boundedChat = createOpenAICompatibleChat('https://api.example.test', 'test-key', 'test-model', 5)
  let oversizedResponseRejected = false
  try { await boundedChat({ system: 's', user: 'u', seed: 1, temperature: 0, maxTokens: 8 }) } catch { oversizedResponseRejected = true }
  ok(oversizedResponseRejected && oversizedResponseCalls === 1, 'provider responses above 1 MiB fail once without retrying a non-transient protocol error')
  ok(redirectPolicy === 'manual', 'provider requests expose redirects as a non-retryable response before sending Skill contents to another origin')
  let redirectCalls = 0
  globalThis.fetch = (async () => { redirectCalls++; return new Response('', { status: 302, headers: { location: 'https://other.example.test/' } }) }) as typeof fetch
  const redirectChat = createOpenAICompatibleChat('https://api.example.test', 'test-key', 'test-model', 5)
  try { await redirectChat({ system: 's', user: 'u', seed: 1, temperature: 0, maxTokens: 8 }) } catch { /* expected */ }
  ok(redirectCalls === 1, 'provider redirects fail once and are never retried')
  let badRequestCalls = 0
  globalThis.fetch = (async () => { badRequestCalls++; return new Response('{}', { status: 400 }) }) as typeof fetch
  const badRequestChat = createOpenAICompatibleChat('https://api.example.test', 'test-key', 'test-model', 5)
  try { await badRequestChat({ system: 's', user: 'u', seed: 1, temperature: 0, maxTokens: 8 }) } catch { /* expected */ }
  ok(badRequestCalls === 1, 'provider HTTP 4xx errors are not retried')
  globalThis.fetch = previousFetch
} finally {
  rmSync(temp, { recursive: true, force: true })
}

if (failures.length) {
  console.error(`\n✗ eval:verification — ${failures.length} failure(s)`)
  for (const failure of failures) console.error(`  ✗ ${failure}`)
  process.exit(1)
}
console.log(`\n✅ eval:verification — ${passed}/${passed}: suite, graders, claim gate, identity, integrity, privacy, outcomes, and VSSR invariants hold.\n`)
