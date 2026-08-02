export const VERIFICATION_SUITE_VERSION = 'skillmoo-verification-suite/1.0'
export const VERIFICATION_PROTOCOL_VERSION = 'skillmoo-verification/1.0'
export const VERIFICATION_RUNNER_VERSION = 'skillmoo-paired-chat/1.0'
export const MIN_VERIFICATION_TRIALS = 3
export const MAX_VERIFICATION_TRIALS = 20
export const MAX_VERIFICATION_PACKAGE_FILES = 200
export const MAX_RECEIPT_BYTES = 1_048_576

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

export type VerificationCheck =
  | { kind: 'exact'; value: string }
  | { kind: 'json-equals'; value: JsonValue }
  | { kind: 'contains'; all: string[]; none?: string[] }

export interface VerificationTaskSpec {
  id: string
  prompt: string
  check: VerificationCheck
}

export interface VerificationSuite {
  version: typeof VERIFICATION_SUITE_VERSION
  title: string
  goal: string
  baseSystem: string
  goalPassRate: number
  tasks: VerificationTaskSpec[]
}

export interface SkillVerificationIdentity {
  name: string
  sha256: string
  files: number
  grade: string
  gate: string
  risk: string
}

export interface SetupVerificationIdentity {
  sha256: string
  orderedSkills: SkillVerificationIdentity[]
}

export interface VerificationEnvironmentIdentity {
  sha256: string
  adapter: 'openai-compatible-chat'
  runnerVersion: typeof VERIFICATION_RUNNER_VERSION
  providerOrigin: string
  model: string
  node: string
  os: string
  arch: string
  temperature: number
  maxTokens: number
  timeoutMs: number
  trials: number
  seeds: number[]
}

export type VerificationArm = 'baseline' | 'proposed'
export type VerificationProviderKind = 'real' | 'simulated'
export type VerificationEvidenceStatus = 'inspected' | 'verified-here'
export type VerificationOutcome = 'improved' | 'unchanged' | 'regressed' | 'inconclusive' | 'error'

export interface VerificationObservation {
  taskId: string
  seed: number
  arm: VerificationArm
  status: 'ok' | 'provider-error'
  pass: boolean
  tokens: number
  durationMs: number
  suiteSha256: string
  environmentSha256: string
  setupSha256: string
  errorCode?: 'provider-error'
}

export interface VerificationDerived {
  runStatus: 'complete' | 'error'
  evidenceStatus: VerificationEvidenceStatus
  experimentOutcome: VerificationOutcome
  goalPassed: boolean | 'unknown'
  baselinePassRate: number
  proposedPassRate: number
  liftPoints: number
  baselineAvgTokens: number
  proposedAvgTokens: number
  tokenDeltaPct: number
  baselineAvgDurationMs: number
  proposedAvgDurationMs: number
  durationDeltaPct: number
}

export interface VerificationReceipt {
  protocolVersion: typeof VERIFICATION_PROTOCOL_VERSION
  receiptId: string
  invocationId: string
  startedAt: string
  completedAt: string
  attestation: 'local-self-attested'
  providerKind: VerificationProviderKind
  suite: {
    sha256: string
    verifierSha256: string
    goalSha256: string
    title: string
    taskIds: string[]
    goalPassRate: number
  }
  setups: {
    baseline: SetupVerificationIdentity
    proposed: SetupVerificationIdentity
  }
  environment: VerificationEnvironmentIdentity
  observations: VerificationObservation[]
  result: VerificationDerived
  limitations: string[]
  integrity: { algorithm: 'sha256'; payloadSha256: string }
}

export interface ReceiptValidation {
  ok: boolean
  errors: string[]
  receipt?: VerificationReceipt
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value)

const finite = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value)

function isJsonValue(value: unknown, depth = 0): value is JsonValue {
  if (depth > 10) return false
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true
  if (finite(value)) return true
  if (Array.isArray(value)) return value.length <= 100 && value.every((x) => isJsonValue(x, depth + 1))
  if (!isRecord(value) || Object.keys(value).length > 100) return false
  return Object.values(value).every((x) => isJsonValue(x, depth + 1))
}

function cleanText(value: unknown, max: number): string | null {
  if (typeof value !== 'string' || value.length > max) return null
  const text = value.trim()
  return text || null
}

export function parseVerificationSuite(raw: unknown): { ok: true; suite: VerificationSuite } | { ok: false; errors: string[] } {
  const errors: string[] = []
  if (!isRecord(raw)) return { ok: false, errors: ['suite must be a JSON object'] }
  if (raw.version !== VERIFICATION_SUITE_VERSION) errors.push(`version must be ${VERIFICATION_SUITE_VERSION}`)
  const title = cleanText(raw.title, 160)
  const goal = cleanText(raw.goal, 2_000)
  const baseSystem = cleanText(raw.baseSystem, 20_000)
  if (!title) errors.push('title is required and must be at most 160 characters')
  if (!goal) errors.push('goal is required and must be at most 2,000 characters')
  if (!baseSystem) errors.push('baseSystem is required and must be at most 20,000 characters')
  if (!finite(raw.goalPassRate) || raw.goalPassRate <= 0 || raw.goalPassRate > 1) errors.push('goalPassRate must be greater than 0 and at most 1')
  if (!Array.isArray(raw.tasks) || raw.tasks.length < 1 || raw.tasks.length > 50) errors.push('tasks must contain 1–50 items')

  const tasks: VerificationTaskSpec[] = []
  const ids = new Set<string>()
  if (Array.isArray(raw.tasks) && raw.tasks.length <= 50) {
    for (const [index, candidate] of raw.tasks.entries()) {
      if (!isRecord(candidate)) { errors.push(`tasks[${index}] must be an object`); continue }
      const id = typeof candidate.id === 'string' && /^[a-z0-9][a-z0-9._-]{0,63}$/i.test(candidate.id) ? candidate.id : null
      const prompt = cleanText(candidate.prompt, 20_000)
      if (!id) errors.push(`tasks[${index}].id is invalid`)
      else if (ids.has(id)) errors.push(`duplicate task id: ${id}`)
      else ids.add(id)
      if (!prompt) errors.push(`tasks[${index}].prompt is required and must be at most 20,000 characters`)
      const c = candidate.check
      let check: VerificationCheck | null = null
      if (!isRecord(c)) errors.push(`tasks[${index}].check must be an object`)
      else if (c.kind === 'exact') {
        if (typeof c.value !== 'string' || c.value.length > 20_000) errors.push(`tasks[${index}].check.value must be a string at most 20,000 characters`)
        else check = { kind: 'exact', value: c.value }
      } else if (c.kind === 'json-equals') {
        if (!isJsonValue(c.value)) errors.push(`tasks[${index}].check.value must be bounded JSON`)
        else check = { kind: 'json-equals', value: c.value }
      } else if (c.kind === 'contains') {
        const all = Array.isArray(c.all) ? c.all : []
        const none = c.none === undefined ? undefined : Array.isArray(c.none) ? c.none : []
        const validList = (values: unknown[], allowEmpty: boolean) =>
          (allowEmpty || values.length > 0) && values.length <= 20 && values.every((x) => typeof x === 'string' && x.length > 0 && x.length <= 500)
        if (!validList(all, false) || (none !== undefined && !validList(none, true))) errors.push(`tasks[${index}].check contains lists are invalid`)
        else check = { kind: 'contains', all: all as string[], ...(none?.length ? { none: none as string[] } : {}) }
      } else errors.push(`tasks[${index}].check.kind is unsupported`)
      if (id && prompt && check) tasks.push({ id, prompt, check })
    }
  }

  if (errors.length || !title || !goal || !baseSystem || !finite(raw.goalPassRate)) return { ok: false, errors }
  return {
    ok: true,
    suite: {
      version: VERIFICATION_SUITE_VERSION,
      title,
      goal,
      baseSystem,
      goalPassRate: raw.goalPassRate,
      tasks,
    },
  }
}

function normalizeText(value: string): string {
  return value.trim().replace(/\r\n/g, '\n')
}

export function gradeVerificationOutput(check: VerificationCheck, output: string): boolean {
  if (check.kind === 'exact') return normalizeText(output) === normalizeText(check.value)
  if (check.kind === 'contains') {
    const text = output.toLowerCase()
    return check.all.every((x) => text.includes(x.toLowerCase())) && !(check.none ?? []).some((x) => text.includes(x.toLowerCase()))
  }
  try {
    return canonicalJson(JSON.parse(output.trim())) === canonicalJson(check.value)
  } catch {
    return false
  }
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue)
  if (!isRecord(value)) return value
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]))
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value))
}

export async function sha256Text(value: string): Promise<string> {
  // Browsers expose Web Crypto globally. Node 18 does not do so consistently,
  // therefore load its standards-compatible implementation only on that path.
  const nodeCryptoSpecifier: string = 'node:crypto'
  const subtle = globalThis.crypto?.subtle
    ?? (await import(nodeCryptoSpecifier) as { webcrypto: Crypto }).webcrypto.subtle
  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(value))
  return [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, '0')).join('')
}

export function receiptPayload(receipt: VerificationReceipt): Omit<VerificationReceipt, 'integrity'> {
  const { integrity: _integrity, ...payload } = receipt
  return payload
}

export async function verifyReceiptIntegrity(receipt: VerificationReceipt): Promise<boolean> {
  const { sha256: _environmentSha, ...environmentPayload } = receipt.environment
  const [payloadHash, baselineHash, proposedHash, environmentHash, receiptIdHash] = await Promise.all([
    sha256Text(canonicalJson(receiptPayload(receipt))),
    sha256Text(canonicalJson(receipt.setups.baseline.orderedSkills)),
    sha256Text(canonicalJson(receipt.setups.proposed.orderedSkills)),
    sha256Text(canonicalJson(environmentPayload)),
    sha256Text(canonicalJson({
      invocationId: receipt.invocationId,
      completedAt: receipt.completedAt,
      suite: receipt.suite.sha256,
      baseline: receipt.setups.baseline.sha256,
      proposed: receipt.setups.proposed.sha256,
      environment: receipt.environment.sha256,
    })),
  ])
  return payloadHash === receipt.integrity.payloadSha256
    && baselineHash === receipt.setups.baseline.sha256
    && proposedHash === receipt.setups.proposed.sha256
    && environmentHash === receipt.environment.sha256
    && receipt.receiptId === `vr_${receiptIdHash.slice(0, 24)}`
}

const rounded = (value: number) => Number(value.toFixed(3))
const rate = (hits: number, total: number) => total ? rounded((hits / total) * 100) : 0
const deltaPct = (base: number, proposed: number) => base ? rounded(((proposed - base) / base) * 100) : 0

export function deriveVerificationResult(
  providerKind: VerificationProviderKind,
  goalPassRate: number,
  observations: VerificationObservation[],
): VerificationDerived {
  const baseline = observations.filter((x) => x.arm === 'baseline')
  const proposed = observations.filter((x) => x.arm === 'proposed')
  const anyError = observations.some((x) => x.status !== 'ok')
  const summarize = (items: VerificationObservation[]) => {
    const ok = items.filter((x) => x.status === 'ok')
    const total = ok.length
    return {
      passRate: rate(ok.filter((x) => x.pass).length, total),
      avgTokens: total ? rounded(ok.reduce((sum, x) => sum + x.tokens, 0) / total) : 0,
      avgDuration: total ? rounded(ok.reduce((sum, x) => sum + x.durationMs, 0) / total) : 0,
    }
  }
  const b = summarize(baseline)
  const p = summarize(proposed)
  const lift = rounded(p.passRate - b.passRate)
  if (anyError) return {
    runStatus: 'error', evidenceStatus: 'inspected', experimentOutcome: 'error', goalPassed: 'unknown',
    baselinePassRate: b.passRate, proposedPassRate: p.passRate, liftPoints: lift,
    baselineAvgTokens: b.avgTokens, proposedAvgTokens: p.avgTokens, tokenDeltaPct: deltaPct(b.avgTokens, p.avgTokens),
    baselineAvgDurationMs: b.avgDuration, proposedAvgDurationMs: p.avgDuration, durationDeltaPct: deltaPct(b.avgDuration, p.avgDuration),
  }
  if (providerKind === 'simulated') return {
    runStatus: 'complete', evidenceStatus: 'inspected', experimentOutcome: 'inconclusive', goalPassed: 'unknown',
    baselinePassRate: b.passRate, proposedPassRate: p.passRate, liftPoints: lift,
    baselineAvgTokens: b.avgTokens, proposedAvgTokens: p.avgTokens, tokenDeltaPct: deltaPct(b.avgTokens, p.avgTokens),
    baselineAvgDurationMs: b.avgDuration, proposedAvgDurationMs: p.avgDuration, durationDeltaPct: deltaPct(b.avgDuration, p.avgDuration),
  }
  const outcome: VerificationOutcome = lift < 0
    ? 'regressed'
    : b.passRate >= 95 ? 'inconclusive' : lift > 0 ? 'improved' : 'unchanged'
  return {
    runStatus: 'complete', evidenceStatus: 'verified-here', experimentOutcome: outcome,
    goalPassed: p.passRate / 100 >= goalPassRate,
    baselinePassRate: b.passRate, proposedPassRate: p.passRate, liftPoints: lift,
    baselineAvgTokens: b.avgTokens, proposedAvgTokens: p.avgTokens, tokenDeltaPct: deltaPct(b.avgTokens, p.avgTokens),
    baselineAvgDurationMs: b.avgDuration, proposedAvgDurationMs: p.avgDuration, durationDeltaPct: deltaPct(b.avgDuration, p.avgDuration),
  }
}

const RECEIPT_STATUSES = new Set(['inspected', 'verified-here'])
const OUTCOMES = new Set(['improved', 'unchanged', 'regressed', 'inconclusive', 'error'])
const FORBIDDEN_KEYS = new Set(['prompt', 'output', 'raw', 'content', 'apikey', 'api_key', 'authorization', 'skillcontent', 'taskprompt'])

function findForbiddenKey(value: unknown, path = ''): string | null {
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      const found = findForbiddenKey(item, `${path}[${index}]`)
      if (found) return found
    }
    return null
  }
  if (!isRecord(value)) return null
  for (const [key, item] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.has(key.toLowerCase())) return path ? `${path}.${key}` : key
    const found = findForbiddenKey(item, path ? `${path}.${key}` : key)
    if (found) return found
  }
  return null
}

function validSha(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
}

function validProviderIdentity(providerKind: VerificationProviderKind, origin: string, model: string): boolean {
  if (providerKind === 'simulated') return origin === 'simulation://local' && model === 'deterministic-harness-stub'
  if (origin === 'simulation://local' || model === 'deterministic-harness-stub') return false
  try {
    const parsed = new URL(origin)
    const loopback = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]' || parsed.hostname === '::1'
    const normalized = `${parsed.origin}${parsed.pathname}`.replace(/\/$/, '')
    return !parsed.username && !parsed.password && !parsed.search && !parsed.hash
      && origin === normalized
      && (parsed.protocol === 'https:' || (parsed.protocol === 'http:' && loopback))
  } catch { return false }
}

function validSetupIdentity(value: unknown): value is SetupVerificationIdentity {
  if (!isRecord(value) || !validSha(value.sha256) || !Array.isArray(value.orderedSkills) || value.orderedSkills.length > 50) return false
  return value.orderedSkills.every((skill) => isRecord(skill)
    && typeof skill.name === 'string' && skill.name.length > 0 && skill.name.length <= 160
    && validSha(skill.sha256)
    && Number.isInteger(skill.files) && Number(skill.files) >= 1 && Number(skill.files) <= MAX_VERIFICATION_PACKAGE_FILES
    && typeof skill.grade === 'string' && typeof skill.gate === 'string' && typeof skill.risk === 'string')
}

export function validateVerificationReceipt(raw: unknown): ReceiptValidation {
  const errors: string[] = []
  if (!isRecord(raw)) return { ok: false, errors: ['receipt must be a JSON object'] }
  const forbidden = findForbiddenKey(raw)
  if (forbidden) errors.push(`receipt contains forbidden raw field: ${forbidden}`)
  if (raw.protocolVersion !== VERIFICATION_PROTOCOL_VERSION) errors.push(`protocolVersion must be ${VERIFICATION_PROTOCOL_VERSION}`)
  if (typeof raw.receiptId !== 'string' || !/^vr_[a-f0-9]{24}$/.test(raw.receiptId)) errors.push('receiptId is invalid')
  if (typeof raw.invocationId !== 'string' || raw.invocationId.length < 8) errors.push('invocationId is invalid')
  if (raw.attestation !== 'local-self-attested') errors.push('attestation is invalid')
  if (raw.providerKind !== 'real' && raw.providerKind !== 'simulated') errors.push('providerKind is invalid')
  if (!isRecord(raw.suite) || !validSha(raw.suite.sha256) || !validSha(raw.suite.verifierSha256) || !validSha(raw.suite.goalSha256)) errors.push('suite identity is invalid')
  if (!isRecord(raw.environment)
    || !validSha(raw.environment.sha256)
    || raw.environment.adapter !== 'openai-compatible-chat'
    || raw.environment.runnerVersion !== VERIFICATION_RUNNER_VERSION
    || !cleanText(raw.environment.providerOrigin, 2_048)
    || !cleanText(raw.environment.model, 256)
    || !cleanText(raw.environment.node, 64)
    || !cleanText(raw.environment.os, 64)
    || !cleanText(raw.environment.arch, 64)
    || !finite(raw.environment.temperature) || raw.environment.temperature < 0 || raw.environment.temperature > 2
    || !Number.isInteger(raw.environment.maxTokens) || Number(raw.environment.maxTokens) < 1 || Number(raw.environment.maxTokens) > 32_768
    || !Number.isInteger(raw.environment.timeoutMs) || Number(raw.environment.timeoutMs) < 1_000 || Number(raw.environment.timeoutMs) > 300_000) errors.push('environment identity is invalid')
  if (!isRecord(raw.setups) || !validSetupIdentity(raw.setups.baseline) || !validSetupIdentity(raw.setups.proposed)) errors.push('setup identity is invalid')
  if (typeof raw.startedAt !== 'string' || !Number.isFinite(Date.parse(raw.startedAt)) || typeof raw.completedAt !== 'string' || !Number.isFinite(Date.parse(raw.completedAt)) || Date.parse(raw.completedAt) < Date.parse(raw.startedAt)) errors.push('receipt timestamps are invalid')
  if (!isRecord(raw.result) || !RECEIPT_STATUSES.has(String(raw.result.evidenceStatus)) || !OUTCOMES.has(String(raw.result.experimentOutcome))) errors.push('result is invalid')
  if (!Array.isArray(raw.limitations) || raw.limitations.length < 1 || raw.limitations.length > 10
    || raw.limitations.some((item) => !cleanText(item, 500))) errors.push('limitations are invalid')
  if (!isRecord(raw.integrity) || raw.integrity.algorithm !== 'sha256' || !validSha(raw.integrity.payloadSha256)) errors.push('integrity is invalid')
  if (!Array.isArray(raw.observations) || raw.observations.length < 1 || raw.observations.length > 2_000) errors.push('observations are invalid')
  if (errors.length) return { ok: false, errors }

  const receipt = raw as unknown as VerificationReceipt
  const taskIds = receipt.suite.taskIds
  const seeds = receipt.environment.seeds
  if (!validProviderIdentity(receipt.providerKind, receipt.environment.providerOrigin, receipt.environment.model)) errors.push('provider kind and environment are inconsistent')
  if (typeof receipt.suite.title !== 'string' || !receipt.suite.title.trim() || receipt.suite.title.length > 160
    || !finite(receipt.suite.goalPassRate) || receipt.suite.goalPassRate <= 0 || receipt.suite.goalPassRate > 1) errors.push('suite metadata is invalid')
  if (!Array.isArray(taskIds) || !taskIds.length || taskIds.length > 50 || new Set(taskIds).size !== taskIds.length
    || taskIds.some((id) => typeof id !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/i.test(id))) errors.push('suite taskIds are invalid')
  if (!Array.isArray(seeds) || seeds.length < MIN_VERIFICATION_TRIALS || seeds.length > MAX_VERIFICATION_TRIALS || new Set(seeds).size !== seeds.length
    || seeds.some((seed) => !Number.isInteger(seed))) errors.push('environment seeds are invalid')
  if (receipt.environment.trials !== seeds.length) errors.push('environment trials must equal seed count')
  if (receipt.setups.baseline.sha256 === receipt.setups.proposed.sha256) errors.push('baseline and proposed setups must differ')
  const seen = new Set<string>()
  for (const [index, observation] of receipt.observations.entries()) {
    if (!isRecord(observation) || (observation.arm !== 'baseline' && observation.arm !== 'proposed')) {
      errors.push(`observation ${index} arm is invalid`)
      continue
    }
    const key = `${observation.arm}:${observation.taskId}:${observation.seed}`
    if (seen.has(key)) errors.push(`duplicate observation: ${key}`)
    seen.add(key)
    if (!taskIds.includes(observation.taskId) || !seeds.includes(observation.seed)) errors.push(`observation ${index} is outside the declared suite`)
    if (observation.suiteSha256 !== receipt.suite.sha256 || observation.environmentSha256 !== receipt.environment.sha256) errors.push(`observation ${index} identity drift`)
    const expectedSetup = observation.arm === 'baseline' ? receipt.setups.baseline.sha256 : receipt.setups.proposed.sha256
    if (observation.setupSha256 !== expectedSetup) errors.push(`observation ${index} setup drift`)
    if ((observation.status !== 'ok' && observation.status !== 'provider-error')
      || typeof observation.pass !== 'boolean'
      || !finite(observation.tokens) || observation.tokens < 0
      || !finite(observation.durationMs) || observation.durationMs < 0
      || (observation.status === 'provider-error' && observation.errorCode !== 'provider-error')
      || (observation.status === 'ok' && observation.errorCode !== undefined)) errors.push(`observation ${index} values are invalid`)
  }
  const expectedCount = taskIds.length * seeds.length * 2
  if (seen.size !== expectedCount) errors.push(`paired ledger is incomplete: expected ${expectedCount}, got ${seen.size}`)
  const derived = deriveVerificationResult(receipt.providerKind, receipt.suite.goalPassRate, receipt.observations)
  if (canonicalJson(derived) !== canonicalJson(receipt.result)) errors.push('derived result does not match observations')
  if (receipt.providerKind === 'simulated' && receipt.result.evidenceStatus === 'verified-here') errors.push('simulation cannot be verified-here')
  return errors.length ? { ok: false, errors } : { ok: true, errors: [], receipt }
}

export interface VerificationMetricSummary {
  validRealAttempts: number
  verifiedGoalSuccesses: number
  localVssrPct: number | null
  errors: number
  regressions: number
  inconclusive: number
  simulations: number
  invalidFiles: number
  duplicateFiles: number
  skippedFiles: number
}

export function summarizeVerificationReceipts(receipts: VerificationReceipt[], invalidFiles = 0, skippedFiles = 0): VerificationMetricSummary {
  const unique: VerificationReceipt[] = []
  const receiptIds = new Set<string>()
  const invocationIds = new Set<string>()
  let duplicateFiles = 0
  for (const receipt of receipts) {
    if (receiptIds.has(receipt.receiptId) || invocationIds.has(receipt.invocationId)) { duplicateFiles++; continue }
    receiptIds.add(receipt.receiptId)
    invocationIds.add(receipt.invocationId)
    unique.push(receipt)
  }
  const real = unique.filter((x) => x.providerKind === 'real')
  const successes = real.filter((x) => x.result.evidenceStatus === 'verified-here' && x.result.goalPassed === true && x.result.experimentOutcome !== 'regressed').length
  return {
    validRealAttempts: real.length,
    verifiedGoalSuccesses: successes,
    localVssrPct: real.length ? rounded((successes / real.length) * 100) : null,
    errors: real.filter((x) => x.result.runStatus === 'error').length,
    regressions: real.filter((x) => x.result.experimentOutcome === 'regressed').length,
    inconclusive: real.filter((x) => x.result.experimentOutcome === 'inconclusive').length,
    simulations: unique.filter((x) => x.providerKind === 'simulated').length,
    invalidFiles,
    duplicateFiles,
    skippedFiles,
  }
}
