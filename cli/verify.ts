import { linkSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import { createHash, randomUUID } from 'node:crypto'
import { basename, dirname, isAbsolute, join, relative } from 'node:path'
import { arch, platform } from 'node:os'
import { readBundle } from './discover'
import { safeTerminalText } from './format'
import { analyzeSkill } from '../src/lib/analyzeSkill'
import {
  MAX_RECEIPT_BYTES,
  MAX_VERIFICATION_PACKAGE_FILES,
  MAX_VERIFICATION_TRIALS,
  MIN_VERIFICATION_TRIALS,
  VERIFICATION_PROTOCOL_VERSION,
  VERIFICATION_RUNNER_VERSION,
  canonicalJson,
  deriveVerificationResult,
  gradeVerificationOutput,
  parseVerificationSuite,
  receiptPayload,
  sha256Text,
  summarizeVerificationReceipts,
  validateVerificationReceipt,
  verifyReceiptIntegrity,
  type SetupVerificationIdentity,
  type VerificationArm,
  type VerificationCheck,
  type VerificationEnvironmentIdentity,
  type VerificationMetricSummary,
  type VerificationObservation,
  type VerificationProviderKind,
  type VerificationReceipt,
  type VerificationSuite,
} from '../src/lib/verificationProtocol'

export interface VerificationChatRequest {
  system: string
  user: string
  seed: number
  temperature: number
  maxTokens: number
}

export type VerificationChat = (request: VerificationChatRequest) => Promise<{ text: string; tokens: number }>

interface LoadedSetup {
  identity: SetupVerificationIdentity
  systemText: string
}

interface VerificationRunInput {
  suite: VerificationSuite
  suiteSha256: string
  verifierSha256: string
  goalSha256: string
  baseline: LoadedSetup
  proposed: LoadedSetup
  environment: VerificationEnvironmentIdentity
  providerKind: VerificationProviderKind
  chat: VerificationChat
  invocationId?: string
  now?: () => Date
}

export interface VerificationRunOutput {
  receipt: VerificationReceipt
  providerErrors: number
}

function frontmatterName(md: string, fallback: string): string {
  const block = md.match(/^---\r?\n([\s\S]*?)\r?\n---/)
  return block?.[1].match(/^name:\s*["']?([^"'\r\n]+)/m)?.[1]?.trim() || fallback
}

function boundedRead(path: string, max = 256_000): string {
  const size = statSync(path).size
  if (size > max) throw new Error(`file too large: ${basename(path)} (${size} bytes; max ${max})`)
  return readFileSync(path, 'utf8')
}

const MAX_VERIFY_PACKAGE_BYTES = 20 * 1024 * 1024

type ExactPackageEntry = { path: string; kind: 'directory'; mode: number } | { path: string; kind: 'file'; mode: number; size: number; sha256: string }
function exactPackageManifest(entryPath: string): ExactPackageEntry[] {
  const root = dirname(realpathSync(entryPath))
  const files: ExactPackageEntry[] = []
  let total = 0
  const add = (entry: ExactPackageEntry) => { if (files.length >= MAX_VERIFICATION_PACKAGE_FILES) throw new Error('Skill package exceeds exact-verification entry limit'); files.push(entry) }
  add({ path: '.', kind: 'directory', mode: lstatSync(root).mode & 0o777 })
  const walk = (dir: string, depth: number): void => {
    if (depth > 8) throw new Error('Skill package exceeds exact-verification nesting limit')
    for (const name of readdirSync(dir).sort((a, b) => a.localeCompare(b, 'en'))) {
      if (name === '.git' || name === 'node_modules') throw new Error(`Skill package contains excluded directory: ${name}`)
      const path = join(dir, name), st = lstatSync(path)
      if (st.isSymbolicLink()) throw new Error(`Skill package contains a symbolic link: ${relative(root, path)}`)
      if (st.isDirectory()) { add({ path: relative(root, path), kind: 'directory', mode: st.mode & 0o777 }); walk(path, depth + 1); continue }
      if (!st.isFile() || st.nlink > 1) throw new Error(`Skill package contains a non-independent regular file: ${relative(root, path)}`)
      const real = realpathSync(path), rel = relative(root, real)
      if (rel.startsWith('..') || isAbsolute(rel)) throw new Error(`Skill package entry escapes its root: ${rel}`)
      total += st.size
      if (total > MAX_VERIFY_PACKAGE_BYTES) throw new Error('Skill package exceeds exact-verification byte limit')
      add({ path: rel, kind: 'file', mode: st.mode & 0o777, size: st.size, sha256: createHash('sha256').update(readFileSync(real)).digest('hex') })
    }
  }
  walk(root, 0)
  return files
}

export async function loadVerificationSetup(paths: string[]): Promise<LoadedSetup> {
  const identities: SetupVerificationIdentity['orderedSkills'] = []
  const sections: string[] = []
  const seenPaths = new Set<string>(), seenNames = new Set<string>()
  for (const path of paths) {
    const entry = lstatSync(path)
    if (entry.isSymbolicLink() || !entry.isFile()) throw new Error(`Skill entry point must be a regular file: ${basename(path)}`)
    const md = boundedRead(path)
    const canonicalPath = realpathSync(path)
    if (seenPaths.has(canonicalPath)) throw new Error(`duplicate Skill entry point: ${basename(path)}`)
    seenPaths.add(canonicalPath)
    const bundle = readBundle(path)
    if (!bundle.complete) throw new Error(`Skill bundle cannot be verified exactly: ${bundle.issues.join('; ')}`)
    const full = bundle.text ? `${md}\n\n${bundle.text}` : md
    const name = frontmatterName(md, basename(dirname(path)) || basename(path))
    const nameKey = name.normalize('NFC').toLocaleLowerCase('en-US')
    if (seenNames.has(nameKey)) throw new Error(`duplicate Skill name in setup: ${name}`)
    seenNames.add(nameKey)
    const manifest = exactPackageManifest(path)
    const sha256 = await sha256Text(canonicalJson({ manifest }))
    const analysis = analyzeSkill(md, bundle.bundle ? { bundleText: bundle.text, bundleFiles: bundle.files } : undefined)
    identities.push({ name, sha256, files: manifest.filter((entry) => entry.kind === 'file').length, grade: analysis.overall.grade, gate: analysis.overall.gate, risk: analysis.risk.level })
    sections.push(`## Installed Skill: ${name}\n\n${full}`)
  }
  return {
    identity: {
      sha256: await sha256Text(canonicalJson(identities)),
      orderedSkills: identities,
    },
    systemText: sections.join('\n\n---\n\n'),
  }
}

function armSystem(suite: VerificationSuite, setup: LoadedSetup): string {
  if (!setup.systemText) return suite.baseSystem
  return `${suite.baseSystem}\n\nThe following ordered Skill setup is installed for this run. Apply it when relevant.\n\n${setup.systemText}`
}

export async function runPairedVerification(input: VerificationRunInput): Promise<VerificationRunOutput> {
  const now = input.now ?? (() => new Date())
  const startedAt = now().toISOString()
  const observations: VerificationObservation[] = []
  let providerErrors = 0
  let providerUnavailable = false

  for (const task of input.suite.tasks) {
    for (const seed of input.environment.seeds) {
      const arms: VerificationArm[] = seed % 2 ? ['baseline', 'proposed'] : ['proposed', 'baseline']
      for (const arm of arms) {
        const setup = arm === 'baseline' ? input.baseline : input.proposed
        const t0 = Date.now()
        if (providerUnavailable) {
          providerErrors++
          observations.push({
            taskId: task.id,
            seed,
            arm,
            status: 'provider-error',
            pass: false,
            tokens: 0,
            durationMs: 0,
            suiteSha256: input.suiteSha256,
            environmentSha256: input.environment.sha256,
            setupSha256: setup.identity.sha256,
            errorCode: 'provider-error',
          })
          continue
        }
        try {
          const answer = await input.chat({
            system: armSystem(input.suite, setup),
            user: task.prompt,
            seed,
            temperature: input.environment.temperature,
            maxTokens: input.environment.maxTokens,
          })
          observations.push({
            taskId: task.id,
            seed,
            arm,
            status: 'ok',
            pass: gradeVerificationOutput(task.check, answer.text),
            tokens: Number.isFinite(answer.tokens) && answer.tokens >= 0 ? answer.tokens : 0,
            durationMs: Math.max(0, Date.now() - t0),
            suiteSha256: input.suiteSha256,
            environmentSha256: input.environment.sha256,
            setupSha256: setup.identity.sha256,
          })
        } catch {
          // The adapter already performs bounded transient retries. Once those are
          // exhausted, stop calling the same unavailable provider for every remaining
          // arm; fill the ledger with bounded errors so the pair stays auditable.
          providerUnavailable = true
          providerErrors++
          observations.push({
            taskId: task.id,
            seed,
            arm,
            status: 'provider-error',
            pass: false,
            tokens: 0,
            durationMs: Math.max(0, Date.now() - t0),
            suiteSha256: input.suiteSha256,
            environmentSha256: input.environment.sha256,
            setupSha256: setup.identity.sha256,
            errorCode: 'provider-error',
          })
        }
      }
    }
  }

  const completedAt = now().toISOString()
  const result = deriveVerificationResult(input.providerKind, input.suite.goalPassRate, observations)
  const invocationId = input.invocationId ?? randomUUID()
  const receiptId = `vr_${(await sha256Text(canonicalJson({
    invocationId,
    completedAt,
    suite: input.suiteSha256,
    baseline: input.baseline.identity.sha256,
    proposed: input.proposed.identity.sha256,
    environment: input.environment.sha256,
  }))).slice(0, 24)}`
  const limitations = input.providerKind === 'simulated'
    ? ['Simulated provider: this run tests the harness only and is not runtime evidence.']
    : result.runStatus === 'error'
      ? ['The provider did not complete every paired observation; no runtime efficacy claim is allowed.']
      : [
          'Applies only to this exact ordered setup, suite, model, adapter, and recorded environment.',
          'Local self-attestation is tamper-evident but is not a SkillMOO platform signature.',
          ...(result.experimentOutcome === 'inconclusive' ? ['The baseline was at ceiling, so this run cannot prove causal Skill lift.'] : []),
        ]
  const draft: VerificationReceipt = {
    protocolVersion: VERIFICATION_PROTOCOL_VERSION,
    receiptId,
    invocationId,
    startedAt,
    completedAt,
    attestation: 'local-self-attested',
    providerKind: input.providerKind,
    suite: {
      sha256: input.suiteSha256,
      verifierSha256: input.verifierSha256,
      goalSha256: input.goalSha256,
      title: input.suite.title,
      taskIds: input.suite.tasks.map((x) => x.id),
      goalPassRate: input.suite.goalPassRate,
    },
    setups: { baseline: input.baseline.identity, proposed: input.proposed.identity },
    environment: input.environment,
    observations,
    result,
    limitations,
    integrity: { algorithm: 'sha256', payloadSha256: '0'.repeat(64) },
  }
  const payloadSha256 = await sha256Text(canonicalJson(receiptPayload(draft)))
  return { receipt: { ...draft, integrity: { algorithm: 'sha256', payloadSha256 } }, providerErrors }
}

function optionValues(argv: string[], name: string): string[] {
  const values: string[] = []
  for (let i = 0; i < argv.length; i++) if (argv[i] === name && argv[i + 1] && !argv[i + 1].startsWith('--')) values.push(argv[++i])
  return values
}

function optionValue(argv: string[], name: string): string | undefined {
  return optionValues(argv, name)[0]
}

function parseNumberOption(argv: string[], name: string, fallback: number): number {
  const raw = optionValue(argv, name)
  return raw === undefined ? fallback : Number(raw)
}

const VERIFY_VALUE_OPTIONS = new Set(['--out-dir', '--dir', '--suite', '--trials', '--temperature', '--max-tokens', '--timeout-ms', '--baseline-skill', '--skill'])
const VERIFY_FLAG_OPTIONS = new Set(['--json', '--summary', '--baseline-empty', '--proposed-empty', '--simulate', '--send-to-model'])

function invalidVerifyArgument(argv: string[]): string | null {
  const summary = argv[0] === 'summary' || argv.includes('--summary')
  const valueOptions = summary ? new Set(['--out-dir', '--dir']) : VERIFY_VALUE_OPTIONS
  const flagOptions = summary ? new Set(['--json', '--summary']) : VERIFY_FLAG_OPTIONS
  const repeatable = new Set(['--baseline-skill', '--skill'])
  const seen = new Set<string>()
  for (let index = argv[0] === 'summary' ? 1 : 0; index < argv.length; index++) {
    const arg = argv[index]
    if (flagOptions.has(arg)) { if (seen.has(arg)) return `${arg} may be provided only once`; seen.add(arg); continue }
    if (valueOptions.has(arg)) {
      if (!repeatable.has(arg) && seen.has(arg)) return `${arg} may be provided only once`
      if (!argv[index + 1] || argv[index + 1].startsWith('--')) return `${arg} requires a value`
      seen.add(arg); index++
      continue
    }
    return `unknown verify argument: ${arg}`
  }
  return null
}

function safeProviderIdentity(base: string): { base: string; identity: string } {
  const parsed = new URL(base)
  if (parsed.username || parsed.password) throw new Error('provider URL must not contain credentials')
  const loopback = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]' || parsed.hostname === '::1'
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) {
    throw new Error('provider URL must use HTTPS (HTTP is allowed only for localhost loopback)')
  }
  parsed.search = ''
  parsed.hash = ''
  const normalized = parsed.toString().replace(/\/$/, '')
  return { base: normalized, identity: `${parsed.origin}${parsed.pathname}`.replace(/\/$/, '') }
}

export async function createVerificationEnvironment(input: {
  providerOrigin: string
  model: string
  trials: number
  temperature: number
  maxTokens: number
  timeoutMs?: number
}): Promise<VerificationEnvironmentIdentity> {
  const seeds = Array.from({ length: input.trials }, (_, index) => index + 1)
  const withoutHash: Omit<VerificationEnvironmentIdentity, 'sha256'> = {
    adapter: 'openai-compatible-chat' as const,
    runnerVersion: VERIFICATION_RUNNER_VERSION,
    providerOrigin: input.providerOrigin,
    model: input.model,
    node: process.version.replace(/^v/, ''),
    os: platform(),
    arch: arch(),
    temperature: input.temperature,
    maxTokens: input.maxTokens,
    timeoutMs: input.timeoutMs ?? 30_000,
    trials: input.trials,
    seeds,
  }
  return { sha256: await sha256Text(canonicalJson(withoutHash)), ...withoutHash }
}

const MAX_PROVIDER_RESPONSE_BYTES = 1_048_576

async function boundedResponseJson(response: Response): Promise<unknown> {
  const declared = Number(response.headers.get('content-length'))
  if (Number.isFinite(declared) && declared > MAX_PROVIDER_RESPONSE_BYTES) throw new Error('provider response exceeds 1 MiB limit')
  if (!response.body) throw new Error('provider returned an empty response')
  const reader = response.body.getReader()
  const joined = new Uint8Array(MAX_PROVIDER_RESPONSE_BYTES)
  let total = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    if (total + value.byteLength > MAX_PROVIDER_RESPONSE_BYTES) {
      await reader.cancel()
      throw new Error('provider response exceeds 1 MiB limit')
    }
    joined.set(value, total)
    total += value.byteLength
  }
  return JSON.parse(new TextDecoder().decode(joined.subarray(0, total)))
}

export function createOpenAICompatibleChat(base: string, key: string, model: string, timeoutMs: number): VerificationChat {
  return async ({ system, user, seed, temperature, maxTokens }) => {
    let lastError: Error = new Error('provider request failed')
    for (let attempt = 0; attempt < 3; attempt++) {
      let response: Response
      try {
        response = await fetch(`${base}/chat/completions`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` },
          body: JSON.stringify({ model, messages: [{ role: 'system', content: system }, { role: 'user', content: user }], seed, temperature, max_tokens: maxTokens }),
          signal: AbortSignal.timeout(timeoutMs),
          redirect: 'manual',
        })
      } catch (error) {
        lastError = error instanceof Error ? error : lastError
        if (attempt < 2) { await new Promise((resolve) => setTimeout(resolve, 300 * (attempt + 1))); continue }
        throw lastError
      }
      if (!response.ok) {
        lastError = new Error(`provider HTTP ${response.status}`)
        if ((response.status === 408 || response.status === 429 || response.status >= 500) && attempt < 2) { await new Promise((resolve) => setTimeout(resolve, 300 * (attempt + 1))); continue }
        throw lastError
      }
      const body = await boundedResponseJson(response) as { choices?: { message?: { content?: string } }[]; usage?: { total_tokens?: number } }
      const text = body.choices?.[0]?.message?.content
      if (typeof text !== 'string') throw new Error('provider returned no text')
      return { text: text.replace(/<think>[\s\S]*?<\/think>/gi, '').trim(), tokens: body.usage?.total_tokens ?? 0 }
    }
    throw lastError
  }
}

function responseForCheck(check: VerificationCheck): string {
  if (check.kind === 'exact') return check.value
  if (check.kind === 'json-equals') return canonicalJson(check.value)
  return check.all.join(' ')
}

function simulatedChat(suite: VerificationSuite): VerificationChat {
  const byPrompt = new Map(suite.tasks.map((task) => [task.prompt, task.check]))
  return async ({ user }) => {
    const check = byPrompt.get(user)
    return { text: check ? responseForCheck(check) : '', tokens: 0 }
  }
}

export function persistVerificationReceipt(receipt: VerificationReceipt, outDir: string): string {
  mkdirSync(outDir, { recursive: true, mode: 0o700 })
  const stamp = receipt.completedAt.replace(/[:.]/g, '-').replace('Z', 'Z')
  const finalPath = join(outDir, `${stamp}-${receipt.receiptId}.json`)
  const tempPath = join(outDir, `.${receipt.receiptId}-${randomUUID()}.tmp`)
  const body = `${JSON.stringify(receipt, null, 2)}\n`
  if (Buffer.byteLength(body) > MAX_RECEIPT_BYTES) throw new Error('receipt exceeds 1 MiB safety limit')
  writeFileSync(tempPath, body, { encoding: 'utf8', flag: 'wx', mode: 0o600 })
  try {
    linkSync(tempPath, finalPath)
  } finally {
    try { unlinkSync(tempPath) } catch { /* ignored: stale .tmp files are never read */ }
  }
  return finalPath
}

export async function readVerificationSummary(directory: string): Promise<VerificationMetricSummary> {
  let invalid = 0
  let skipped = 0
  const receipts: VerificationReceipt[] = []
  let files: string[] = []
  let rootReal = ''
  try {
    rootReal = realpathSync(directory)
    const all = readdirSync(directory).filter((name) => name.endsWith('.json')).sort((a, b) => a.localeCompare(b, 'en'))
    skipped = Math.max(0, all.length - 5_000)
    files = all.slice(0, 5_000)
  } catch { files = [] }
  for (const file of files) {
    try {
      const path = join(directory, file)
      const st = lstatSync(path)
      if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_RECEIPT_BYTES) { invalid++; continue }
      const real = realpathSync(path), fromRoot = relative(rootReal, real)
      if (fromRoot.startsWith('..') || isAbsolute(fromRoot)) { invalid++; continue }
      const parsed = validateVerificationReceipt(JSON.parse(readFileSync(real, 'utf8')))
      if (!parsed.ok || !parsed.receipt || !await verifyReceiptIntegrity(parsed.receipt)) invalid++
      else receipts.push(parsed.receipt)
    } catch { invalid++ }
  }
  return summarizeVerificationReceipts(receipts, invalid, skipped)
}

export async function runVerifyCommand(argv: string[], version: string): Promise<number> {
  const json = argv.includes('--json')
  const outDir = optionValue(argv, '--out-dir') ?? join(process.cwd(), '.skillmoo', 'receipts')
  const invalidArgument = invalidVerifyArgument(argv)
  if (invalidArgument) { console.error(safeTerminalText(invalidArgument)); return 1 }
  if (argv[0] === 'summary' || argv.includes('--summary')) {
    const summary = await readVerificationSummary(optionValue(argv, '--dir') ?? outDir)
    if (json) console.log(JSON.stringify(summary, null, 2))
    else {
      console.log('\n  ◇ SkillMOO verification summary · local self-attested receipts\n')
      console.log(`  valid real attempts   ${summary.validRealAttempts}`)
      console.log(`  verified goal success ${summary.verifiedGoalSuccesses}`)
      console.log(`  local VSSR            ${summary.localVssrPct === null ? 'not available' : `${summary.localVssrPct.toFixed(1)}%`}`)
      console.log(`  errors / regressions  ${summary.errors} / ${summary.regressions}`)
      console.log(`  inconclusive / sim    ${summary.inconclusive} / ${summary.simulations}`)
      console.log(`  invalid / duplicate   ${summary.invalidFiles} / ${summary.duplicateFiles}`)
      console.log(`  skipped over limit    ${summary.skippedFiles}`)
      console.log('\n  Local metric only — not a platform, cross-model, or industry success rate.\n')
    }
    return summary.invalidFiles || summary.duplicateFiles || summary.skippedFiles ? 1 : 0
  }

  const suitePath = optionValue(argv, '--suite')
  if (!suitePath) { console.error('verify requires --suite <suite.json>'); return 1 }
  let rawSuite: unknown
  try { rawSuite = JSON.parse(boundedRead(suitePath, MAX_RECEIPT_BYTES)) } catch (error) { console.error(`could not read suite: ${safeTerminalText((error as Error).message)}`); return 1 }
  const parsed = parseVerificationSuite(rawSuite)
  if (!parsed.ok) { console.error(`invalid verification suite:\n  - ${parsed.errors.join('\n  - ')}`); return 1 }
  const suite = parsed.suite
  const trials = parseNumberOption(argv, '--trials', MIN_VERIFICATION_TRIALS)
  const temperature = parseNumberOption(argv, '--temperature', 0)
  const maxTokens = parseNumberOption(argv, '--max-tokens', 1024)
  const timeoutMs = parseNumberOption(argv, '--timeout-ms', 30_000)
  if (!Number.isInteger(trials) || trials < MIN_VERIFICATION_TRIALS || trials > MAX_VERIFICATION_TRIALS) { console.error(`--trials must be an integer from ${MIN_VERIFICATION_TRIALS} to ${MAX_VERIFICATION_TRIALS}`); return 1 }
  if (!Number.isFinite(temperature) || temperature < 0 || temperature > 2) { console.error('--temperature must be between 0 and 2'); return 1 }
  if (!Number.isInteger(maxTokens) || maxTokens < 1 || maxTokens > 32_768) { console.error('--max-tokens must be an integer from 1 to 32768'); return 1 }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 300_000) { console.error('--timeout-ms must be an integer from 1000 to 300000'); return 1 }

  const baselinePaths = optionValues(argv, '--baseline-skill')
  const proposedPaths = optionValues(argv, '--skill')
  const baselineEmpty = argv.includes('--baseline-empty')
  const proposedEmpty = argv.includes('--proposed-empty')
  if ((!baselinePaths.length && !baselineEmpty) || (!proposedPaths.length && !proposedEmpty)) {
    console.error('declare both setups with --baseline-skill/--baseline-empty and --skill/--proposed-empty')
    return 1
  }
  if ((baselinePaths.length && baselineEmpty) || (proposedPaths.length && proposedEmpty)) {
    console.error('an empty-setup flag cannot be combined with Skill paths for the same arm')
    return 1
  }
  if (baselinePaths.length > 50 || proposedPaths.length > 50) { console.error('each setup may contain at most 50 Skills'); return 1 }
  let baseline: LoadedSetup, proposed: LoadedSetup
  try {
    baseline = await loadVerificationSetup(baselinePaths)
    proposed = await loadVerificationSetup(proposedPaths)
  } catch (error) { console.error(`could not load setup: ${safeTerminalText((error as Error).message)}`); return 1 }
  if (baseline.identity.sha256 === proposed.identity.sha256) { console.error('baseline and proposed ordered setups are identical'); return 1 }
  const untrusted = proposed.identity.orderedSkills.filter((skill) => !['A', 'B'].includes(skill.grade) || skill.gate !== 'pass' || skill.risk !== 'low')
  if (untrusted.length) { console.error(`proposed setup fails the automatic trust gate: ${safeTerminalText(untrusted.map((skill) => `${skill.name} (${skill.grade}/${skill.gate}/${skill.risk})`).join(', '))}`); return 1 }
  const requests = suite.tasks.length * trials * 2
  const maxAttempts = 3
  const inputBytes = maxAttempts * trials * suite.tasks.reduce((sum, task) => sum + Buffer.byteLength(suite.baseSystem) * 2 + Buffer.byteLength(task.prompt) * 2 + Buffer.byteLength(baseline.systemText) + Buffer.byteLength(proposed.systemText), 0)
  const maxOutputTokens = maxAttempts * requests * maxTokens
  if (requests > 200 || inputBytes > 20 * 1024 * 1024 || maxOutputTokens > 200_000) {
    console.error(`verification budget exceeded: ${requests} requests, ${(inputBytes / 1048576).toFixed(1)} MiB input, up to ${maxOutputTokens.toLocaleString()} output tokens; split the suite or lower trials/max-tokens`)
    return 1
  }

  const suiteSha256 = await sha256Text(canonicalJson(suite))
  const verifierSha256 = await sha256Text(canonicalJson({ goalPassRate: suite.goalPassRate, tasks: suite.tasks.map((task) => ({ id: task.id, check: task.check })) }))
  const goalSha256 = await sha256Text(suite.goal)
  const simulated = argv.includes('--simulate')
  let providerKind: VerificationProviderKind
  let providerOrigin: string
  let model: string
  let chat: VerificationChat
  if (simulated) {
    providerKind = 'simulated'
    providerOrigin = 'simulation://local'
    model = 'deterministic-harness-stub'
    chat = simulatedChat(suite)
  } else {
    if (!argv.includes('--send-to-model')) {
      console.error('refusing network egress: add --send-to-model to send this suite and the declared Skill bundles to your configured model endpoint')
      return 1
    }
    const rawBase = process.env.SKILLMOO_VERIFY_URL || process.env.OPENAI_BASE_URL || process.env.GEN_BASE_URL || ''
    const key = process.env.SKILLMOO_VERIFY_KEY || process.env.OPENAI_API_KEY || process.env.GEN_API_KEY || ''
    model = process.env.SKILLMOO_VERIFY_MODEL || process.env.EVAL_MODEL || process.env.GEN_MODEL || ''
    if (model.length > 200 || [...model].some((ch) => { const code = ch.charCodeAt(0); return code < 32 || code === 127 })) { console.error('verification model identifier is invalid'); return 1 }
    if (!rawBase || !key || !model) {
      console.error('set SKILLMOO_VERIFY_URL, SKILLMOO_VERIFY_KEY, and SKILLMOO_VERIFY_MODEL (or compatible OPENAI_/GEN_ variables)')
      return 1
    }
    let provider
    try { provider = safeProviderIdentity(rawBase) } catch (error) { console.error(`invalid provider URL: ${safeTerminalText((error as Error).message)}`); return 1 }
    providerKind = 'real'
    providerOrigin = provider.identity
    chat = createOpenAICompatibleChat(provider.base, key, model, timeoutMs)
    if (!json) {
      console.error(`\n  ⚠ verify sends ${requests} model request(s) (${suite.tasks.length} tasks × ${trials} trials × 2 arms) to ${providerOrigin}.`)
      console.error(`  Worst-case adapter ceiling: ${requests * maxAttempts} HTTP attempts, ${(inputBytes / 1048576).toFixed(1)} MiB input, and ${maxOutputTokens.toLocaleString()} output tokens.`)
      console.error('  Raw prompts, outputs, Skill contents, and keys are not written to the receipt.\n')
    }
  }
  const environment = await createVerificationEnvironment({ providerOrigin, model, trials, temperature, maxTokens, timeoutMs })
  const { receipt, providerErrors } = await runPairedVerification({ suite, suiteSha256, verifierSha256, goalSha256, baseline, proposed, environment, providerKind, chat })
  const selfValidation = validateVerificationReceipt(receipt)
  if (!selfValidation.ok || !await verifyReceiptIntegrity(receipt)) {
    console.error(`internal verification receipt failed self-validation: ${selfValidation.errors.join('; ') || 'integrity mismatch'}`)
    return 1
  }
  let receiptPath: string
  try { receiptPath = persistVerificationReceipt(receipt, outDir) } catch (error) { console.error(`could not persist receipt: ${safeTerminalText((error as Error).message)}`); return 1 }

  if (json) console.log(JSON.stringify({ cliVersion: version, receiptPath, receipt }, null, 2))
  else {
    const result = receipt.result
    console.log(`\n  ◇ SkillMOO verify · ${safeTerminalText(suite.title)}`)
    console.log(`  evidence    ${result.evidenceStatus}${providerKind === 'simulated' ? ' · simulated' : ''}`)
    console.log(`  outcome     ${result.experimentOutcome}`)
    console.log(`  goal        ${result.goalPassed === 'unknown' ? 'unknown' : result.goalPassed ? 'passed' : 'failed'}`)
    if (result.runStatus === 'complete') {
      console.log(`  baseline    ${result.baselinePassRate.toFixed(1)}%`)
      console.log(`  proposed    ${result.proposedPassRate.toFixed(1)}%  (${result.liftPoints >= 0 ? '+' : ''}${result.liftPoints.toFixed(1)} pts)`)
    } else {
      console.log('  comparison  unavailable · incomplete paired run')
    }
    console.log(`  model       ${safeTerminalText(model)} · ${trials} trials · ${receipt.attestation}`)
    console.log(`  receipt     ${safeTerminalText(receiptPath)}`)
    if (providerErrors) console.log(`  errors      ${providerErrors} provider observation(s) failed`)
    for (const limitation of receipt.limitations) console.log(`  note        ${safeTerminalText(limitation)}`)
    console.log('')
  }
  if (receipt.result.runStatus === 'error') return 1
  if (providerKind === 'simulated') return 3
  return receipt.result.goalPassed === true && receipt.result.experimentOutcome !== 'regressed' ? 0 : 2
}
