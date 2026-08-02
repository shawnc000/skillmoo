import { closeSync, constants, fchmodSync, fstatSync, fsyncSync, openSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { ARTIFACT_INDEX } from '../src/data/artifactIndex'
import { createSetupCapsule, MAX_SETUP_CAPSULE_BYTES, validateSetupCapsule, type SetupCapsule } from '../src/lib/setupCapsule'
import { validateVerificationReceipt, type VerificationReceipt } from '../src/lib/verificationProtocol'
import { prepareCatalogSetup } from './catalog'
import { SetupError } from './setup'
import { safeTerminalText } from './format'
import { parseStrictJson } from '../src/lib/strictJson'

function readBoundedJson(path: string): unknown {
  const absolute = resolve(path)
  const fd = openSync(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const stat = fstatSync(fd)
    if (!stat.isFile() || stat.size > MAX_SETUP_CAPSULE_BYTES) throw new SetupError(`JSON input must be a regular file at most ${MAX_SETUP_CAPSULE_BYTES} bytes: ${absolute}`)
    let text: string
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(fd)) }
    catch { throw new SetupError(`JSON input is not valid UTF-8: ${absolute}`) }
    try { return parseStrictJson(text) }
    catch (error) { throw new SetupError(`invalid JSON input: ${(error as Error).message}`) }
  } finally { closeSync(fd) }
}

function writeNewJson(path: string, value: unknown): void {
  const absolute = resolve(path)
  const fd = openSync(absolute, 'wx', 0o600)
  try {
    fchmodSync(fd, 0o600)
    writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
    fsyncSync(fd)
  } finally { closeSync(fd) }
}

function parse(argv: string[], allowed: Record<string, 'single'>): Map<string, string> {
  const out = new Map<string, string>()
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i]!, mode = allowed[key]
    if (!mode) throw new SetupError(`unknown capsule option: ${key}`)
    const value = argv[++i]
    if (!value || value.startsWith('--') || out.has(key)) throw new SetupError(`${key} requires exactly one value`)
    out.set(key, value)
  }
  return out
}

export async function inspectSetupCapsule(path: string): Promise<{ capsule: SetupCapsule; compatible: boolean }> {
  const result = await validateSetupCapsule(readBoundedJson(path), ARTIFACT_INDEX)
  if (!result.ok || !result.capsule) throw new SetupError(`capsule validation failed: ${result.errors[0] ?? 'unknown error'}`, 2)
  return { capsule: result.capsule, compatible: result.catalogCompatible }
}

export async function prepareCapsuleSetup(options: {
  capsulePath: string
  targetRoot: string
  planPath: string
  projectRoot?: string
  cacheRoot?: string
  payloads?: Parameters<typeof prepareCatalogSetup>[0]['payloads']
}) {
  const { capsule, compatible } = await inspectSetupCapsule(options.capsulePath)
  if (!compatible) throw new SetupError(`capsule requires CLI ${capsule.setup.cliVersion}; current catalog is ${ARTIFACT_INDEX.cliVersion}. Prepare is blocked. After that exact release is published, inspect it with: npx skillmoo@${capsule.setup.cliVersion} capsule inspect --capsule <capsule.json>`, 2)
  const prepared = prepareCatalogSetup({ artifactIds: capsule.replay.artifactIds, targetRoot: options.targetRoot, planPath: options.planPath, projectRoot: options.projectRoot, cacheRoot: options.cacheRoot, payloads: options.payloads })
  return { capsule, ...prepared }
}

function help(): void {
  console.log(`
  skillmoo capsule create --receipt <receipt.json> --out <capsule.json>
  skillmoo capsule inspect --capsule <capsule.json>
  skillmoo capsule prepare --capsule <capsule.json> --target-root <dir> --out <plan.json> [--project-root <dir>]

  Capsules share exact embedded catalog setup identities. They never include the private suite,
  are not SkillMOO-signed, and do not transfer the sender's verified state to the recipient.
`)
}

export async function runCapsuleCommand(argv: string[]): Promise<number> {
  try {
    const [subcommand, ...rest] = argv
    if (!subcommand || ['help', '--help', '-h'].includes(subcommand)) { help(); return 0 }
    if (subcommand === 'create') {
      const options = parse(rest, { '--receipt': 'single', '--out': 'single' })
      const receiptPath = options.get('--receipt'), out = options.get('--out')
      if (!receiptPath || !out) throw new SetupError('capsule create requires --receipt and --out')
      const raw = readBoundedJson(receiptPath)
      const validation = validateVerificationReceipt(raw)
      if (!validation.ok || !validation.receipt) throw new SetupError(`receipt validation failed: ${validation.errors[0] ?? 'unknown error'}`, 2)
      const capsule = await createSetupCapsule(validation.receipt as VerificationReceipt, ARTIFACT_INDEX)
      writeNewJson(out, capsule)
      console.log(JSON.stringify({ state: 'created', capsuleId: capsule.capsuleId, path: resolve(out), setup: 'exact-catalog-artifacts', experiment: 'unavailable-private-suite', signed: false, authentication: 'none', senderIdentityVerified: false, runOccurrenceVerified: false }, null, 2))
      return 0
    }
    if (subcommand === 'inspect') {
      const options = parse(rest, { '--capsule': 'single' })
      const path = options.get('--capsule'); if (!path) throw new SetupError('capsule inspect requires --capsule')
      const { capsule, compatible } = await inspectSetupCapsule(path)
      console.log(JSON.stringify({
        capsuleId: capsule.capsuleId,
        integrityValid: true,
        catalogCompatible: compatible,
        setupReplayableHere: compatible,
        senderEvidence: 'local-self-attested',
        authentication: 'none',
        signed: false,
        senderIdentityVerified: false,
        runOccurrenceVerified: false,
        experimentReplayable: false,
        requiredCliVersion: capsule.setup.cliVersion,
        currentCliVersion: ARTIFACT_INDEX.cliVersion,
        next: compatible
          ? 'Run capsule prepare only after reviewing this output.'
          : `Use the exact compatible release after it is published: npx skillmoo@${capsule.setup.cliVersion} capsule inspect --capsule <capsule.json>`,
        artifacts: capsule.setup.orderedArtifacts.map((item) => ({ name: item.name, artifactId: item.artifactId, bundleSha256: item.bundleSha256, grade: item.assessment.grade, gate: item.assessment.gate, risk: item.assessment.risk, license: item.license.spdx, source: item.source.pinnedUrl })),
        limitations: capsule.limitations,
      }, null, 2))
      return compatible ? 0 : 2
    }
    if (subcommand === 'prepare') {
      const options = parse(rest, { '--capsule': 'single', '--target-root': 'single', '--out': 'single', '--project-root': 'single' })
      const path = options.get('--capsule'), targetRoot = options.get('--target-root'), out = options.get('--out')
      if (!path || !targetRoot || !out) throw new SetupError('capsule prepare requires --capsule, --target-root, and --out')
      const prepared = await prepareCapsuleSetup({ capsulePath: path, targetRoot, planPath: out, projectRoot: options.get('--project-root') })
      const { capsule } = prepared
      console.log(JSON.stringify({ state: 'prepared', capsuleId: capsule.capsuleId, planId: prepared.plan.planId, planPath: resolve(out), targetRoot: prepared.plan.target.root, applied: false, next: `Review the plan, then run skillmoo setup apply --plan ${resolve(out)} --confirm ${prepared.plan.planId}` }, null, 2))
      return 0
    }
    throw new SetupError(`unknown capsule command: ${subcommand}`)
  } catch (error) {
    if (error instanceof SetupError) { console.error(`capsule: ${safeTerminalText(error.message)}`); return error.exitCode }
    console.error(`capsule: ${safeTerminalText((error as Error).message)}`)
    return 1
  }
}
