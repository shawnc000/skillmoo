import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { ARTIFACT_INDEX } from '../src/data/artifactIndex'
import { MATCH_SKILLS } from '../src/data/matchCatalog'
import { ARTIFACT_PAYLOADS } from '../cli/artifactPayloads'
import {
  canonicalJson,
  catalogDigest,
  artifactIdFor,
  validateArtifactIndex,
  validateArtifactPayload,
  type ArtifactIndex,
  type ArtifactPayload,
} from '../cli/catalogArtifact'
import { materializeCatalogArtifact, prepareCatalogSetup } from '../cli/catalog'
import { readSetupReceipt, rollbackSetup, applySetup, SetupError } from '../cli/setup'
import { artifactHandoffScript, artifactRoute, filterCompletePackageEligible } from '../src/lib/artifactRouting'

let passed = 0
const failures: string[] = []
const ok = (value: unknown, name: string) => value ? passed++ : failures.push(name)
const rejects = (fn: () => unknown, name: string, exitCode?: number) => {
  try { fn(); failures.push(name) } catch (error) {
    if (exitCode === undefined || error instanceof SetupError && error.exitCode === exitCode) passed++
    else failures.push(`${name} (wrong error: ${(error as Error).message})`)
  }
}
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T
const readyCommit = (value: ArtifactIndex): string | null => {
  const commits = new Set(value.entries.flatMap((entry) => entry.status === 'pilot-ready' ? [entry.artifact.source.commit] : []))
  return commits.size === 1 ? [...commits][0]! : null
}
const run = (command: string, args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number | null; stderr: string }> => new Promise((resolveRun) => {
  const child = spawn(command, args, { cwd: process.cwd(), env, stdio: ['ignore', 'ignore', 'pipe'] })
  let stderr = ''
  child.stderr.on('data', (chunk) => { stderr += String(chunk) })
  child.on('close', (code) => resolveRun({ code, stderr }))
})

const index = ARTIFACT_INDEX as unknown as ArtifactIndex
const temp = mkdtempSync(join(tmpdir(), 'skillmoo-catalog-v2-test-'))
try {
  validateArtifactIndex(index)
  ok(true, 'generated artifact index validates')
  const committedIndex = JSON.parse(readFileSync(join(process.cwd(), 'catalog', 'v2', 'index.json'), 'utf8')) as ArtifactIndex
  ok(canonicalJson(committedIndex) === canonicalJson(index), 'committed JSON index and generated Web/CLI index are byte-semantically identical')
  const cliPackage = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8')) as { version?: unknown }
  ok(index.cliVersion === cliPackage.version, 'artifact index is bound to the exact publishable CLI package version')
  const sourceLock = JSON.parse(readFileSync(join(process.cwd(), 'catalog', 'v2', 'sources.lock.json'), 'utf8')) as { commit?: unknown; repositoryId?: unknown }
  ok(sourceLock.commit === readyCommit(index) && sourceLock.repositoryId === 'R_kgDOQFGGXQ', 'source lock and every ready artifact bind the same reviewed repository version')
  ok(index.entries.length === MATCH_SKILLS.length && index.entries.length === 115, 'artifact index covers every trusted match entry')
  const ready = index.entries.filter((entry) => entry.status === 'pilot-ready')
  ok(ready.length === 4, 'only four complete-package gate survivors are pilot-ready')
  const rejectedSeo = index.entries.find((entry) => entry.name === 'seo-audit' && entry.status === 'link-only')
  ok(rejectedSeo !== undefined && 'reason' in rejectedSeo && rejectedSeo.reason === 'full-gate-failed', 'single-manifest pass that fails the full gate stays reason-coded link-only')
  ok(new Set(index.entries.map((entry) => entry.name)).size === MATCH_SKILLS.length && index.entries.every((entry) => MATCH_SKILLS.some((skill) => skill.name === entry.name && skill.url === entry.sourceUrl)), 'index identity and source URL retain match-catalog parity')
  ok(ready.every((entry) => entry.status === 'pilot-ready' && /^[0-9a-f]{40}$/.test(entry.artifact.source.commit) && !/\/(?:main|master)\//.test(entry.artifact.source.pinnedUrl)), 'ready artifacts use full immutable commit URLs')
  ok(ready.every((entry) => entry.status === 'pilot-ready' && entry.artifact.source.repositoryId === 'R_kgDOQFGGXQ' && entry.artifact.license.spdx === 'MIT'), 'ready artifacts bind reviewed repository identity and MIT evidence')
  ok(new Set(ready.map((entry) => entry.status === 'pilot-ready' ? entry.artifact.artifactId : '')).size === ready.length, 'artifact IDs are unique and content-addressed')
  const starterNames = ['marketing-ideas', 'launch-strategy', 'email-sequence', 'marketing-psychology']
  const starterHandoff = artifactHandoffScript({ names: starterNames, displayName: 'Pinned content launch starter', language: 'en', index })
  ok(starterHandoff.route.allReady && starterHandoff.route.readyByName.size === 4 && starterHandoff.script.includes('catalog inspect') && starterHandoff.script.includes('catalog prepare') && starterHandoff.script.includes(`skillmoo@${index.cliVersion}`), 'four-item Web starter forms an exact-version pinned inspect/prepare handoff')
  const mixedNames = [...starterNames, 'seo-audit']
  const mixedHandoff = artifactHandoffScript({ names: mixedNames, displayName: 'Content marketing & SEO', language: 'en', index })
  ok(!mixedHandoff.route.allReady && mixedHandoff.route.rejectedByName.get('seo-audit') === 'full-gate-failed' && !mixedHandoff.script.includes('catalog prepare') && (mixedHandoff.script.match(/--source/g) ?? []).length === 5, 'mixed five-item workflow discloses rejection and falls back to complete local sources')
  const fullRoute = artifactRoute(index.entries.map((entry) => entry.name), index)
  ok(ready.every((entry) => entry.status === 'pilot-ready' && fullRoute.pinnedUrlByName.get(entry.name) === entry.artifact.source.pinnedUrl), 'ready Web source chips resolve to immutable pinned URLs')
  ok(!filterCompletePackageEligible(MATCH_SKILLS, index).some((skill) => skill.name === 'seo-audit'), 'full-package gate rejection cannot enter automatic Web/CLI matching')

  for (const entry of ready) if (entry.status === 'pilot-ready') {
    const payload = ARTIFACT_PAYLOADS[entry.artifact.artifactId]
    if (!payload) { failures.push(`embedded payload exists: ${entry.name}`); continue }
    validateArtifactPayload(entry.artifact, payload)
    passed++
    const committedPayload = JSON.parse(readFileSync(join(process.cwd(), 'catalog', 'v2', 'payloads', `${entry.name}.json`), 'utf8')) as ArtifactPayload
    ok(canonicalJson(committedPayload) === canonicalJson(payload), `committed payload and embedded CLI payload match: ${entry.name}`)
  }

  const damagedIndex = clone(index)
  damagedIndex.entries.pop()
  rejects(() => validateArtifactIndex(damagedIndex), 'index removal invalidates catalog digest')
  const duplicateIndex = clone(index)
  duplicateIndex.entries[1]!.name = duplicateIndex.entries[0]!.name
  rejects(() => validateArtifactIndex(duplicateIndex), 'duplicate artifact index identity is rejected')
  const unsafeIndex = clone(index)
  const unsafeEntry = unsafeIndex.entries.find((entry) => entry.status === 'pilot-ready')
  if (!unsafeEntry || unsafeEntry.status !== 'pilot-ready') throw new Error('fixture invariant')
  unsafeEntry.artifact.files[0]!.path = '../escape'
  unsafeIndex.catalogSha256 = catalogDigest({ protocolVersion: unsafeIndex.protocolVersion, cliVersion: unsafeIndex.cliVersion, entries: unsafeIndex.entries })
  rejects(() => validateArtifactIndex(unsafeIndex), 'path escape is rejected after a recomputed outer catalog digest')
  const mutableRefIndex = clone(index)
  const mutableEntry = mutableRefIndex.entries.find((entry) => entry.status === 'pilot-ready')
  if (!mutableEntry || mutableEntry.status !== 'pilot-ready') throw new Error('fixture invariant')
  mutableEntry.artifact.source.pinnedUrl = mutableEntry.artifact.source.sourceUrl
  mutableRefIndex.catalogSha256 = catalogDigest({ protocolVersion: mutableRefIndex.protocolVersion, cliVersion: mutableRefIndex.cliVersion, entries: mutableRefIndex.entries })
  rejects(() => validateArtifactIndex(mutableRefIndex), 'mutable artifact URL is rejected after a recomputed outer catalog digest')
  const readyFirst = ready[0]!
  if (readyFirst.status !== 'pilot-ready') throw new Error('fixture invariant')
  const payload = ARTIFACT_PAYLOADS[readyFirst.artifact.artifactId]!
  const tamperedPayload = clone(payload)
  tamperedPayload.files[0]!.base64 = Buffer.from('tampered').toString('base64')
  rejects(() => validateArtifactPayload(readyFirst.artifact, tamperedPayload), 'payload byte tamper is rejected')
  const truncatedPayload = clone(payload)
  truncatedPayload.files.pop()
  rejects(() => validateArtifactPayload(readyFirst.artifact, truncatedPayload), 'payload truncation is rejected')
  const modePayload = clone(payload)
  modePayload.files[0]!.mode = modePayload.files[0]!.mode === 0o600 ? 0o700 : 0o600
  rejects(() => validateArtifactPayload(readyFirst.artifact, modePayload), 'payload mode drift is rejected')
  const nonCanonicalPayload = clone(payload)
  nonCanonicalPayload.files[0]!.base64 += '=='
  rejects(() => validateArtifactPayload(readyFirst.artifact, nonCanonicalPayload), 'non-canonical base64 encoding is rejected')
  const falseGitIdentity = clone(readyFirst.artifact)
  falseGitIdentity.files[0]!.gitBlobOid = '0'.repeat(40)
  falseGitIdentity.artifactId = artifactIdFor((({ artifactId: _, ...descriptor }) => descriptor)(falseGitIdentity))
  const falseGitPayload = clone(payload)
  falseGitPayload.artifactId = falseGitIdentity.artifactId
  rejects(() => validateArtifactPayload(falseGitIdentity, falseGitPayload), 'payload bytes must match their declared Git blob object identity')

  const originalFetch = globalThis.fetch
  globalThis.fetch = (() => { throw new Error('network must not be used by catalog materialization') }) as typeof fetch
  try {
    const cacheRoot = join(temp, 'cache')
    mkdirSync(cacheRoot, { mode: 0o700 })
    chmodSync(cacheRoot, 0o700)
    const first = materializeCatalogArtifact(readyFirst.artifact.artifactId, { cacheRoot })
    ok(!first.cacheHit && existsSync(join(first.sourceDir, 'SKILL.md')), 'artifact materializes exact complete package offline')
    ok((lstatSync(join(cacheRoot, readyFirst.artifact.artifactId)).mode & 0o777) === 0o700 && existsSync(join(first.sourceDir, 'LICENSE.upstream.txt')), 'cache is private and retains installable upstream license evidence inside the Skill package')
    const second = materializeCatalogArtifact(readyFirst.artifact.artifactId, { cacheRoot })
    ok(second.cacheHit && second.sourceDir === first.sourceDir, 'content-addressed materialization is idempotent')

    const scope = join(temp, 'project')
    const targetRoot = join(scope, '.codex', 'skills')
    const planPath = join(temp, 'catalog-plan.json')
    mkdirSync(targetRoot, { recursive: true })
    const before = readdirSync(targetRoot).join('|')
    const chosen = ready.slice(0, 2).map((entry) => entry.status === 'pilot-ready' ? entry.artifact.artifactId : '')
    const prepared = prepareCatalogSetup({ artifactIds: chosen, targetRoot, planPath, projectRoot: scope, cacheRoot })
    ok(readdirSync(targetRoot).join('|') === before && prepared.plan.actions.length === 2, 'catalog prepare creates a multi-artifact plan without target mutation')
    ok(prepared.plan.actions.every((action) => action.analysis.gate === 'pass' && action.analysis.risk === 'low'), 'catalog plan reuses the complete setup gate')
    const receiptPath = applySetup({ planPath, confirm: prepared.plan.planId })
    const receipt = readSetupReceipt(receiptPath)
    ok(chosen.every((_, index) => existsSync(join(targetRoot, prepared.plan.actions[index]!.name, 'SKILL.md'))), 'existing setup transaction applies every pinned artifact')
    ok(prepared.plan.actions.every((action) => existsSync(join(targetRoot, action.name, 'LICENSE.upstream.txt'))), 'installed artifacts retain upstream license evidence')
    rollbackSetup({ receiptPath, confirm: receipt.receiptId })
    ok(prepared.plan.actions.every((action) => !existsSync(join(targetRoot, action.name))), 'existing setup rollback restores the pre-artifact state')
    rejects(() => prepareCatalogSetup({ artifactIds: [chosen[0]!, chosen[0]!], targetRoot, planPath: join(temp, 'duplicate.json'), projectRoot: scope, cacheRoot }), 'duplicate artifact IDs are rejected', 1)
    rejects(() => materializeCatalogArtifact('sa_not_in_catalog', { cacheRoot }), 'link-only or unknown artifact cannot materialize', 1)

    const damagedRoot = join(temp, 'damaged-cache')
    mkdirSync(damagedRoot, { mode: 0o700 }); chmodSync(damagedRoot, 0o700)
    const damaged = materializeCatalogArtifact(readyFirst.artifact.artifactId, { cacheRoot: damagedRoot })
    writeFileSync(join(damaged.sourceDir, 'SKILL.md'), 'damaged after materialization')
    rejects(() => materializeCatalogArtifact(readyFirst.artifact.artifactId, { cacheRoot: damagedRoot }), 'damaged immutable cache fails closed without overwrite', 3)
    ok(readFileSync(join(damaged.sourceDir, 'SKILL.md'), 'utf8') === 'damaged after materialization', 'damaged-cache refusal performs no silent repair')

    const metadataRoot = join(temp, 'metadata-cache')
    mkdirSync(metadataRoot, { mode: 0o700 }); chmodSync(metadataRoot, 0o700)
    materializeCatalogArtifact(readyFirst.artifact.artifactId, { cacheRoot: metadataRoot })
    writeFileSync(join(metadataRoot, readyFirst.artifact.artifactId, 'artifact.json'), '{}')
    rejects(() => materializeCatalogArtifact(readyFirst.artifact.artifactId, { cacheRoot: metadataRoot }), 'damaged cached descriptor evidence fails closed', 3)

    const unexpectedRoot = join(temp, 'unexpected-cache')
    mkdirSync(unexpectedRoot, { mode: 0o700 }); chmodSync(unexpectedRoot, 0o700)
    materializeCatalogArtifact(readyFirst.artifact.artifactId, { cacheRoot: unexpectedRoot })
    writeFileSync(join(unexpectedRoot, readyFirst.artifact.artifactId, 'unexpected.txt'), 'unexpected')
    rejects(() => materializeCatalogArtifact(readyFirst.artifact.artifactId, { cacheRoot: unexpectedRoot }), 'unexpected cached top-level content fails closed', 3)

    const missingPayloads: Record<string, ArtifactPayload> = {}
    rejects(() => materializeCatalogArtifact(readyFirst.artifact.artifactId, { cacheRoot: join(temp, 'missing-payload'), payloads: missingPayloads }), 'missing embedded payload requires state inspection', 3)
  } finally { globalThis.fetch = originalFetch }

  const canonicalTemp = realpathSync(temp)
  const concurrentHome = join(canonicalTemp, 'parallel-home')
  const concurrentScope = join(canonicalTemp, 'parallel-project')
  const concurrentTarget = join(concurrentScope, '.codex', 'skills')
  mkdirSync(concurrentHome, { mode: 0o700 }); chmodSync(concurrentHome, 0o700)
  mkdirSync(concurrentTarget, { recursive: true })
  const tsx = join(process.cwd(), 'node_modules', 'tsx', 'dist', 'cli.mjs')
  const cliEntry = join(process.cwd(), 'cli', 'index.ts')
  const badPlan = join(canonicalTemp, 'bad-option-plan.json')
  const cliEnv = { ...process.env, HOME: concurrentHome }
  const [badList, badInspect, badPrepare] = await Promise.all([
    run(process.execPath, [tsx, cliEntry, 'catalog', 'list', '--definitely-invalid'], cliEnv),
    run(process.execPath, [tsx, cliEntry, 'catalog', 'inspect', '--artifact', readyFirst.artifact.artifactId, '--definitely-invalid'], cliEnv),
    run(process.execPath, [tsx, cliEntry, 'catalog', 'prepare', '--artifact', readyFirst.artifact.artifactId, '--target-root', concurrentTarget, '--project-root', concurrentScope, '--out', badPlan, '--definitely-invalid'], cliEnv),
  ])
  ok([badList, badInspect, badPrepare].every((result) => result.code === 1) && !existsSync(badPlan), 'catalog commands reject unknown options before any plan mutation')
  const parallel = await Promise.all(Array.from({ length: 4 }, (_, index) => run(process.execPath, [
    tsx, cliEntry, 'catalog', 'prepare',
    '--artifact', readyFirst.artifact.artifactId,
    '--target-root', concurrentTarget,
    '--project-root', concurrentScope,
    '--out', join(canonicalTemp, `parallel-${index}.json`),
  ], { ...process.env, HOME: concurrentHome })))
  ok(parallel.every((result) => result.code === 0), `concurrent first materialization is idempotent (${parallel.map((result) => `${result.code}:${result.stderr.trim()}`).join(' | ')})`)
  const concurrentCache = join(concurrentHome, '.skillmoo', 'artifacts', 'v1')
  ok(existsSync(concurrentCache) && readdirSync(concurrentCache).filter((name) => !name.startsWith('.stage-')).length === 1, 'concurrent materialization leaves one immutable cache generation')

  console.log(`catalog-v2: ${passed}/${passed + failures.length} checks passed`)
  if (failures.length) {
    for (const failure of failures) console.error(`  FAIL ${failure}`)
    process.exit(1)
  }
} finally {
  rmSync(temp, { recursive: true, force: true })
}
