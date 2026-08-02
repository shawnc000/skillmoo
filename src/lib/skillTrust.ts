import type { StoreSkill } from '@/data/seedSkills'

export const EVIDENCE_CONTRACT_VERSION = 'skillmoo-evidence/1.0'
export type EvidenceBasis = 'inherited-rule' | 'deterministic' | 'runtime' | 'heuristic'
export type EvidenceStatus = 'inspected' | 'verified-here' | 'cross-environment'
export type RuntimeEvidenceStatus = 'not-tested' | 'incomplete' | 'measured'

export interface AssessmentEvidenceSummary {
  contractVersion: typeof EVIDENCE_CONTRACT_VERSION
  status: EvidenceStatus
  scope: 'skill' | 'combination'
  basis: EvidenceBasis[]
  packageEvidence: 'full-bundle' | 'manifest-only' | 'mixed' | 'unknown'
  runtime: {
    status: RuntimeEvidenceStatus
    environment?: string
    harness?: string
    model?: string
    trials?: number
  }
  composition: { status: 'not-tested' | 'measured' }
  limitations: string[]
}

/** A static grade answers "is the package well-formed and acceptably safe?".
 * Runtime evidence answers the separate question "did it improve this task in this
 * environment?". Keeping these fields separate prevents an A grade being displayed
 * as measured efficacy. */
export interface RuntimeVerification {
  status: 'not-tested' | 'measured'
  harness?: string
  environment?: string
  model?: string
  trials?: number
  baselinePassRate?: number
  withSkillPassRate?: number
  measuredAt?: string
  verifier?: 'deterministic' | 'human' | 'llm-judge'
}

export interface CatalogEvidence {
  scope: 'manifest' | 'bundle'
  sourceRef: string
  sourcePath: string
  sha256: string
}

export function isAutoMatchEligible(skill: StoreSkill): boolean {
  return (skill.grade === 'A' || skill.grade === 'B') && skill.gate === 'pass' && skill.risk === 'low'
}

function completeRuntime(skill: StoreSkill): boolean {
  const r = skill.runtime
  return r?.status === 'measured' && !!r.environment && !!r.harness && !!r.model && Number.isFinite(r.trials) && (r.trials ?? 0) > 0
}

export function runtimeLabel(skill: StoreSkill): 'runtime-verified' | 'incomplete' | 'not-tested' {
  if (completeRuntime(skill)) return 'runtime-verified'
  return skill.runtime?.status === 'measured' ? 'incomplete' : 'not-tested'
}

export function evidenceLabel(skill: StoreSkill): 'full-bundle' | 'manifest-only' | 'unknown' {
  if (skill.evidence?.scope === 'bundle') return 'full-bundle'
  if (skill.evidence?.scope === 'manifest') return 'manifest-only'
  return 'unknown'
}

/** One Skill's evidence, with broad claims withheld when runtime scope is absent. */
export function summarizeSkillEvidence(skill: StoreSkill): AssessmentEvidenceSummary {
  const runtime = runtimeLabel(skill)
  const measured = runtime === 'runtime-verified'
  const r = skill.runtime
  return {
    contractVersion: EVIDENCE_CONTRACT_VERSION,
    status: measured ? 'verified-here' : 'inspected',
    scope: 'skill',
    basis: measured ? ['inherited-rule', 'deterministic', 'runtime'] : ['inherited-rule', 'deterministic'],
    packageEvidence: evidenceLabel(skill),
    runtime: {
      status: measured ? 'measured' : runtime,
      ...(measured ? { environment: r?.environment, harness: r?.harness, model: r?.model, trials: r?.trials } : {}),
    },
    composition: { status: 'not-tested' },
    limitations: measured
      ? ['Result applies only to the declared model, harness, task set, and environment.']
      : [runtime === 'incomplete' ? 'Runtime metadata is incomplete; no efficacy claim is allowed.' : 'Runtime utility has not been tested.'],
  }
}

/**
 * Current goal matching is deterministic retrieval plus static trust gates. Even
 * when an individual Skill has runtime data, the exact ordered set is not verified
 * until the combination itself has a scoped run.
 */
export function summarizeCombinationEvidence(skills: StoreSkill[]): AssessmentEvidenceSummary {
  const packageLabels = new Set(skills.map(evidenceLabel))
  const packageEvidence = packageLabels.size === 1
    ? [...packageLabels][0]
    : packageLabels.size > 1
      ? 'mixed'
      : 'unknown'
  return {
    contractVersion: EVIDENCE_CONTRACT_VERSION,
    status: 'inspected',
    scope: 'combination',
    basis: ['inherited-rule', 'deterministic', 'heuristic'],
    packageEvidence,
    runtime: { status: 'not-tested' },
    composition: { status: 'not-tested' },
    limitations: [
      'Runtime utility has not been tested for this exact setup.',
      'Static conflict checks cannot prove that the ordered combination works in a real task.',
    ],
  }
}
