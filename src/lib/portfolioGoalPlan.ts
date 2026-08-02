/**
 * Join the two previously separate answers:
 *   1. what to do with the Skills already installed; and
 *   2. what trusted Skill, if any, is still needed for the user's goal.
 *
 * Pure + framework-free so Web and CLI ship the same decision.
 */
import type { StoreSkill } from '@/data/seedSkills'
import { analyzeSkill } from './analyzeSkill'
import { planGoal, type MatchPlan, type PlannedSkill } from './bundleMatch'
import { composePortfolio, type PortfolioPlan, type PortfolioSkill } from './composePortfolio'
import { analyzePortfolio } from './conflictScan'
import { isAutoMatchEligible, summarizeCombinationEvidence, type AssessmentEvidenceSummary } from './skillTrust'

export interface SetupChange {
  action: 'add' | 'replace'
  skill: PlannedSkill
  reason: string
}
export interface PortfolioGoalPlan {
  portfolio: PortfolioPlan
  setup: MatchPlan
  alreadyInstalled: PlannedSkill[]
  changes: SetupChange[]
  evidence: AssessmentEvidenceSummary
}

const conflictCache = new WeakMap<StoreSkill[], Set<string>>()
function highConflicts(catalog: StoreSkill[]): Set<string> {
  const cached = conflictCache.get(catalog)
  if (cached) return cached
  const rows = analyzePortfolio(catalog.map((s) => ({ name: s.name, description: s.description }))).conflicts
  const value = new Set(rows.filter((c) => c.severity === 'high').flatMap((c) => [`${c.a}|${c.b}`, `${c.b}|${c.a}`]))
  conflictCache.set(catalog, value)
  return value
}

function asCatalogSkill(skill: PortfolioSkill, index: number): StoreSkill {
  const opts = skill.bundleText === undefined && skill.bundleFiles === undefined
    ? undefined
    : { bundleText: skill.bundleText, bundleFiles: skill.bundleFiles }
  const a = analyzeSkill(skill.md, opts)
  return {
    name: skill.name || a.frontmatter.name || `installed-${index + 1}`,
    source: 'installed',
    url: '',
    license: 'local',
    category: 'Installed',
    description: a.frontmatter.description ?? '',
    grade: a.overall.grade,
    score: a.overall.score,
    gate: a.overall.gate,
    risk: a.risk.level,
    tokens: a.tokens.total,
    findings: a.findings.map((f) => ({ severity: f.severity, title: f.title, detail: f.detail })),
    capabilities: a.capabilities.map((c) => ({ cap: c.cap, label: c.label, severity: c.severity })),
    evidence: {
      scope: skill.bundleFiles !== undefined ? 'bundle' : 'manifest',
      sourceRef: 'local',
      sourcePath: skill.name,
      sha256: 'local-not-exported',
    },
    runtime: { status: 'not-tested' },
  }
}

export function planPortfolioGoal(skills: PortfolioSkill[], goal: string, catalog: StoreSkill[]): PortfolioGoalPlan {
  const portfolio = composePortfolio(skills, goal)
  const installed = skills.map(asCatalogSkill)
  const installedNames = new Set(installed.map((s) => s.name.toLowerCase()))
  const eligibleInstalled = installed.filter(isAutoMatchEligible)
  const eligibleNames = new Set(eligibleInstalled.map((s) => s.name.toLowerCase()))

  // Installed candidates win same-name deduplication. An unsafe installed copy is
  // omitted, allowing the trusted catalog copy to become an explicit replacement.
  const seen = new Set<string>()
  const combined = [...eligibleInstalled, ...catalog].filter((s) => {
    const key = s.name.toLowerCase()
    if (seen.has(key)) return false
    seen.add(key)
    return isAutoMatchEligible(s)
  })
  const setup = planGoal(goal, combined, highConflicts(combined))
  const alreadyInstalled = setup.selected.filter((s) => s.skill.source === 'installed')
  const changes = setup.selected
    .filter((s) => s.skill.source !== 'installed')
    .map((skill): SetupChange => {
      const sameNameInstalled = installedNames.has(skill.skill.name.toLowerCase())
      const action = sameNameInstalled && !eligibleNames.has(skill.skill.name.toLowerCase()) ? 'replace' : 'add'
      return {
        action,
        skill,
        reason: action === 'replace'
          ? `The installed copy does not pass the automatic trust gate; replace it with the reviewed source before relying on it.`
          : `This trusted candidate covers the goal capability not selected from the current installed portfolio.`,
      }
    })
  const evidence = summarizeCombinationEvidence(setup.selected.map((s) => s.skill))
  return { portfolio, setup, alreadyInstalled, changes, evidence }
}
