/**
 * Shared catalog shape used by the deterministic matching and trust modules.
 *
 * The hosted repository owns its larger store dataset. The public CLI commits only
 * the compact, audited match catalog in matchCatalog.ts, so this module deliberately
 * exports the type contract without duplicating private catalog data.
 */
export interface StoreSkill {
  name: string
  source: string
  url: string
  license: string
  category: string
  description: string
  grade: string
  score: number
  gate: string
  risk: string
  tokens: number
  findings: { severity: string; title: string; detail: string }[]
  capabilities: { cap: string; label?: string; severity: string }[]
  evidence?: { scope: 'manifest' | 'bundle'; sourceRef: string; sourcePath: string; sha256: string }
  runtime?: {
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
}
