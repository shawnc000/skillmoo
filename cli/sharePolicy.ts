import type { ReportData } from './report-html'

/** Network policy for the otherwise-local scan command. Pure for regression tests. */
export function shouldPublishScan(argv: string[], envNoShare = false): boolean {
  const noShare = argv.includes('--no-share') || envNoShare
  return argv.includes('--publish') && !noShare
}

/**
 * Build the deliberately anonymous hosted-report payload. Local HTML keeps the
 * rich evidence; publishing keeps only ordinal labels and derived verdicts.
 */
export function buildPublishReport(data: ReportData): ReportData {
  const labels = new Map(data.skills.map((skill, index) => [skill.name, `skill-${index + 1}`]))
  const label = (name: string) => labels.get(name) ?? 'skill-unlisted'
  return {
    generatedAt: data.generatedAt,
    locations: data.locations.map((location) => ({ source: 'local', dir: '', count: location.count })),
    skills: data.skills.map((skill) => ({
      name: label(skill.name), source: 'local', path: '',
      a: { findings: skill.a.findings.map((finding) => ({
        severity: finding.severity, category: finding.category, title: '', detail: '',
      })) },
      tokens: skill.tokens, grade: skill.grade, unsafe: skill.unsafe, review: skill.review,
      bloated: skill.bloated, bloatRatio: skill.bloatRatio,
      reason: skill.unsafe ? 'unsafe' : skill.review ? 'review' : skill.bloated ? 'bloated' : 'clean',
    })),
    conflicts: data.conflicts.map((conflict) => ({ a: label(conflict.a), b: label(conflict.b), kind: conflict.kind, severity: conflict.severity, shared: [] })),
    broad: data.broad.map(label), median: data.median, bloatThresh: data.bloatThresh,
    optimizable: false, lang: data.lang,
  }
}
