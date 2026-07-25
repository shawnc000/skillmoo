/**
 * crossSkillScan — risks that only exist BETWEEN skills, so no single-file scan
 * can see them.
 *
 * conflictScan answers "which of these will fire?" (a retrieval question). This
 * answers "what can these do TOGETHER that neither does alone?" (a capability
 * question). A skill that only reads credentials is not an exfiltration path; a
 * skill that only posts to an endpoint is not either. Installed side by side in
 * one agent's tool surface, the pair is.
 *
 * ADVISORY BY CONSTRUCTION. These are capability observations across files the
 * user chose to install together, not proof of coordination — two skills sharing
 * a destination are usually two skills from the same vendor. So this reports and
 * never gates: the canon rule that only an unambiguous MUST-level safety finding
 * may block a skill stays intact, and nothing here changes a grade.
 */

export interface CrossSkillInput {
  name: string
  description?: string
  /** the skill body, including fenced code — required for capability pairing */
  body: string
}

export type CrossRiskKind = 'data-relay' | 'shared-destination' | 'shared-pattern' | 'chained-triggers'

export interface CrossRisk {
  kind: CrossRiskKind
  /** the skills involved, always ≥2 */
  skills: string[]
  title: string
  detail: string
  /** the concrete shared evidence (a host, a fragment, the tokens) */
  evidence: string[]
}

// Reads secret MATERIAL or the environment — the "source" half of a relay.
const READS_SECRET =
  /process\.env\b|\bos\.environ\b|\bENV\[|printenv\b|~\/\.ssh\/|\.aws\/credentials|\bid_rsa\b|\bid_ed25519\b|\.env\b|\b[A-Z_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z_]*\b/

// Sends somewhere — the "sink" half.
const SENDS =
  /\bfetch\s*\(|\baxios\b|requests?\.(?:post|put|patch)\s*\(|urllib|http\.client|\bcurl\b|\bwget\b|Net::HTTP|\bnc\b\s|\bscp\b|\bsftp\b/

// Hosts that are infrastructure, not a destination worth pairing on. Two skills
// both mentioning github.com is not a signal; two both posting to the same
// unfamiliar host is.
const WELL_KNOWN =
  /(?:^|\.)(?:github\.com|githubusercontent\.com|gitlab\.com|npmjs\.(?:com|org)|pypi\.org|crates\.io|golang\.org|go\.dev|python\.org|nodejs\.org|docker\.(?:com|io)|microsoft\.com|apple\.com|google\.com|googleapis\.com|cloudflare\.com|anthropic\.com|claude\.com|openai\.com|localhost|127\.0\.0\.1|example\.(?:com|org|net)|w3\.org|mozilla\.org|stackoverflow\.com|wikipedia\.org)$/i

function hostsIn(body: string): Set<string> {
  const out = new Set<string>()
  for (const m of body.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?/gi)) {
    const host = m[1].toLowerCase()
    if (!WELL_KNOWN.test(host)) out.add(host)
  }
  return out
}

/**
 * A "rare fragment" is a command line long enough to be distinctive. Identical
 * distinctive fragments across skills from different places is either copy-paste
 * or a coordinated payload — worth a look either way.
 */
function rareFragments(body: string): Set<string> {
  const out = new Set<string>()
  const fences = body.match(/```[\s\S]*?```/g) ?? []
  for (const f of fences) {
    for (const raw of f.split('\n')) {
      const line = raw.trim()
      if (line.length < 40 || line.startsWith('```') || line.startsWith('#')) continue
      // Only lines that DO something — a prose line in a fence is not a payload.
      if (!/[|>$]|\b(?:curl|wget|eval|base64|chmod|ssh|scp|nc|python3?|node|sh|bash)\b/.test(line)) continue
      out.add(line.replace(/\s+/g, ' '))
    }
  }
  return out
}

const inter = <T,>(a: Set<T>, b: Set<T>): T[] => [...a].filter((x) => b.has(x))

export function crossSkillRisks(skills: CrossSkillInput[]): CrossRisk[] {
  const s = skills
    .filter((x) => typeof x.body === 'string')
    .map((x) => ({
      name: x.name || '(unnamed)',
      reads: READS_SECRET.test(x.body),
      sends: SENDS.test(x.body),
      hosts: hostsIn(x.body),
      frags: rareFragments(x.body),
    }))

  const risks: CrossRisk[] = []

  // 1) DATA RELAY — one reads secrets and does NOT send; another sends. Neither
  //    is an exfil path alone. Skip a skill that already does both: that is a
  //    single-file finding analyzeSkill already reports, not a cross-skill one.
  const sources = s.filter((x) => x.reads && !x.sends)
  const sinks = s.filter((x) => x.sends && !x.reads)
  for (const src of sources) {
    for (const sink of sinks) {
      risks.push({
        kind: 'data-relay',
        skills: [src.name, sink.name],
        title: 'Credential read and network send split across two installed skills',
        detail: `"${src.name}" reads secrets but never sends; "${sink.name}" sends but never reads. Each is benign alone. Sharing one agent's tool surface, they compose into a path from your credentials to the network. Review whether both need to be installed together.`,
        evidence: [`${src.name}: reads secrets`, `${sink.name}: network send`],
      })
    }
  }

  // 2) SHARED DESTINATION — two skills reaching the same non-well-known host.
  for (let i = 0; i < s.length; i++) {
    for (let j = i + 1; j < s.length; j++) {
      const shared = inter(s[i].hosts, s[j].hosts)
      if (!shared.length) continue
      risks.push({
        kind: 'shared-destination',
        skills: [s[i].name, s[j].name],
        title: 'Two skills reach the same third-party host',
        detail: `Both reference ${shared.join(', ')}. Usually this just means one vendor shipped both. It matters when you did not install them from the same place: a common destination across independent skills concentrates whatever they send.`,
        evidence: shared,
      })
    }
  }

  // 3) SHARED PATTERN — the same distinctive command in more than one skill.
  for (let i = 0; i < s.length; i++) {
    for (let j = i + 1; j < s.length; j++) {
      const shared = inter(s[i].frags, s[j].frags)
      if (!shared.length) continue
      risks.push({
        kind: 'shared-pattern',
        skills: [s[i].name, s[j].name],
        title: 'Identical command block appears in two skills',
        detail: `The same distinctive command appears verbatim in both. That is copy-paste between skills, or one payload propagated into several — either way, reviewing it once covers both.`,
        evidence: shared.slice(0, 2).map((f) => (f.length > 120 ? f.slice(0, 117) + '…' : f)),
      })
    }
  }

  return risks
}
