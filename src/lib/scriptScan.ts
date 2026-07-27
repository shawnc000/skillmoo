/**
 * scriptScan — the "Level 1" step: from *what a skill says* to *what its
 * embedded scripts can actually do*.
 *
 * It pulls the fenced code blocks out of a SKILL.md, classifies each command
 * into a CAPABILITY (network egress, filesystem write, code execution,
 * privilege, secret access, package install, encoded exec), and runs a light
 * TAINT pass: a script that reads a secret AND talks to the network is an
 * exfiltration path — reported as a source→sink dataflow finding, not a
 * keyword hit. This is the browser-side mirror of the semgrep rules in
 * `rules/skill-scripts.yml` (see scripts/scan-skill.ts for the backend path).
 */
import type { Finding, Severity } from './analyzeSkill'

export type Capability =
  | 'network' | 'filesystem' | 'exec' | 'privilege' | 'secret' | 'install' | 'encoded'

export interface CapabilityHit {
  cap: Capability
  label: string
  detail: string
  severity: Severity
}

export interface ScriptScan {
  scriptCount: number
  capabilities: CapabilityHit[]
  findings: Finding[]
}

// Bounded header ([^\n]{0,240} not [^\n]*) so a degenerate run of ``` can't force
// O(n²) backtracking while hunting a newline that isn't there.
const FENCE = /```([a-zA-Z0-9_+-]*)[^\n]{0,240}\n([\s\S]*?)```/g
const SCRIPT_LANGS = new Set([
  'bash', 'sh', 'shell', 'zsh', 'console', 'shellscript', 'ps1', 'powershell',
  'python', 'py', 'python3', 'javascript', 'js', 'node', 'typescript', 'ts',
  'ruby', 'rb', 'perl',
])
// empty-lang fence still counts as a script if it looks like commands
const SHELLISH = /(^|\n)\s*(?:curl|wget|rm|sudo|cat|echo|export|pip3?|npm|apt|brew|chmod|chown|ssh|scp|nc|bash|sh|eval|python3?|node|base64)\b/

function extractScripts(md: string): { lang: string; code: string }[] {
  const out: { lang: string; code: string }[] = []
  FENCE.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = FENCE.exec(md))) {
    const lang = m[1].toLowerCase()
    const code = m[2]
    if (SCRIPT_LANGS.has(lang) || (lang === '' && SHELLISH.test(code))) {
      out.push({ lang: lang || 'sh', code })
    }
  }
  return out
}

interface Behavior {
  cap: Capability
  label: string
  severity: Severity
  re: RegExp
  detail: string
}

const BEHAVIORS: Behavior[] = [
  // curl|sh runs remote code but is ALSO the standard installer for uv/rustup/brew;
  // HIGH → review, not critical/block (source unverifiable ≠ proven malice). Raw-IP
  // curl|sh, decode-pipe-to-shell, and reverse shells below stay critical/block.
  { cap: 'exec', label: 'Executes code', severity: 'high', re: /\b(?:curl|wget)\b[^\n|]{0,120}\|\s*(?:sudo\s+)?(?:ba)?sh\b/i, detail: 'downloads a remote script and runs it (curl | sh) — verify the source' },
  { cap: 'exec', label: 'Executes code', severity: 'critical', re: /\/dev\/tcp\/\d|\bnc\b[^\n]{0,30}\s-e\b|\bncat\b[^\n]{0,30}--exec|\b(?:ba)?sh\s+-i\b[^\n]{0,24}(?:>&|<&|\d>&)|mkfifo\b[^\n]{0,50}\|\s*(?:ba)?sh|\b(?:nc|ncat|socat)\b[^\n]{0,40}\b\d{2,5}\b[^\n]{0,20}\|\s*(?:sudo\s+)?(?:\/\S*\/)?(?:ba|z)?sh\b|\bsocat\b[^\n]{0,60}\bexec:\s*\/?\S*\/?(?:ba|z)?sh\b|python3?\s+-c[^\n]{0,90}(?:pty\.spawn|socket\.socket[^\n]{0,60}connect)/i, detail: 'opens a reverse shell (nc -e, /dev/tcp, bash -i >&, mkfifo backpipe, nc host port | sh) — full remote control' },
  { cap: 'encoded', label: 'Runs encoded content', severity: 'critical', re: /(?:base64\s+(?:-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d|gunzip|zcat)[^\n]{0,50}\|\s*(?:sudo\s+)?(?:ba)?sh\b|eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)/i, detail: 'decodes hidden content and pipes it straight to a shell / eval — obfuscated execution' },
  { cap: 'encoded', label: 'Runs encoded content', severity: 'high', re: /base64\s+-d|openssl\s+enc\s+-d|xxd\s+-r|atob\s*\(|\|\s*base64\b/i, detail: 'decodes then executes hidden content' },
  { cap: 'exec', label: 'Executes code', severity: 'high', re: /\beval\b|\bexec\s*\(|\bsh\s+-c\b|\bbash\s+-c\b|python3?\s+-c\b|node\s+-e\b|os\.system|subprocess\.|child_process/i, detail: 'dynamic code / subprocess execution' },
  { cap: 'secret', label: 'Reads secrets', severity: 'high', re: /~\/\.ssh|\.aws\/credentials|\bid_rsa\b|\/etc\/(?:passwd|shadow)|\.env\b|printenv|process\.env|os\.environ|\$[A-Za-z_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CRED)[A-Za-z_]*/i, detail: 'reads keys, tokens, or credential files' },
  { cap: 'network', label: 'Network egress', severity: 'medium', re: /\b(?:curl|wget|nc|ncat|netcat|scp|sftp|rsync|ftp|telnet)\b|requests\.(?:get|post)|urllib|http\.client|socket\.|\bfetch\s*\(|\baxios\b/i, detail: 'sends or fetches data over the network' },
  { cap: 'privilege', label: 'Escalates privilege', severity: 'medium', re: /\bsudo\b|\bdoas\b|chmod\s+(?:\+x|777|u\+s)|\bchown\b|setcap\b/i, detail: 'sudo / chmod / chown' },
  { cap: 'filesystem', label: 'Writes / deletes files', severity: 'medium', re: /\brm\s+-[a-z]*[rf]|\bunlink\b|shutil\.rmtree|fs\.(?:unlink|rm|writeFile)|>\s*\/|(?:^|\s)(?:tee|dd|truncate|shred)\b/i, detail: 'modifies or deletes files' },
  { cap: 'install', label: 'Installs packages', severity: 'medium', re: /\b(?:pip3?|npm|pnpm|yarn|apt|apt-get|brew|gem|go|cargo)\b[^\n]{0,40}\b(?:install|add)\b/i, detail: 'pulls third-party packages (supply chain)' },
]

// Sensitive credential MATERIAL / FILES (not just a $API_KEY env var). Reading
// these + network is a genuine theft flow; reading a config env var + network is
// just an API/deploy client. This is what gates a benign capability from a
// CRITICAL exfil verdict — static analysis sees the flow, not the intent.
const SENSITIVE_SECRET_RE = /~\/\.ssh\/\S+|\.aws\/credentials|\bid_rsa\b|\bid_ed25519\b|\/etc\/(?:passwd|shadow)|-----BEGIN[A-Z\s]*PRIVATE KEY/i

/**
 * A LOOPBACK / private / link-local / documentation address is not an exfiltration
 * destination — it is where a local dev server binds (`127.0.0.1`, `0.0.0.0`, `192.168.x.x`)
 * or a doc example. Only a ROUTABLE literal IP carries the "skipped DNS on purpose" signal
 * this gates on. Prefixes are ^-anchored and dot-terminated so `100.64.x`, `172.160.x` and
 * `10x.x.x.x` are correctly treated as public.
 */
const LOCAL_IP_RE = /^(?:127\.|0\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|255\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/

/**
 * IPs that are actually a DESTINATION — a URL host, or the target of a transfer command.
 * Restricting to destinations is mandatory, not cosmetic: scanning every IP-shaped string
 * false-flagged a real skill whose reference doc merely DOCUMENTS an allowlist CIDR. And
 * scanning only the FIRST host in the bundle (the previous behaviour) meant one comment
 * containing `127.0.0.1` anywhere above the payload disarmed the check for the whole bundle.
 */
const destIps = (txt: string): string[] => {
  const out: string[] = []
  for (const m of txt.matchAll(/https?:\/\/(?:[^/@\s]*@)?((?:\d{1,3}\.){3}\d{1,3})(?=[:/?#\s"')]|$)/gi)) out.push(m[1])
  for (const m of txt.matchAll(/\b(?:curl|wget|nc|ncat|netcat|scp|sftp|rsync|telnet|ssh)\b[^\n]{0,80}?\b((?:\d{1,3}\.){3}\d{1,3})\b/gi)) out.push(m[1])
  return out
}

const CAP_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 }

export function scanScripts(md: string, opts?: { defensivePurpose?: boolean }): ScriptScan {
  const scripts = extractScripts(md)
  const capabilities: CapabilityHit[] = []
  const findings: Finding[] = []
  const seenCap = new Map<Capability, CapabilityHit>()

  let anySecret = false
  let anyNetwork = false
  let sensitiveSecret = false

  for (const { code } of scripts) {
    for (const b of BEHAVIORS) {
      if (!b.re.test(code)) continue
      const existing = seenCap.get(b.cap)
      if (!existing || CAP_ORDER[b.severity] < CAP_ORDER[existing.severity]) {
        seenCap.set(b.cap, { cap: b.cap, label: b.label, detail: b.detail, severity: b.severity })
      }
      if (b.cap === 'secret') anySecret = true
      if (b.cap === 'network') anyNetwork = true
    }
    if (SENSITIVE_SECRET_RE.test(code)) sensitiveSecret = true
  }

  for (const c of seenCap.values()) capabilities.push(c)
  capabilities.sort((a, b) => CAP_ORDER[a.severity] - CAP_ORDER[b.severity])

  // TAINT / dataflow: reads a secret AND reaches the network. This is ALSO the
  // shape of any API/deploy script, so we assert a CRITICAL exfiltration flow
  // ONLY with a real malice signal — reading sensitive key MATERIAL/files, an
  // obfuscated/encoded payload, or a raw-IP destination. A config env var
  // (`$API_KEY`) + a normal HTTPS host is a benign client (analyzeSkill already
  // notes it at REVIEW level) — flagging it CRITICAL would mislead.
  if (anySecret && anyNetwork) {
    // Only DECODE-and-run obfuscation (base64 -d | sh = critical) is a malice
    // co-signal. Plain base64 ENCODING (`… | base64`) is the STANDARD HTTP Basic
    // Auth pattern (Jira/GitHub encode `email:token` for the header) — benign, not
    // obfuscation; counting it flagged every auth-client script as exfiltration.
    const encoded = seenCap.get('encoded')?.severity === 'critical'
    // Every script, not just the first host, and only genuine destinations. `http://127.0.0.1@45.77.12.9/`
    // (userinfo obfuscation) resolves to the routable half, which is what this now reads.
    const rawIp = scripts.some(({ code }) => destIps(code).some((ip) => !LOCAL_IP_RE.test(ip)))
    if (sensitiveSecret || encoded || rawIp) {
      // Real MECHANICS block regardless: decode-and-run, or key MATERIAL sent to a raw
      // IP (a genuine key→IP flow). But a raw IP ALONE, in a security-hardening skill,
      // is usually a WAF/allowlist EXAMPLE (`ipAllowlist(["1.2.3.4"])`), not an exfil
      // destination — so for a defensive-purpose skill it does not force block unless
      // paired with actual key material. A real key→raw-IP exfil (sensitiveSecret &&
      // rawIp) still blocks even with a "security" description → no evasion hole.
      const mechanics = encoded || (rawIp && sensitiveSecret)
      findings.push(opts?.defensivePurpose && !mechanics ? {
        severity: 'medium',
        category: 'exfil',
        title: 'Credential + network in a security-analysis skill — verify it is an example',
        detail: 'A script references credential material and reaches the network. In a security-analysis / detection skill these are usually examples — verify they are, not an actual key→network flow.',
      } : {
        severity: 'critical',
        category: 'exfil',
        title: 'Exfiltration path in an embedded script',
        detail: `A script reads ${sensitiveSecret ? 'sensitive credentials' : 'a secret'} and ${rawIp ? 'sends them to a raw IP address' : encoded ? 'hides code behind encoding' : 'reaches the network'} — a data-theft flow, not the benign API-client pattern.`,
      })
    }
  }

  // Elevate the two most dangerous capabilities into explicit findings too.
  for (const c of capabilities) {
    if (c.severity === 'critical') {
      findings.push({ severity: 'critical', category: 'shell', title: `Script capability: ${c.label.toLowerCase()}`, detail: `An embedded script ${c.detail}.` })
    }
  }

  return { scriptCount: scripts.length, capabilities, findings }
}
