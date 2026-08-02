/* oxlint-disable no-control-regex */
/** Tiny ANSI helpers — no dependency. Colors auto-disable off a TTY or with NO_COLOR. */
const on = !!process.stdout.isTTY && !process.env.NO_COLOR && process.env.TERM !== 'dumb'
/** Remove terminal control/invisible direction sequences from untrusted labels. */
export function safeTerminalText(value: string | number): string {
  return String(value)
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '')
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]/g, '')
    .replace(/[\u{e0000}-\u{e007f}]/gu, '')
    .replace(/[\r\n\t]+/g, ' ')
}
const w = (a: number, b: number) => (s: string | number) => {
  const safe = safeTerminalText(s)
  return on ? `\x1b[${a}m${safe}\x1b[${b}m` : safe
}

export const c = {
  bold: w(1, 22), dim: w(2, 22),
  red: w(31, 39), green: w(32, 39), yellow: w(33, 39), blue: w(34, 39), cyan: w(36, 39), gray: w(90, 39),
  onRed: w(41, 49),
}

/** visible length ignoring ANSI escapes, so padding lines up when colored */
export const vlen = (s: string): number => s.replace(/\x1b\[[0-9;]*m/g, '').length
/** greedy word wrap for explanatory prose — plain text only, apply colour after */
export function wrapTo(s: string, width: number): string[] {
  const out: string[] = []
  let line = ''
  for (const w of s.split(/\s+/)) {
    if (line && line.length + 1 + w.length > width) { out.push(line); line = w } else line = line ? line + ' ' + w : w
  }
  if (line) out.push(line)
  return out
}
export const padEndV = (s: string, n: number): string => s + ' '.repeat(Math.max(0, n - vlen(s)))

/** A → green, B → green, C → yellow, D → orange-ish, F → red. */
export function gradeBadge(g: string): string {
  const fn = g === 'A' || g === 'B' ? c.green : g === 'C' ? c.yellow : g === 'D' ? c.yellow : c.red
  return c.bold(fn(g))
}

export function bar(pct: number, width = 16): string {
  const n = Math.round((Math.max(0, Math.min(100, pct)) / 100) * width)
  return c.green('█'.repeat(n)) + c.gray('░'.repeat(width - n))
}
