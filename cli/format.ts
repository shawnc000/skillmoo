/** Tiny ANSI helpers — no dependency. Colors auto-disable off a TTY or with NO_COLOR. */
const on = !!process.stdout.isTTY && !process.env.NO_COLOR && process.env.TERM !== 'dumb'
const w = (a: number, b: number) => (s: string | number) => (on ? `\x1b[${a}m${s}\x1b[${b}m` : `${s}`)

export const c = {
  bold: w(1, 22), dim: w(2, 22),
  red: w(31, 39), green: w(32, 39), yellow: w(33, 39), blue: w(34, 39), cyan: w(36, 39), gray: w(90, 39),
  onRed: w(41, 49),
}

/** visible length ignoring ANSI escapes, so padding lines up when colored */
export const vlen = (s: string): number => s.replace(/\x1b\[[0-9;]*m/g, '').length
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
