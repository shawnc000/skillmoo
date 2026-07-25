/**
 * listingBudget — the SKILL LISTING is a fixed-size budget, and past a certain
 * portfolio size the harness silently starts throwing your descriptions away.
 *
 * Every installed skill's `name` + `description` is loaded into the system prompt
 * at startup and re-sent every turn (Anthropic: "Level 1: Metadata (always
 * loaded) … ~100 tokens per Skill"). That listing is CAPPED. When it overflows,
 * the harness does not warn — it drops or truncates descriptions, and a skill
 * whose description is gone stops being matched against the user's request.
 *
 * That is the mechanism behind the real-world reports ("Showing 30 of 39 skills
 * due to token limits") and behind truncation cutting a "DO NOT TRIGGER when …"
 * clause off the end of a description so the skill then MIS-fires.
 *
 * This models it deterministically: no model call, no measurement, pure
 * arithmetic over the published per-harness caps. What we can state as fact is
 * the OVERFLOW and HOW MANY entries must lose their description. What we can NOT
 * know is WHICH ones — Claude Code drops "starting with the skills you invoke
 * least", and invocation history lives on the user's machine, not in the files.
 * We say so rather than guessing.
 */

export interface HarnessListing {
  id: string
  label: string
  /** fraction of the context window reserved for the listing */
  fraction: number
  /**
   * Token window the fraction is computed against. Claude Code computes 1% off a
   * FIXED ~200K baseline rather than the live model window, so on a larger-context
   * model the effective budget does not grow (claude-code#57941, open).
   */
  baselineTokens: number
  /** hard per-entry cap on description characters, if the harness sets one */
  maxDescChars?: number
  /** what happens on overflow */
  overflow: 'drop-descriptions' | 'truncate-then-omit'
  /** whether names always survive (so the skill is still invokable by name) */
  namesAlwaysKept: boolean
  source: string
}

/**
 * Published caps only. Each entry cites where the number comes from so a reader
 * can re-derive it; when a harness publishes no cap we do not invent one.
 */
export const HARNESS_LISTINGS: HarnessListing[] = [
  {
    id: 'claude-code',
    label: 'Claude Code',
    fraction: 0.01,
    baselineTokens: 200_000,
    maxDescChars: 1536,
    overflow: 'drop-descriptions',
    namesAlwaysKept: true,
    source: 'settings: skillListingBudgetFraction (default 0.01) · skillListingMaxDescChars (1536) — "drops descriptions starting with the skills you invoke least"; the listing always contains every skill name',
  },
  {
    id: 'codex',
    label: 'OpenAI Codex',
    fraction: 0.02,
    baselineTokens: 400_000,
    overflow: 'truncate-then-omit',
    namesAlwaysKept: false,
    source: 'codex-rs/core-skills/src/render.rs: SKILL_METADATA_CONTEXT_WINDOW_PERCENT = 2, DEFAULT_SKILL_METADATA_CHAR_BUDGET = 8_000 — truncates descriptions char-by-char, then omits whole skills by scope priority',
  },
]

/** Codex's absolute char floor when the percentage cannot be resolved. */
const CODEX_CHAR_FLOOR = 8_000

export interface ListingEntry {
  name: string
  description: string
}

export interface ListingVerdict {
  harness: string
  harnessLabel: string
  skills: number
  /** tokens the listing occupies, as installed */
  listingTokens: number
  /** tokens available before the harness starts cutting */
  budgetTokens: number
  overflows: boolean
  /** tokens over budget (0 when it fits) */
  overBy: number
  /**
   * How many entries must lose their description for the listing to fit, using
   * the harness's own documented policy. WHICH ones is not knowable from the
   * files (Claude Code drops least-invoked first), so we report only the count.
   */
  entriesLosingDescription: number
  /** entries whose description exceeds the harness's per-entry char cap */
  overLongEntries: { name: string; chars: number; cap: number }[]
  /** the portfolio size at which this harness starts cutting, all else equal */
  cliffAt: number
  detail: string
  source: string
}

/**
 * ~4 chars/token for Latin text; CJK runs ~1.5 chars/token, so count those
 * separately or a Chinese description reads as 2-3x cheaper than it bills.
 */
export function listingTokens(text: string): number {
  const cjk = (text.match(/[㐀-䶿一-鿿぀-ヿ가-힯]/g) ?? []).length
  const rest = text.length - cjk
  return Math.ceil(cjk / 1.5 + rest / 4)
}

/**
 * Per-entry listing cost. The harness renders name + description (plus a little
 * structural framing); we bill the text and add a small fixed per-entry overhead
 * rather than pretending the framing is free.
 */
const ENTRY_OVERHEAD_TOKENS = 4

function entryTokens(e: ListingEntry): number {
  return listingTokens(`${e.name} ${e.description}`) + ENTRY_OVERHEAD_TOKENS
}

export function budgetFor(h: HarnessListing): number {
  const byFraction = Math.floor(h.baselineTokens * h.fraction)
  // Codex resolves a char budget, not a token budget; its documented floor is
  // 8,000 chars, which is the binding constraint when it is the smaller of the two.
  if (h.id === 'codex') return Math.min(byFraction, Math.ceil(CODEX_CHAR_FLOOR / 4))
  return byFraction
}

/**
 * Judge one portfolio against one harness. Deterministic: same input → same verdict.
 */
export function judgeListing(entries: ListingEntry[], h: HarnessListing): ListingVerdict {
  const budgetTokens = budgetFor(h)
  const costs = entries
    .map((e) => ({ name: e.name || '(unnamed)', desc: e.description ?? '', cost: entryTokens(e) }))
    .sort((a, b) => b.cost - a.cost)
  const listingTotal = costs.reduce((n, c) => n + c.cost, 0)
  const overflows = listingTotal > budgetTokens
  const overBy = Math.max(0, listingTotal - budgetTokens)

  // How many entries must lose their description to fit. Names survive on Claude
  // Code, so a dropped entry still bills its name; on Codex a whole entry can go.
  let entriesLosingDescription = 0
  if (overflows) {
    let running = listingTotal
    for (const c of costs) {
      if (running <= budgetTokens) break
      const nameOnly = h.namesAlwaysKept ? listingTokens(c.name) + ENTRY_OVERHEAD_TOKENS : 0
      running -= c.cost - nameOnly
      entriesLosingDescription++
    }
  }

  const overLongEntries = h.maxDescChars
    ? costs.filter((c) => c.desc.length > h.maxDescChars!).map((c) => ({ name: c.name, chars: c.desc.length, cap: h.maxDescChars! }))
    : []

  // The cliff: with this portfolio's own average entry cost, how many skills fit?
  const avg = entries.length ? listingTotal / entries.length : 0
  const cliffAt = avg > 0 ? Math.floor(budgetTokens / avg) : 0

  const detail = overflows
    ? `${entries.length} skills need ${listingTotal.toLocaleString()} listing tokens but ${h.label} reserves ${budgetTokens.toLocaleString()}. ` +
      (h.overflow === 'drop-descriptions'
        ? `${entriesLosingDescription} description${entriesLosingDescription > 1 ? 's' : ''} will be dropped (names are kept, so the skills stay invokable by name but stop being auto-matched). Which ones depends on your invocation history — the harness drops least-invoked first — so we do not name them.`
        : `${entriesLosingDescription} entr${entriesLosingDescription > 1 ? 'ies' : 'y'} will be truncated, and whole skills can be omitted by scope priority once names alone no longer fit.`)
    : `${entries.length} skills fit ${h.label}'s listing (${listingTotal.toLocaleString()} of ${budgetTokens.toLocaleString()} tokens). At this portfolio's average entry cost, cutting starts around ${cliffAt} skills.`

  return {
    harness: h.id,
    harnessLabel: h.label,
    skills: entries.length,
    listingTokens: listingTotal,
    budgetTokens,
    overflows,
    overBy,
    entriesLosingDescription,
    overLongEntries,
    cliffAt,
    detail,
    source: h.source,
  }
}

/** Judge a portfolio against every harness with a published cap. */
export function judgeAllListings(entries: ListingEntry[]): ListingVerdict[] {
  return HARNESS_LISTINGS.map((h) => judgeListing(entries, h))
}

/**
 * ALWAYS-ON cost: what the portfolio bills every turn regardless of whether any
 * skill fires. This is deliberately separate from a skill's full body size —
 * conflating the two overstates the standing cost by an order of magnitude,
 * because a body is only paid when that skill actually activates.
 */
export function alwaysOnTokens(entries: ListingEntry[]): number {
  return entries.reduce((n, e) => n + entryTokens(e), 0)
}
