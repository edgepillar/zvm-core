// Every number a person reads, in one copy.
//
// Exact quantities, always mono. Trailing zeros are dimmed, not rounded away —
// the caller splits on the decimal point where that matters.
//
// The only thing an app gets to choose is what these print when there is
// nothing to print: see `empty` in config.ts. Each function also takes that as
// a last argument, for the call sites that want a different one.

import {empty} from './config'

export function units(
  value: string | bigint | number | null | undefined,
  decimals: number,
  maxFrac = 6,
  dash?: string,
): string {
  if (value === null || value === undefined || value === '') return empty(dash)
  const v = typeof value === 'bigint' ? value : BigInt(value)
  const negative = v < 0n
  const abs = negative ? -v : v
  const base = 10n ** BigInt(decimals)
  const whole = abs / base
  const full = (abs % base).toString().padStart(decimals, '0')
  let frac = full.slice(0, maxFrac).replace(/0+$/, '')
  // Never show a non-zero amount as 0: a 1 gwei transfer is 0.000000001 ZNN,
  // and cutting it at six places printed "0 ZNN" for a transaction that did
  // move value. Past the cut, keep going to the first two significant digits.
  if (whole === 0n && frac === '' && abs !== 0n) {
    const first = full.search(/[1-9]/)
    frac = full.slice(0, first + 2).replace(/0+$/, '')
  }
  const grouped = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')
  return `${negative ? '-' : ''}${grouped}${frac ? '.' + frac : ''}`
}

/** ZNN on the ZVM, which is 18 decimals like every other EVM native token. */
export const znn = (wei: string | bigint | null | undefined, maxFrac = 6, dash?: string) =>
  units(wei, 18, maxFrac, dash)

/** The same token on NoM, where it has 8 decimals and not 18. */
export const nomUnits = (raw: string | bigint | null | undefined, maxFrac = 8, dash?: string) =>
  units(raw, 8, maxFrac, dash)

/** The same value, unformatted, for putting back into an input. */
export function plain(value: bigint, decimals: number): string {
  const base = 10n ** BigInt(decimals)
  const whole = value / base
  const frac = (value % base).toString().padStart(decimals, '0').replace(/0+$/, '')
  return frac ? `${whole}.${frac}` : whole.toString()
}

/**
 * A quantity at the precision its own size deserves. A fixed number of decimals
 * turns a small trade into a zero, which is worse than a long number.
 */
export function amount(v: number | null | undefined, opts: {dash?: string} = {}): string {
  if (v === null || v === undefined || !isFinite(v)) return empty(opts.dash)
  const abs = Math.abs(v)
  if (abs === 0) return '0'
  if (abs >= 1000) return v.toLocaleString('en-US', {maximumFractionDigits: 2})
  if (abs >= 1) return v.toLocaleString('en-US', {maximumFractionDigits: 4})
  return v.toLocaleString('en-US', {maximumSignificantDigits: 4})
}

/** A price, which needs significant digits rather than a fixed number of places. */
export function price(v: number | null | undefined, dash?: string): string {
  if (v === null || v === undefined || !isFinite(v) || v <= 0) return empty(dash)
  if (v >= 1000) return v.toLocaleString('en-US', {maximumFractionDigits: 2})
  return String(Number(v.toPrecision(6)))
}

/**
 * Dollars, at the precision the size of the number deserves.
 *
 * `compact` is for a figure whose magnitude is the point — a pool's liquidity,
 * a day's volume. It is never used for a balance or a price, where the digits
 * are what the reader came for.
 */
export function usd(value: number | null | undefined, opts: {compact?: boolean; dash?: string} = {}): string {
  if (value === null || value === undefined || !isFinite(value)) return empty(opts.dash)
  const abs = Math.abs(value)
  if (opts.compact && abs >= 10_000) {
    return `$${value.toLocaleString('en-US', {notation: 'compact', maximumFractionDigits: 1})}`
  }
  const digits = abs >= 1 ? 2 : abs >= 0.01 ? 4 : abs > 0 ? 6 : 2
  return `$${value.toLocaleString('en-US', {minimumFractionDigits: Math.min(2, digits), maximumFractionDigits: digits})}`
}

/** A signed percentage, for a 24-hour change. Always signed: +0.00% and 0.00%
 * say different things, and a change of exactly nothing is worth showing. */
export function change(fraction: number | null | undefined, dash?: string): string {
  if (fraction === null || fraction === undefined || !isFinite(fraction)) return empty(dash)
  const pct = fraction * 100
  return `${pct >= 0 ? '+' : ''}${pct.toFixed(2)}%`
}

/** Which way a change should be coloured. Zero and null are both plain. */
export function changeTone(fraction: number | null | undefined): 'good' | 'bad' | 'plain' {
  if (!fraction) return 'plain'
  return fraction > 0 ? 'good' : 'bad'
}

export function number(n: number | string | null | undefined, dash?: string): string {
  if (n === null || n === undefined) return empty(dash)
  return Number(n).toLocaleString('en-US')
}

export function short(id: string | null | undefined, head = 8, tail = 6, dash?: string): string {
  if (!id) return empty(dash)
  if (id.length <= head + tail + 1) return id
  return `${id.slice(0, head)}…${id.slice(-tail)}`
}

// ZNN's green and QSR's blue, the exact marketing hexes (style.css), applied
// wherever the token itself is named — not to every number denominated in
// it — so a copycat token sharing the symbol still can't borrow the color.
const BRAND_COLOR: Record<string, string> = {
  ZNN: 'var(--znn)',
  WZNN: 'var(--znn)',
  QSR: 'var(--nom-ink)',
  WQSR: 'var(--nom-ink)',
}

export function tokenColor(symbol?: string | null): string | undefined {
  return symbol ? BRAND_COLOR[symbol.toUpperCase()] : undefined
}

/** The Token tracker's naming scheme: "MyToken (MTK)", either half optional. */
export function tokenLabel(name?: string | null, symbol?: string | null): string {
  if (name && symbol) return `${name} (${symbol})`
  return name || symbol || ''
}

export function ago(timestamp: number | null | undefined, dash?: string): string {
  if (!timestamp) return empty(dash)
  const secs = Math.max(0, Math.floor(Date.now() / 1000 - timestamp))
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`
  return `${Math.floor(secs / 86400)}d ago`
}

export function timestamp(ts: number | null | undefined, dash?: string): string {
  if (!ts) return empty(dash)
  return new Date(ts * 1000).toISOString().replace('T', ' ').replace('.000Z', 'Z')
}

export function gwei(wei: string | number | bigint | null | undefined, dash?: string): string {
  if (wei === null || wei === undefined) return empty(dash)
  const v = Number(wei) / 1e9
  if (v === 0) return '0'
  return v < 0.001 ? v.toExponential(2) : v.toFixed(v < 1 ? 4 : 2)
}

/**
 * A base-fee-sized wei quantity, always in gwei.
 *
 * Gwei is the unit every EVM tool quotes a base fee in, so switching to wei
 * below a whole gwei made this chain's floor read as "1,000,000" next to
 * another chain's "150" — two numbers four orders of magnitude apart in
 * apparent size that are nothing of the sort. A sub-gwei fee keeps its
 * significant digits instead of rounding to 0.00.
 */
export function baseFeeUnits(wei: string | number | bigint | null | undefined, dash?: string): string {
  if (wei === null || wei === undefined || wei === '') return empty(dash)
  let w: bigint
  try {
    w = BigInt(typeof wei === 'number' ? Math.trunc(wei) : wei)
  } catch {
    return empty(dash)
  }
  if (w < 0n) return empty(dash)
  const GWEI = 1_000_000_000n
  const group = (s: string) => s.replace(/\B(?=(\d{3})+(?!\d))/g, ',')
  if (w === 0n) return '0 gwei'
  if (w % GWEI === 0n) return `${group((w / GWEI).toString())} gwei`
  const v = Number(w) / 1e9
  if (v >= 1) return `${v.toFixed(2)} gwei`
  // A wei is 0.000000001 gwei, so nine places covers every value; trailing
  // zeros are dropped rather than padding the column with noise.
  return `${v.toFixed(9).replace(/0+$/, '').replace(/\.$/, '')} gwei`
}

export function bytes(n: number | null | undefined, dash?: string): string {
  if (n === null || n === undefined || !isFinite(n)) return empty(dash)
  const names = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = n
  let i = 0
  while (Math.abs(v) >= 1024 && i < names.length - 1) {
    v /= 1024
    i++
  }
  return i === 0 ? `${Math.round(v)} B` : `${v.toFixed(i === 1 ? 1 : 2)} ${names[i]}`
}

/**
 * A byte axis label, at the unit and precision the tick step needs: a disk that
 * grew 4 MB on 1.8 GB reads 1,843 MB, 1,845 MB rather than 1.80 GB twice.
 */
export function bytesAxis(v: number, step: number): string {
  const names = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (i < names.length - 1 && 1024 ** (i + 1) <= Math.max(Math.abs(v), step) && 1024 ** (i + 1) <= step * 100) i++
  const unit = 1024 ** i
  const decimals = i === 0 ? 0 : Math.max(0, Math.min(2, Math.ceil(-Math.log10(step / unit))))
  return `${(v / unit).toLocaleString('en-US', {minimumFractionDigits: decimals, maximumFractionDigits: decimals})} ${names[i]}`
}

const compactFormat = new Intl.NumberFormat('en-US', {notation: 'compact', maximumFractionDigits: 1})

/** An axis label: 1.2K, 3.4M. Never for a value a reader acts on. */
export const compact = (n: number) => compactFormat.format(n)

/** A share, at the precision a small one needs. */
export function percent(share: number | null | undefined, dash?: string): string {
  if (share === null || share === undefined || !isFinite(share)) return empty(dash)
  const pct = share * 100
  if (pct === 0) return '0%'
  return `${pct.toFixed(pct < 0.1 ? 3 : pct < 10 ? 2 : 1)}%`
}

/** Seconds as the two largest units: 3d 4h, 12m 5s. */
export function duration(seconds: number | null | undefined, dash?: string): string {
  if (seconds === null || seconds === undefined || !isFinite(seconds)) return empty(dash)
  const s = Math.max(0, Math.floor(seconds))
  const parts: [number, string][] = [
    [Math.floor(s / 86400), 'd'],
    [Math.floor((s % 86400) / 3600), 'h'],
    [Math.floor((s % 3600) / 60), 'm'],
    [s % 60, 's'],
  ]
  const first = parts.findIndex(([v]) => v > 0)
  if (first < 0) return '0s'
  return parts
    .slice(first, first + 2)
    .filter(([v]) => v > 0)
    .map(([v, u]) => `${v}${u}`)
    .join(' ')
}

// One word per state, app-wide.
export const laneLabel: Record<string, string> = {
  native: 'Native',
  batch: 'Relayed',
  deposit: 'Deposit',
  system: 'System',
  fees: 'Fee split',
  unknown: 'Unknown',
}

export const laneHelp: Record<string, string> = {
  native: 'Authored by a Zenon account: the NoM block is the signature.',
  batch: 'A signed EVM transaction a relayer posted to NoM.',
  deposit: 'Derived from value sent to the bridge vault on NoM.',
  system: 'Derived from a NoM fact: the momentum header, or a vault payout.',
  fees: 'Derived: the block’s tip, split between whoever posted it and the burn address.',
  unknown: 'No derivation record for this transaction.',
}
