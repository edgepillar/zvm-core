// What a ZNN, a QSR and anything with a pool against them is worth in dollars.
//
// The node does the asking. It polls DexScreener for the bridged wZNN and wQSR
// on Ethereum once a minute and derives every other token from the ZVM's own
// Uniswap reserves (zvm-node/prices, zvm-node/markets); a page reads the one
// endpoint `/api/prices` on the node it already talks to. That is not a detail
// of where the code sits: a browser asking a price API directly would tell a
// third party who is looking at which token, and would be refused outright as
// mixed content on any node served over plain http.
//
// A price the node does not have is `null` everywhere below, never 0. A token
// with no pool deep enough to price is a token whose value is unknown, and a
// page that prints $0.00 for it is stating something false about somebody's
// balance.
//
// Each app makes its own store with `createPrices`, because each app reaches
// its node differently: the explorer and the NFT market always have an API
// base, and glyphswap may be pointed at a bare op-reth that has none — where
// prices are simply absent and every caller below returns null.

import {reactive} from 'vue'

/**
 * The types below are zvm-node/prices' Go structs as JSON. They are kept field
 * for field rather than trimmed to what one page happens to draw: a page that
 * declares only the fields it uses makes the next page's author guess what else
 * is in there, and guessing against a live endpoint is how `hops` ended up
 * meaning two different things in two apps.
 */

/** One DexScreener pool, as configured and as it answered. */
export interface PricePair {
  chain: string
  address: string
  /** DexScreener's API does not return every pool its site shows. */
  found: boolean
  dex?: string
  labels?: string[]
  url: string
  base?: {address: string; symbol: string; name: string}
  quote?: {address: string; symbol: string; name: string}
  priceUsd?: number
  priceNative?: number
  liquidityUsd?: number
  volume24hUsd?: number
  change24h?: number
  txns24h?: number
}

/** A Zenon asset's dollar price, and the pool on another chain it came from. */
export interface PriceQuote {
  asset: string
  usd: number
  /** DexScreener's own 24-hour change, and only for the base side of a pair. */
  change24h?: number
  pair: string
  side: string
  liquidityUsd: number
  url: string
  at: number
}

/** A ZVM token's dollar price and the route this chain's pools took to it. */
export interface TokenPrice {
  usd: number
  /** The Zenon asset it is priced as directly (ZNN, QSR); empty when derived. */
  anchor?: string
  /** The pool the price came through, and that pool's depth from its priced side. */
  pair?: string
  liquidityUsd?: number
  /** How many pools from an anchor. 0 is the anchor itself. */
  hops: number
}

export interface PriceSnapshot {
  enabled: boolean
  source: string
  updatedAt?: number
  checkedAt?: number
  /** The node last asked and did not get an answer; what is here is old. */
  stale: boolean
  error?: string
  assets: Record<string, PriceQuote>
  tokens: Record<string, TokenPrice>
  pairs?: PricePair[]
  minLiquidityUsd?: number
}

export interface PricesState {
  snap: PriceSnapshot | null
  /** Why there is no snapshot, for a page that wants to say so. */
  error: string
  /** One attempt has finished, successfully or not. Guards a flash of "—". */
  loaded: boolean
}

export interface Prices {
  state: PricesState
  refresh(): Promise<void>
  /** Refreshes now and every intervalMs. Calling it twice is a no-op. */
  start(intervalMs?: number): void
  stop(): void
  znnUsd(): number | null
  qsrUsd(): number | null
  stale(): boolean
  /** One whole token's price: a 0x address, or 'znn' for ZNN itself. */
  usdOf(token: string | null | undefined): number | null
  /** What an amount is worth, or null when this token has no price. */
  usdValue(
    amount: bigint | string | number | null | undefined,
    decimals: number,
    token: string | null | undefined,
  ): number | null
  /** Where a token's price came from, for a tooltip that does not overclaim. */
  usdSource(token: string | null | undefined): string
}

/**
 * Makes an app's price store.
 *
 * `apiBase` is called on every refresh rather than captured, because both the
 * explorer and glyphswap let a person change node mid-session — and it may
 * return null, which is how "this endpoint has no node in front of it" is
 * spelled. A null base is not an error: nothing is fetched, no error is shown,
 * and every price is simply unknown.
 */
export function createPrices(apiBase: () => string | null | undefined): Prices {
  const state = reactive<PricesState>({snap: null, error: '', loaded: false})
  let timer: ReturnType<typeof setInterval> | undefined

  async function refresh(): Promise<void> {
    const base = apiBase()
    if (!base) {
      state.snap = null
      state.error = ''
      state.loaded = true
      return
    }
    try {
      const res = await fetch(`${base.replace(/\/$/, '')}/api/prices`)
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
      state.snap = (await res.json()) as PriceSnapshot
      state.error = ''
    } catch (err: any) {
      state.error = err?.message ?? String(err)
    } finally {
      state.loaded = true
    }
  }

  const assetOf = (token: string | null | undefined): PriceQuote | TokenPrice | undefined => {
    const snap = state.snap
    if (!snap || !token) return undefined
    if (token === 'znn') return snap.assets?.ZNN
    return snap.tokens?.[token.toLowerCase()]
  }

  return {
    state,
    refresh,
    start(intervalMs = 30_000) {
      if (timer) return
      refresh()
      timer = setInterval(refresh, intervalMs)
    },
    stop() {
      if (timer) clearInterval(timer)
      timer = undefined
    },
    znnUsd: () => state.snap?.assets?.ZNN?.usd ?? null,
    qsrUsd: () => state.snap?.assets?.QSR?.usd ?? null,
    stale: () => !!state.snap?.stale,
    usdOf: token => assetOf(token)?.usd ?? null,
    usdValue(amount, decimals, token) {
      const unit = this.usdOf(token)
      if (unit === null || amount === null || amount === undefined || amount === '') return null
      const raw = typeof amount === 'bigint' ? amount : BigInt(amount)
      // Float is fine here: this is a display value, never a payment.
      return (Number(raw) / 10 ** decimals) * unit
    },
    usdSource(token) {
      const snap = state.snap
      const asset = assetOf(token)
      if (!snap || !asset) return ''
      if ('anchor' in asset && asset.anchor) {
        const quote = snap.assets?.[asset.anchor]
        return quote ? `${asset.anchor} from DexScreener (${quote.side} of ${abbrev(quote.pair)})` : asset.anchor
      }
      if ('pair' in asset && asset.pair) return `derived from the ${abbrev(asset.pair)} pool on this chain`
      return ''
    },
  }
}

const abbrev = (s: string) => (s?.length > 12 ? `${s.slice(0, 6)}…${s.slice(-4)}` : s)
