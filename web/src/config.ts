// What an app tells this package about itself.
//
// Everything here is something the two ZVM front ends genuinely disagree about,
// kept to four values so that the rest — the arithmetic, the encoding, the fee
// policy — can be one copy.

export interface WebConfig {
  /**
   * What a formatter prints when it has nothing to print.
   *
   * The explorer uses `-`, because a dash in a table says "not known". A swap
   * interface uses `0`, because a dash in an amount field reads as a broken
   * input. Both are right for their app, which is exactly why it is a setting
   * and not a constant.
   */
  empty: string
  /** Where this app lives, for a wallet's "view on explorer" link. */
  appUrl: () => string
  /** The JSON-RPC this app reads through. */
  rpcUrl: () => string
  /** A chain id's display name, for the wallet's add-chain prompt. */
  chainName: (chainId: number) => string
}

const state: WebConfig = {
  empty: '-',
  appUrl: () => (typeof location === 'undefined' ? '' : location.origin + location.pathname),
  rpcUrl: () => '',
  chainName: chainId => `ZVM ${chainId}`,
}

export const config: Readonly<WebConfig> = state

/** Called once, before anything else. Partial: unset keys keep their default. */
export function configure(partial: Partial<WebConfig>): void {
  Object.assign(state, partial)
}

/** The configured placeholder, or an override at the call site. */
export const empty = (override?: string) => override ?? state.empty
