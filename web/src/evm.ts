// EVM wallets: MetaMask, Rabby, Phantom, and anything else that announces
// itself through EIP-6963.
//
// The ZVM is an ordinary EVM chain to all of them. The one ZVM detail is that
// eth_sendRawTransaction reaches a relayer, which posts the transaction to a
// NoM momentum, so a wallet never sees a mempool and a transaction is as fast
// as the chain's heartbeat.
//
// Every read here goes through the configured endpoint. The wallet's own
// requests go out from the extension rather than from this page, so a node on
// http://localhost stays usable even when this page is served over HTTPS.

import {
  createPublicClient,
  createWalletClient,
  custom,
  defineChain,
  http,
  type Address,
  type Chain,
  type Hex,
} from 'viem'

import {config} from './config'

export interface Discovered {
  id: string
  name: string
  icon: string
  provider: any
}

const discovered = new Map<string, Discovered>()
const listeners = new Set<() => void>()

if (typeof window !== 'undefined') {
  window.addEventListener('eip6963:announceProvider', (event: any) => {
    const {info, provider} = event.detail ?? {}
    if (!info?.uuid) return
    // Wallets answer every request by announcing, synchronously. Telling
    // listeners about one already known would let a listener that requests
    // again recurse until the stack runs out.
    const known = discovered.get(info.uuid)
    if (known && known.provider === provider) return
    discovered.set(info.uuid, {id: info.uuid, name: info.name, icon: info.icon, provider})
    listeners.forEach(l => l())
  })
}

/** Wallets already announced, without asking again. */
export function knownWallets(): Discovered[] {
  if (typeof window === 'undefined') return []
  const list = [...discovered.values()]
  // Older injections that never announce still work.
  if (list.length === 0 && (window as any).ethereum) {
    const w = (window as any).ethereum
    list.push({
      id: 'injected',
      name: w.isRabby ? 'Rabby' : w.isPhantom ? 'Phantom' : w.isMetaMask ? 'MetaMask' : 'Injected wallet',
      icon: '',
      provider: w,
    })
  }
  return list
}

export function requestWallets(): Discovered[] {
  if (typeof window === 'undefined') return []
  window.dispatchEvent(new Event('eip6963:requestProvider'))
  return knownWallets()
}

export function onWallets(fn: () => void): () => void {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

export function zvmChain(chainId: number): Chain {
  return defineChain({
    id: chainId,
    name: config.chainName(chainId),
    nativeCurrency: {name: 'Zenon', symbol: 'ZNN', decimals: 18},
    rpcUrls: {default: {http: [config.rpcUrl()]}},
    blockExplorers: {default: {name: 'ZVM Explorer', url: config.appUrl()}},
  })
}

export function publicClient(chainId: number) {
  // Batched: a page that draws a table asks for a dozen values at once, and one
  // request carrying twelve calls is one momentum's worth of latency instead of
  // twelve. The node and op-reth both answer batched JSON-RPC.
  return createPublicClient({
    chain: zvmChain(chainId),
    transport: http(config.rpcUrl(), {batch: {wait: 16}}),
  })
}

// The relayer accepts a transaction on its *effective* tip — min(tipCap,
// feeCap − baseFee) — which shrinks as the base fee rises under a signed
// transaction. Its floor is 50 gwei; every sender in the zvm tree offers double
// that on purpose, so a transaction signed now still clears the floor if the
// base fee moves before it lands. viem's generic estimateFeesPerGas() knows
// none of this, and a wallet filling the gap itself uses whatever it has cached
// for this chain id — often nothing, on a devnet it has just met.
export const TIP_WEI = 100_000_000_000n // rollup.DefaultTipWei

export async function estimateFees(chainId: number) {
  const block = await publicClient(chainId).getBlock({blockTag: 'latest'})
  const baseFee = block.baseFeePerGas ?? 0n
  // 2x the base fee plus the tip: room for the base fee to keep rising for a
  // block or two before inclusion without the effective tip falling under the
  // floor.
  return {maxFeePerGas: baseFee * 2n + TIP_WEI, maxPriorityFeePerGas: TIP_WEI}
}

export function walletClient(provider: any, chainId: number, account: Address) {
  return createWalletClient({account, chain: zvmChain(chainId), transport: custom(provider)})
}

/** Adds the ZVM to the wallet if it does not know it, then switches to it. */
export async function ensureChain(provider: any, chainId: number): Promise<void> {
  const hexId = `0x${chainId.toString(16)}` as Hex
  try {
    await provider.request({method: 'wallet_switchEthereumChain', params: [{chainId: hexId}]})
    return
  } catch (err: any) {
    // 4902: unknown chain. Some wallets nest the code.
    const code = err?.code ?? err?.data?.originalError?.code
    if (code !== 4902 && code !== -32603) throw err
  }
  await provider.request({
    method: 'wallet_addEthereumChain',
    params: [
      {
        chainId: hexId,
        chainName: `${config.chainName(chainId)} (Zenon based rollup)`,
        nativeCurrency: {name: 'Zenon', symbol: 'ZNN', decimals: 18},
        rpcUrls: [config.rpcUrl()],
        blockExplorerUrls: [config.appUrl()],
      },
    ],
  })
}

export async function connect(provider: any, chainId: number): Promise<Address> {
  const accounts: Address[] = await provider.request({method: 'eth_requestAccounts'})
  await ensureChain(provider, chainId)
  return accounts[0]
}

/** Offers a token to the wallet's own list, so a balance shows up there too. */
export async function watchAsset(
  provider: any,
  token: {address: Address; symbol: string; decimals: number},
): Promise<boolean> {
  try {
    return await provider.request({
      method: 'wallet_watchAsset',
      params: {type: 'ERC20', options: {address: token.address, symbol: token.symbol, decimals: token.decimals}},
    })
  } catch {
    return false
  }
}
