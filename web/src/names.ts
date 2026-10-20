// ZNS, the ZVM's name service (zvm-zns): an address's primary name, and the
// address a .znn name points at.
//
// Both go through ZNS's UniversalResolver, which is ENS's own, with viem's
// getEnsName and getEnsAddress, so an app here resolves a name exactly as the
// ZNS page and any ENS-aware tool do. A primary name is returned only when
// the name also points back at the address (the resolver checks both ways),
// so an app may print it in place of the address without further checks.
//
// Every app on a chain shares one lookup per address per page load: answers
// are cached in a reactive map that components read directly, and lookups
// made in the same tick go out as one batched request.

import {reactive} from 'vue'
import {createPublicClient, getAddress, http, type Address} from 'viem'
import {getEnsAddress, getEnsName} from 'viem/ens'

import {config} from './config'
import {zvmChain} from './evm'

/**
 * ZNS's universal resolver on the chain this build points at: VITE_ZNS_RESOLVER,
 * the `UniversalResolver` in zvm-zns's deployment record. Every devnet deploys
 * its own ZNS, so none is written here, and a build without one shows
 * addresses, not names.
 */
const resolver = ((import.meta.env.VITE_ZNS_RESOLVER as string | undefined) ?? '').trim()
export const ZNS_RESOLVER: Address | null = /^0x[0-9a-fA-F]{40}$/.test(resolver) ? (resolver as Address) : null

/**
 * The ZNS page, under the origin the other apps are at (VITE_GATEWAY, see the
 * app's .env.example). An app built without one links to no ZNS page.
 */
const znsApp = (import.meta.env.VITE_GATEWAY as string | undefined)?.replace(/\/+$/, '')

export const hasNames = (chainId: number | null | undefined) => chainId != null && ZNS_RESOLVER != null

/** A .znn name as typed: labels of a-z, 0-9 and "-", ending in .znn. */
export const isName = (s: string) => /^([a-z0-9-]+\.)+znn$/.test(s.trim().toLowerCase())

/** The ZNS page for a name or an address. */
export const znsLink = (chainId: number, what: string) =>
  hasNames(chainId) && znsApp ? `${znsApp}/zns/#/${isName(what) ? `name/${what.trim().toLowerCase()}` : `address/${what}`}` : null

const clients = new Map<string, ReturnType<typeof createPublicClient>>()
function client(chainId: number) {
  const rpc = config.rpcUrl()
  const key = `${chainId}:${rpc}`
  let c = clients.get(key)
  if (!c) {
    const base = zvmChain(chainId)
    c = createPublicClient({
      chain: {...base, contracts: {ensUniversalResolver: {address: ZNS_RESOLVER!}}},
      transport: http(rpc, {batch: {wait: 16}}),
    }) as any
    clients.set(key, c!)
  }
  return c!
}

/** Primary names read so far, by lower-case address; null means "has none".
 *  Reactive, so a component that reads it redraws when the answer arrives. */
export const primaryNames = reactive(new Map<string, string | null>())
const inflight = new Map<string, Promise<string | null>>()

/** An address's verified primary name, or null. Cached for the page's life
 *  unless `fresh`. */
export function nameOf(chainId: number | null | undefined, address: string | null | undefined, fresh = false): Promise<string | null> {
  if (!address || !hasNames(chainId) || !/^0x[0-9a-fA-F]{40}$/.test(address)) return Promise.resolve(null)
  const key = `${chainId}:${address.toLowerCase()}`
  const cacheKey = address.toLowerCase()
  if (!fresh && primaryNames.has(cacheKey)) return Promise.resolve(primaryNames.get(cacheKey)!)
  if (!fresh && inflight.has(key)) return inflight.get(key)!
  const p = getEnsName(client(chainId!) as any, {address: address as Address})
    .catch(() => null)
    .then((name) => {
      primaryNames.set(cacheKey, name)
      inflight.delete(key)
      return name
    })
  inflight.set(key, p)
  return p
}

/** What cached answer there is for an address, without asking. Read inside a
 *  computed, it makes the computed redraw once `nameOf` has answered. */
export const cachedName = (address: string | null | undefined) => (address ? (primaryNames.get(address.toLowerCase()) ?? null) : null)

/** The address a .znn name points at, or null when it points nowhere. */
export async function addressOf(chainId: number | null | undefined, name: string): Promise<Address | null> {
  if (!hasNames(chainId) || !isName(name)) return null
  const a = await getEnsAddress(client(chainId!) as any, {name: name.trim().toLowerCase()}).catch(() => null)
  return a ? getAddress(a) : null
}
