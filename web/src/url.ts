// What a browser will and will not let a page call.
//
// These are facts about browsers rather than choices about an app, so both
// front ends use the same ones. Normalizing an endpoint is *not* here: the
// explorer's endpoint is a node's API base and glyphswap's is a bare JSON-RPC
// URL, and the two trim different things off the end on purpose.

/** localhost is a potentially-trustworthy origin, which is what makes an https page able to reach it. */
export function isLoopback(url: string): boolean {
  try {
    const h = new URL(url).hostname.toLowerCase()
    return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]' || h.endsWith('.localhost')
  } catch {
    return false
  }
}

/**
 * Whether the browser will refuse this endpoint before it is ever requested.
 *
 * An https page may not load http sub-resources — except from loopback, which
 * the Secure Contexts spec treats as trustworthy, and which Chrome, Edge and
 * Firefox all honour. So `http://localhost:47000` works from the deployed page
 * and `http://192.168.1.20:47000` does not, and the difference is worth saying
 * out loud rather than surfacing as a bare "failed to fetch".
 */
export function mixedContentBlocked(url: string): boolean {
  if (typeof location === 'undefined' || location.protocol !== 'https:') return false
  return url.startsWith('http://') && !isLoopback(url)
}

/**
 * Adds a scheme to what people actually paste — a bare host, a host:port — and
 * drops a trailing slash. What each app does with the rest of the path is its
 * own business: see `normalize` in either app's `core/endpoint.ts`.
 */
export function withScheme(input: string): URL | null {
  let s = input.trim()
  if (!s) return null
  if (!/^https?:\/\//i.test(s)) s = `http://${s}`
  try {
    return new URL(s)
  } catch {
    return null
  }
}
