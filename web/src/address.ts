// bech32 (BIP-173), enough to move between a NoM address and its EVM
// spelling. The checksum is verified on decode: a stripped checksum lets a
// mistyped recipient decode silently to different bytes.

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

function polymod(values: number[]): number {
  let chk = 1
  for (const v of values) {
    const top = chk >>> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i]
  }
  return chk >>> 0
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = []
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5)
  out.push(0)
  for (const c of hrp) out.push(c.charCodeAt(0) & 31)
  return out
}

function convertBits(data: number[], from: number, to: number, pad: boolean): number[] {
  let acc = 0
  let bits = 0
  const out: number[] = []
  const maxv = (1 << to) - 1
  for (const value of data) {
    if (value < 0 || value >> from !== 0) throw new Error('bech32: value out of range')
    acc = (acc << from) | value
    bits += from
    while (bits >= to) {
      bits -= to
      out.push((acc >> bits) & maxv)
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv)
  } else if (bits >= from || ((acc << (to - bits)) & maxv) !== 0) {
    throw new Error('bech32: non-zero padding')
  }
  return out
}

export function decodeBech32(s: string): {hrp: string; bytes: Uint8Array} {
  if (s.length > 90) throw new Error('bech32: too long')
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) throw new Error('bech32: mixed case')
  s = s.toLowerCase()
  const sep = s.lastIndexOf('1')
  if (sep < 1 || sep + 7 > s.length) throw new Error('bech32: no separator')
  const hrp = s.slice(0, sep)
  const values: number[] = []
  for (const c of s.slice(sep + 1)) {
    const idx = CHARSET.indexOf(c)
    if (idx < 0) throw new Error(`bech32: invalid character ${c}`)
    values.push(idx)
  }
  if (polymod([...hrpExpand(hrp), ...values]) !== 1) throw new Error('bech32: checksum mismatch')
  return {hrp, bytes: Uint8Array.from(convertBits(values.slice(0, -6), 5, 8, false))}
}

export function encodeBech32(hrp: string, bytes: Uint8Array): string {
  const data = convertBits([...bytes], 8, 5, true)
  const checksum: number[] = []
  const mod = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1
  for (let i = 0; i < 6; i++) checksum.push((mod >> (5 * (5 - i))) & 31)
  return `${hrp}1${[...data, ...checksum].map((v) => CHARSET[v]).join('')}`
}

export function isNomAddress(s: string): boolean {
  if (!s?.toLowerCase().startsWith('z1')) return false
  try {
    const {hrp, bytes} = decodeBech32(s.toLowerCase())
    return hrp === 'z' && bytes.length === 20
  } catch {
    return false
  }
}

export function nomToHex(s: string): `0x${string}` {
  const {hrp, bytes} = decodeBech32(s.toLowerCase())
  if (hrp !== 'z' || bytes.length !== 20) throw new Error('not a NoM address')
  return `0x${[...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')}` as `0x${string}`
}

export function hexToNom(hex: string): string {
  const clean = hex.replace(/^0x/, '')
  if (clean.length !== 40) throw new Error('not a 20-byte address')
  const bytes = new Uint8Array(20)
  for (let i = 0; i < 20; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return encodeBech32('z', bytes)
}

/** Either spelling in, EVM spelling out. */
export function toEvmAddress(s: string): `0x${string}` {
  const trimmed = s.trim()
  if (isNomAddress(trimmed)) return nomToHex(trimmed)
  if (/^0x[0-9a-fA-F]{40}$/.test(trimmed)) return trimmed.toLowerCase() as `0x${string}`
  throw new Error('not an address')
}

/** True when these 20 bytes are a NoM account a key can sign for. */
export function isNomUser(hexAddress: string): boolean {
  return /^0x00/i.test(hexAddress)
}
