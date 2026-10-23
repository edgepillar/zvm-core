import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import test from 'node:test'
import {decodeBech32, hexToNom, isNomAddress, isNomUser, nomToHex, toEvmAddress} from '../src/address.ts'

const vectors = JSON.parse(readFileSync(new URL('../../vectors/address-vectors.json', import.meta.url), 'utf8'))

for (const v of vectors.valid) {
  test(`shared encoding: ${v.name}`, () => {
    assert.equal(hexToNom(v.hex), v.nom)
    assert.equal(hexToNom(v.hex.slice(2)), v.nom)
    assert.equal(hexToNom(v.hex.toUpperCase()), v.nom)
    assert.equal(nomToHex(v.nom), v.hex)
    assert.equal(nomToHex(v.nom.toUpperCase()), v.hex)
    assert.equal(isNomAddress(v.nom), true)
    assert.equal(isNomAddress(v.nom.toUpperCase()), true)
    assert.equal(isNomUser(v.hex), v.isUser)
    assert.equal(isNomUser(v.hex.toUpperCase()), v.isUser)
    assert.equal(toEvmAddress(` ${v.nom} `), v.hex)
    assert.equal(toEvmAddress(v.hex.toUpperCase()), v.hex)
  })
}

for (const v of vectors.invalidNom) {
  test(`refuse NoM input: ${v.name}`, () => {
    assert.equal(isNomAddress(v.value), false)
    assert.throws(() => nomToHex(v.value))
    if (v.trimmedHex) assert.equal(toEvmAddress(v.value), v.trimmedHex)
    else assert.throws(() => toEvmAddress(v.value))
  })
}

test('hex conversion validates every byte before converting', () => {
  const inputs = [
    '', '0x00', '0x' + '00'.repeat(19), '0x' + '00'.repeat(21),
    '0x' + 'gg'.repeat(20), '0x' + '00'.repeat(19) + '0g',
    '0x' + '00'.repeat(19) + '-1', '0x' + '00'.repeat(19) + ' 1',
    '0x' + '00'.repeat(19) + '１', '0x' + '00'.repeat(20) + '\n',
  ]
  for (const value of inputs) assert.throws(() => hexToNom(value), value)
})

test('a user type byte is recognized only in a complete prefixed hex address', () => {
  for (const value of ['', '0x00', '0x00' + 'gg'.repeat(19), '0x00' + '00'.repeat(20), '00'.repeat(20), '0x' + '00'.repeat(20) + '\n']) {
    assert.equal(isNomUser(value), false, value)
  }
})

test('the generic decoder rejects non-printable human-readable prefixes', () => {
  // Valid checksums for these payloads do not make their prefixes BIP-173.
  for (const value of vectors.invalidPrefix) assert.throws(() => decodeBech32(value))
})
