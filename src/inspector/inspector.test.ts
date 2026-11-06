import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  decodeDelivery,
  encodeDelivery,
  grantDescriptor,
  newSalt,
  openDelivery,
  pieceKey,
  pieceMetadata,
  publicKeyOf,
  rootClaim,
  unwrapWith,
  wrapTo,
} from '@filoz/keysmith'
import * as fee from 'filecoin-encryption-envelope'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import SAMPLES from '../samples.json' with { type: 'json' }
import { envelopeInCar, inspectBytes } from './describe.ts'
import { parseText } from './input.ts'

// filecoin-pin#788's golden Grant (Anvil keys), and the FOC-Grant header of Example 1 in keysmith's claim vectors.
const GRANT =
  'fgr1_gwGBqwABAWhrZXlzcGFjZQJU85_W5RqtiPb0zmq4gnJ5z_-5ImYDUALKCM9-AiLIQyrcFZIyt-sEVDxEzd22qQD6K1hd0pngPRL6QpO8BQAGGgAEyy8HUGoMg9KNYHqOiNxnkftJ1-IIWEGdCbSL16RMCZ2Hjsznju8VSTRpq-2RHLu7I-Bporb53VomKJ-goC0IRqON69e6bUOcH7QUKmWcKFlpQI2nT5JjGwpQagyD0o1geo6I3GeR-0nX4gsa9IZXAFi6pwABAWhrZXlzcGFjZQJU85_W5RqtiPb0zmq4gnJ5z_-5ImYDUALKCM9-AiLIQyrcFZIyt-sEWEEEQ9-xkEnBkX7FqCJHDgkGNVOlDBknDtAvJ__SuOQjpQlgLGfm1EvV4j3YxrjJg33xI92pA85BM-J4cgycL0Yl1QVMYIy-eUdXcvuV3NhHBlgwikJobsjiFOwzSVnbA7-WyI7_-0AIn8UgnzuANx3YCl_SQDZrM8iUMIDuNL620d39'
const HEADER =
  'Authorization: FOC-Grant gwGCqwABAWhrZXlzcGFjZQJU85_W5RqtiPb0zmq4gnJ5z_-5ImYDUAARIjNEVWZ3iJmqu8zd7v8EVHCZeXDFGBLcOgEMfQG1Dg0X3HnIBQEGGgAEyy8HUGmCgHZJZQ4xHkxpr0rJBBcIWEEFITskOn04xokCHpz4cyHOnMcc0CGKBqpT3ryp8WjPaWFOYYj1dHrWTqatbUuFDLALuFTlGuuSFIdywgWZq9GRHApQaYKAdkllDjEeTGmvSskEFwsaat1GgKYAAQFyc2NvcGU6YWdlbnQtbWVtb3J5BFQ8RM3dtqkA-itYXdKZ4D0S-kKTvAUAB1DAdHzv1YTi_8bp-684aTPGCFhBmqxvu_MYJOcy9lYmAS_W2c0gKhrtvc3to2HW5G4RkDBTKSvc_Nq4ZY2qy5m53iwuNoUeHsJ2v2RarYolbQeXLRujAFgnAVWRICIzBFy7lWgxqOJH7Qb38pP63xobZGvshUKsakzSKSkTY2knARpq1Bs8AlhBdfsRhhdC-lZ0Rf9egiAE_MxWM9eOK9f939d8-BT-Qv54nZFERMIDIP_LVuiH27gHks40GlEw5xXYlBgLaLqBnhw'

function parsed(text: string) {
  const result = parseText(text)
  assert.ok(result.ok, result.ok ? '' : result.refusal)
  return result
}

test('a Grant, with or without its session.env variable, is a delivery Keysmith accepts', () => {
  for (const text of [GRANT, `GROUP_KEY_GRANT=${GRANT}`, `  ${GRANT.slice(0, 200)}\n${GRANT.slice(200)}  `]) {
    const view = inspectBytes(parsed(text).bytes)
    assert.equal(view.kind, 'grant')
    assert.ok(view.kind === 'grant' && view.chain && !view.strictError)
    assert.equal(view.kind === 'grant' && view.chain?.links[0]?.node, 'keyspace')
  }
})

test('a FOC-Grant header is a presentation with its request', () => {
  const result = parsed(HEADER)
  assert.equal(result.source, 'FOC-Grant header')
  const view = inspectBytes(result.bytes)
  assert.equal(view.kind, 'presentation')
  assert.ok(view.kind === 'presentation' && !view.strictError && view.request && view.chain?.links.length === 2)
})

test('a grant reaches Curio the ways its gate reads one, and other credentials stay hidden', () => {
  const token = HEADER.slice('Authorization: FOC-Grant '.length)
  for (const [text, source] of [
    [`Authorization: ${token}`, 'Authorization header'],
    [`Authorization: Basic ${btoa(`FOC Grant:${token}`)}`, 'Authorization: Basic, user "FOC Grant"'],
    [`Basic ${btoa(`FOC%20Grant:FOC-Grant ${token}`)}`, 'Authorization: Basic, user "FOC%20Grant"'],
    [`Cookie: session=hunter2; FOC Grant=${token}`, 'FOC Grant cookie'],
    [`FOC%20Grant=${token}`, 'FOC Grant cookie'],
  ] as const) {
    const result = parsed(text)
    assert.equal(result.source, source)
    assert.deepEqual(result.notes, [])
    assert.equal(inspectBytes(result.bytes).kind, 'presentation')
  }

  assert.match(parsed(`Authorization: foc-grant ${token}`).notes[0]!, /refuses this spelling/)
  assert.match(parsed(`FOC-Grant ${token.replace(/-/g, '+').replace(/_/g, '/')}`).notes[0]!, /base64url only/)
  for (const text of [
    `Authorization: Basic ${btoa('alice:hunter2')}`,
    'Cookie: session=hunter2',
    'Authorization: Bearer hunter2',
  ]) {
    const result = parseText(text)
    assert.ok(!result.ok && !result.refusal.includes('hunter2'), text)
  }
})

test('a share link, as filecoin-pin writes it, shows its grant and never decodes an Access key unless asked', () => {
  const open = SAMPLES[1]!.items[0]!.text
  const restricted = SAMPLES[2]!.items[0]!.text
  const plain = parsed(restricted)
  assert.equal(inspectBytes(plain.bytes).kind, 'grant')
  assert.match(plain.notes.join(' '), /sent separately/)
  const carried = parsed(open)
  assert.match(carried.notes.join(' '), /carries its Access key.*not decoded/)
  assert.equal(carried.key, undefined)
  assert.equal(parseText(restricted.replace('#v1/', '#v9/')).ok, false)
  assert.equal(parseText(`${restricted}&x=1`).ok, false)
})

test('private keys are refused, however they are pasted', () => {
  const key = `0x${'ab'.repeat(32)}`
  for (const text of [key, key.slice(2), `SESSION_KEY=${key}`, `PRIVATE_KEY=${key}`, `fak1_${'A'.repeat(43)}`]) {
    const result = parseText(text)
    assert.equal(result.ok, false, text)
    assert.match(result.ok ? '' : result.refusal, /private key/)
  }
})

test('danger mode decodes keys, and opens a restricted share link with its Access key', async () => {
  const key = `0x${'ab'.repeat(32)}`
  for (const text of [key, `SESSION_KEY=${key}`, `fak1_${Buffer.from(key.slice(2), 'hex').toString('base64url')}`]) {
    const result = parseText(text, { danger: true })
    assert.ok(result.ok && result.keyOnly && result.key === key, text)
  }

  const owner = privateKeyToAccount(generatePrivateKey())
  const accessKey = generatePrivateKey()
  const bearer = privateKeyToAccount(accessKey)
  const ref = { owner: owner.address, keyspace: '0x00112233445566778899aabbccddeeff' } as const
  const { chain, nodeKey } = await rootClaim(owner, {
    ...ref,
    chainId: 314159n,
    kk: new Uint8Array(32).fill(9),
    node: 'keyspace',
    bearer: bearer.address,
    maxDepth: 0,
    expires: 4102444800,
  })
  const delivery = encodeDelivery(
    chain,
    await wrapTo(publicKeyOf(accessKey), nodeKey, grantDescriptor(ref, 'keyspace'))
  )
  const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url')
  const link = `#v1/bafyroot&d=${b64(delivery)}&k=fak1_${b64(Buffer.from(accessKey.slice(2), 'hex'))}`

  const opened = parseText(link, { danger: true })
  assert.ok(opened.ok && opened.key === accessKey && !opened.keyOnly)
  assert.deepEqual((await openDelivery(opened.key, opened.bytes)).key, nodeKey)

  // A whole session.env: refused normally; in danger mode, the grant to inspect plus the key that opens it.
  const env = `WALLET_ADDRESS=${owner.address}\nSESSION_KEY=${accessKey}\nKEYSPACE_GRANT=fgr1_${b64(delivery)}`
  assert.equal(parseText(env).ok, false)
  const fromEnv = parseText(env, { danger: true })
  assert.ok(fromEnv.ok && fromEnv.key === accessKey && inspectBytes(fromEnv.bytes).kind === 'grant')
})

test('a FEE piece shows its Keysmith labels', async () => {
  const metadata = pieceMetadata(
    { owner: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', keyspace: '0x00112233445566778899aabbccddeeff' },
    { salt: newSalt(), scope: 'team' }
  )
  const plaintext = new TextEncoder().encode('hello')
  const stream = new Blob([plaintext]).stream().pipeThrough(
    fee.encrypt({
      cek: pieceKey(new Uint8Array(32).fill(7), metadata['foc/salt']),
      appMetadata: metadata,
      contentLength: plaintext.length,
    })
  )
  const bytes = new Uint8Array(await new Response(stream).arrayBuffer())
  const view = inspectBytes(bytes)
  assert.equal(view.kind, 'piece')
  assert.equal(view.kind === 'piece' && view.metadata?.['foc/scope'], 'team')
})

test('a CAR file is explained rather than misread', () => {
  // varint 0x11, then the CBOR map {"roots": [], "version": 1}
  const car = new Uint8Array([
    0x11,
    0xa2,
    0x65,
    ...new TextEncoder().encode('roots'),
    0x80,
    0x67,
    ...new TextEncoder().encode('version'),
    0x01,
  ])
  const view = inspectBytes(car)
  assert.equal(view.kind, 'unknown')
  assert.match(view.kind === 'unknown' ? view.reason : '', /CAR file/)
})

test('every sample inspects, and its keys open it', async () => {
  // The upload: an outer CAR whose block is the FEE envelope, labelled with the owner's keyspace.
  const car = parsed(SAMPLES[0]!.items[0]!.text).bytes
  const inner = envelopeInCar(car)
  assert.ok(inner)
  const piece = inspectBytes(inner.bytes)
  assert.ok(piece.kind === 'piece' && piece.metadata?.['foc/salt'])

  // The open link carries its key; the restricted one opens with the detached Access key.
  const open = parseText(SAMPLES[1]!.items[0]!.text, { danger: true })
  const restricted = parseText(SAMPLES[2]!.items[0]!.text, { danger: true })
  const access = parseText(SAMPLES[2]!.items[1]!.text, { danger: true })
  assert.ok(open.ok && open.key && restricted.ok && !restricted.key && access.ok && access.key)
  assert.deepEqual(await unwrapWith(open.key, open.bytes), await unwrapWith(access.key, restricted.bytes))

  // The Grants: one link for keyspace and for scope:team, two for the nested chain.
  for (const [i, node, links] of [
    [3, 'keyspace', 1],
    [4, 'scope:team', 1],
    [5, 'scope:team/alice', 2],
  ] as const) {
    const grant = parsed(SAMPLES[i]!.items[0]!.text)
    const key = parseText(SAMPLES[i]!.items[1]!.text, { danger: true })
    assert.ok(key.ok && key.key)
    const { claim } = await openDelivery(key.key, grant.bytes)
    assert.equal(claim.node, node)
    assert.equal(decodeDelivery(grant.bytes).chain.links.length, links)
  }
})

test('a claim chain or request with a nonsense expiry still inspects', () => {
  const hex = (s: string) => Uint8Array.from(s.match(/../g)!, (b) => parseInt(b, 16))
  for (const bytes of ['830181a10b617840', '830180a1011bffffffffffffffff']) {
    const view = inspectBytes(hex(bytes))
    assert.ok(view.fields.some((f) => f.value?.includes('not a valid time')))
  }
})
