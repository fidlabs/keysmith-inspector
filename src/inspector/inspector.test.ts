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
  verifyPresentation,
  wrapTo,
} from '@filoz/keysmith'
import * as fee from 'filecoin-encryption-envelope'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import SAMPLES from '../samples.json' with { type: 'json' }
import { envelopeInCar, inspectBytes, openWithKey } from './describe.ts'
import { parseText } from './input.ts'

// filecoin-pin's golden Grant (Anvil keys, keysmith format 2), and the FOC-Grant header of Example 1 in keysmith's claim vectors.
const GRANT =
  'fgr1_gwKBqwACAWhncm91cEtleQJU85_W5RqtiPb0zmq4gnJ5z_-5ImYDUALKCM9-AiLIQyrcFZIyt-sEVDxEzd22qQD6K1hd0pngPRL6QpO8BQAGGgAEyy8HUKTAK_v_zb_3Sz5mAaZ0bZwIWEFG8XomGpP0MPKlif23na1MQLEFFhipPX0GNZbtOZtVbEnsqFZxhM0Tq5a53kaP2LBSDM5ZEU3WcH3MOkQtzt5QGwpQpMAr-__Nv_dLPmYBpnRtnAsa9IZXAFi6pwACAWhncm91cEtleQJU85_W5RqtiPb0zmq4gnJ5z_-5ImYDUALKCM9-AiLIQyrcFZIyt-sEWEEEBoUkIEGC2gyP3meS8N2b9UhsyBd3WReZgk7mSKPpS6C32SriAFwr42n4tCRCEkfwYwayZrzr65t4R75nm1wcuAVMtAgEssgVvy1RrhL7Blgw-shWVySbCmDnncKG_XYFLv-tFsqTcdkWlaSISB1gboMHUylMQWkyH0lKC6Lzb0Bn'
const HEADER =
  'Authorization: FOC-Grant gwKCqwACAWhncm91cEtleQJU85_W5RqtiPb0zmq4gnJ5z_-5ImYDUAARIjNEVWZ3iJmqu8zd7v8EVHCZeXDFGBLcOgEMfQG1Dg0X3HnIBQEGGgAEyy8HUFdwiSIPY9xmK0_Epgq-G0gIWEFHODCs5W1V5ClE4k7ja5QfDDMWw0n9T-5_P7dv-sXzxymOZEybwCUM2kz2lSLbT7oUcgW8_J3Akvv55EQ4Tg51GwpQV3CJIg9j3GYrT8SmCr4bSAsaat1GgKYAAgFyZ3JvdXA6YWdlbnQtbWVtb3J5BFQ8RM3dtqkA-itYXdKZ4D0S-kKTvAUAB1C-yBeNS_TRIT4hOy1bx31OCFhB9X9fEPPE7o9HpTKteIoTaCBMzBxnbibxN-PLJfZJd-AtvOZhDZiY0yGE8PbpO98fTg4rTGbo7Cn92BPD_QUSQRujAFgnAVWRICIzBFy7lWgxqOJH7Qb38pP63xobZGvshUKsakzSKSkTY2knARpq1Bs8AlhB0OyIN8Q1LXcgik9ifXks5-FR9lktfL4AAVVB22gan6wDNYJ9imgNM0EpGuPFdQLnxUPvLrVqBg35m6BMQx0O6Bs'

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
    assert.equal(view.kind === 'grant' && view.chain?.links[0]?.node, 'groupKey')
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
  const ref = { owner: owner.address, groupKeyId: '0x00112233445566778899aabbccddeeff' } as const
  const { chain, nodeKey } = await rootClaim(owner, {
    ...ref,
    chainId: 314159n,
    groupKey: new Uint8Array(32).fill(9),
    node: 'groupKey',
    bearer: bearer.address,
    maxDepth: 0,
    expires: 4102444800,
  })
  const delivery = encodeDelivery(
    chain,
    await wrapTo(publicKeyOf(accessKey), nodeKey, grantDescriptor(ref, 'groupKey'))
  )
  const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url')
  const link = `#v1/bafyroot&d=${b64(delivery)}&k=fak1_${b64(Buffer.from(accessKey.slice(2), 'hex'))}`

  const opened = parseText(link, { danger: true })
  assert.ok(opened.ok && opened.key === accessKey && !opened.keyOnly)
  assert.deepEqual((await openDelivery(opened.key, opened.bytes)).key, nodeKey)

  // A whole session.env: refused normally; in danger mode, the grant to inspect plus the key that opens it.
  const env = `WALLET_ADDRESS=${owner.address}\nSESSION_KEY=${accessKey}\nGROUP_KEY_GRANT=fgr1_${b64(delivery)}`
  assert.equal(parseText(env).ok, false)
  const fromEnv = parseText(env, { danger: true })
  assert.ok(fromEnv.ok && fromEnv.key === accessKey && inspectBytes(fromEnv.bytes).kind === 'grant')
})

test('several comma-separated Grants in GROUP_KEY_GRANT: one at a time, the picked one', async () => {
  const owner = privateKeyToAccount(generatePrivateKey())
  const sessionKey = generatePrivateKey()
  const ref = { owner: owner.address, groupKeyId: '0x00112233445566778899aabbccddeeff' } as const
  const grantFor = async (node: string) => {
    const { chain, nodeKey } = await rootClaim(owner, {
      ...ref,
      chainId: 314159n,
      groupKey: new Uint8Array(32).fill(9),
      node,
      bearer: privateKeyToAccount(sessionKey).address,
      maxDepth: 0,
      expires: 4102444800,
    })
    const delivery = encodeDelivery(
      chain,
      await wrapTo(publicKeyOf(sessionKey), nodeKey, grantDescriptor(ref, node as 'groupKey'))
    )
    return `fgr1_${Buffer.from(delivery).toString('base64url')}`
  }
  const line = `GROUP_KEY_GRANT=${await grantFor('group:a')},${await grantFor('group:b/c')}`

  for (const [pick, node] of [
    [0, 'group:a'],
    [1, 'group:b/c'],
    [9, 'group:b/c'],
  ] as const) {
    const parsed = parseText(line, { pick })
    assert.ok(parsed.ok && parsed.of?.count === 2, `pick ${pick}`)
    const view = inspectBytes(parsed.bytes)
    assert.equal(view.kind === 'grant' && view.chain?.links[0]?.node, node)
  }
  assert.ok(parseText(line).ok && /Showing Grant 1/.test(String((parseText(line) as { notes: string[] }).notes)))
})

test('a FEE piece shows its Keysmith labels', async () => {
  const metadata = pieceMetadata(
    { owner: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', groupKeyId: '0x00112233445566778899aabbccddeeff' },
    { salt: newSalt(), group: 'team' }
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
  assert.equal(view.kind === 'piece' && view.metadata?.['foc/group'], 'team')
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
  // The upload: an outer CAR whose block is the FEE envelope, labelled with the owner's group key.
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

  // The Grants: one link for the group key and for group:team, two for the nested chain.
  for (const [i, node, links] of [
    [3, 'groupKey', 1],
    [4, 'group:team', 1],
    [5, 'group:team/alice', 2],
  ] as const) {
    const grant = parsed(SAMPLES[i]!.items[0]!.text)
    const key = parseText(SAMPLES[i]!.items[1]!.text, { danger: true })
    assert.ok(key.ok && key.key)
    const { claim } = await openDelivery(key.key, grant.bytes)
    assert.equal(claim.node, node)
    assert.equal(decodeDelivery(grant.bytes).chain.links.length, links)
  }

  // The header: the group key Grant's chain, and its session key's request for the upload, which the gate serves.
  const header = parsed(SAMPLES[6]!.items[0]!.text)
  const view = inspectBytes(header.bytes)
  assert.ok(view.kind === 'presentation' && !view.strictError && view.request)
  const session = parseText(SAMPLES[3]!.items[1]!.text, { danger: true })
  assert.ok(session.ok && session.key)
  const claim = await verifyPresentation(header.bytes, {
    pieceCid: view.request.pieceCid,
    piece: piece.metadata,
    chainId: 314159n,
    now: view.request.expires - 1,
  })
  assert.equal(claim.bearer, privateKeyToAccount(session.key).address)

  // The nested header: the nested Grant's chain (group key, then team/alice), and the agent's request.
  const nested = inspectBytes(parsed(SAMPLES[7]!.items[0]!.text).bytes)
  assert.ok(nested.kind === 'presentation' && !nested.strictError && nested.chain)
  assert.deepEqual(
    nested.chain.links.map((link) => [link.node, link.maxDepth]),
    [
      ['groupKey', 1],
      ['group:team/alice', 0],
    ]
  )
  const agent = parseText(SAMPLES[5]!.items[1]!.text, { danger: true })
  assert.ok(agent.ok && agent.key)
  assert.equal(nested.chain.links[1]!.bearer, privateKeyToAccount(agent.key).address)
  assert.deepEqual(nested.chain, decodeDelivery(parsed(SAMPLES[5]!.items[0]!.text).bytes).chain)
})

test('a claim chain or request with a nonsense expiry still inspects', () => {
  const hex = (s: string) => Uint8Array.from(s.match(/../g)!, (b) => parseInt(b, 16))
  for (const bytes of ['830281a10b617840', '830280a1011bffffffffffffffff']) {
    const view = inspectBytes(hex(bytes))
    assert.ok(view.fields.some((f) => f.value?.includes('not a valid time')))
  }
})

test("a private upload's share links, and the foc_grant request URL", async () => {
  const [byOwner, bySession, request] = SAMPLES.slice(8) as typeof SAMPLES
  for (const [sample, links, unverified] of [
    [byOwner, 1, false],
    [bySession, 2, true],
  ] as const) {
    const link = parseText(sample!.items[0]!.text, { danger: true })
    assert.ok(link.ok && link.key, sample!.title)
    assert.ok(link.notes.some((note) => note.includes('private upload') && note.includes('Delivery')))
    assert.ok(link.notes.includes('Providers that hold the piece (s=): https://sp.invalid/pdp.'))
    const view = inspectBytes(link.bytes)
    assert.ok(view.kind === 'grant' && view.chain?.links.length === links && view.chain.links.at(-1)?.pieceCid)
    const opened = await openWithKey(link.key, link.bytes, true)
    assert.match(opened.node, /^piece:0x/)
    assert.equal(opened.unverified === true, unverified)
    // Another key is not the chain's bearer, verified or not
    await assert.rejects(openWithKey(`0x${'ab'.repeat(32)}`, link.bytes, true), /another bearer/)
  }

  const url = parsed(request!.items[0]!.text)
  assert.equal(url.source, 'foc_grant query')
  assert.ok(url.notes.some((note) => note.includes('/download/')))
  assert.equal(inspectBytes(url.bytes).kind, 'presentation')
  assert.equal(parsed(`foc_grant=${request!.items[0]!.text.split('foc_grant=')[1]}`).source, 'foc_grant query')

  const badProvider = byOwner!.items[0]!.text.replace(/&s=[^&]*/, `&s=${encodeURIComponent('javascript:alert(1)')}`)
  assert.equal(parseText(badProvider, { danger: true }).ok, false)
})
