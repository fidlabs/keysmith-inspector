// Writes src/samples.json: the page's "Try it" data. Throwaway keys, made fresh on each run.
// The upload and share links come from filecoin-pin's own code, so they match what it writes:
//
//   FILECOIN_PIN=../filecoin-pin node scripts/make-samples.mjs   (filecoin-pin built: pnpm build)
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import * as ks from '@filoz/keysmith'
import * as fee from 'filecoin-encryption-envelope'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'

const fp = resolve(process.env.FILECOIN_PIN ?? '../filecoin-pin')
const { encryptPath, ENCRYPTED_FILE_NAME } = await import(join(fp, 'dist/common/encryption.js'))
const { createCarFromPath } = await import(join(fp, 'dist/core/unixfs/index.js'))
const { defaultGroupKeyId, newPieceKey } = await import(join(fp, 'dist/common/group-key.js'))
const { createShare } = await import(join(fp, 'dist/common/share-link.js'))

const VIEWER = 'https://viewer.invalid/' // the fragment is what matters; no viewer holds this sample upload
const CHAIN_ID = 314159n // calibration
const EXPIRES = 4102444800 // 2100-01-01
const b64 = (bytes) => Buffer.from(bytes).toString('base64url')
const key = () => {
  const privateKey = generatePrivateKey()
  return { privateKey, account: privateKeyToAccount(privateKey) }
}

// The owner wallet and its group key (keyspace), as filecoin-pin derives them.
const owner = key().account
const ref = { owner: owner.address, keyspace: defaultGroupKeyId(owner.address) }
const { kk, descriptor } = await ks.keyspaceKeys(owner, ref)

// 1. `add --encrypt`: inner UnixFS CAR → FEE → encrypted.fee → outer UnixFS CAR.
const dir = await mkdtemp(join(tmpdir(), 'inspector-samples-'))
const plaintext = join(dir, 'hello.txt')
await writeFile(plaintext, 'Hello from the Keysmith Inspector samples.\n')
const pieceKey = newPieceKey(ks.writeTarget(descriptor, kk))
await encryptPath(plaintext, join(dir, ENCRYPTED_FILE_NAME), pieceKey)
const { carPath, rootCid } = await createCarFromPath(join(dir, ENCRYPTED_FILE_NAME))
const car = await readFile(carPath)
const envelope = await readFile(join(dir, ENCRYPTED_FILE_NAME))
await rm(dir, { recursive: true })
await rm(carPath, { force: true })
const inner = new Uint8Array(
  await new Response(new Blob([envelope]).stream().pipeThrough(fee.decrypt(ks.keyResolver(kk)))).arrayBuffer()
)
assert.equal(inner[1], 0xa2, 'the decrypted upload is the inner CAR') // a CARv1 header: varint, then a 2-entry map

// 2, 3. Share links for that upload, from the owner wallet.
const labels = pieceKey.appMetadata
const open = await createShare({ sender: { owner }, rootCid, labels, mode: 'open', viewer: VIEWER })
const restricted = await createShare({ sender: { owner }, rootCid, labels, mode: 'restricted', viewer: VIEWER })
for (const [link, access] of [
  [open.link, open.link.split('&k=')[1]],
  [restricted.link, restricted.accessKey],
]) {
  const payload = Buffer.from(link.split('&d=')[1].split('&')[0], 'base64url')
  const T = `0x${Buffer.from(access.slice('fak1_'.length), 'base64url').toString('hex')}`
  assert.deepEqual(await ks.unwrapWith(T, payload), pieceKey.cek)
}

// 4, 5, 6. Grants (fgr1_ deliveries), as the console signs them for a session key.
async function grant(chainAndKey, node, bearer) {
  const { chain, nodeKey } = await chainAndKey
  const delivery = ks.encodeDelivery(
    chain,
    await ks.wrapTo(ks.publicKeyOf(bearer.privateKey), nodeKey, ks.grantDescriptor(ref, node))
  )
  assert.deepEqual((await ks.openDelivery(bearer.privateKey, delivery)).key, nodeKey)
  return `fgr1_${b64(delivery)}`
}
const root = (node, bearer, maxDepth) =>
  ks.rootClaim(owner, {
    ...ref,
    chainId: CHAIN_ID,
    kk,
    node,
    bearer: bearer.account.address,
    maxDepth,
    expires: EXPIRES,
  })

const session = key()
const team = key()
const delegator = key()
const agent = key()
const sessionRoot = await root('keyspace', delegator, 1)
const nested = ks.delegateClaim(delegator.account, sessionRoot.chain, {
  parentKey: sessionRoot.nodeKey,
  node: 'scope:team/alice',
  bearer: agent.account.address,
  maxDepth: 0,
})

const samples = [
  {
    title: 'An encrypted upload (nested CAR)',
    about:
      'What `filecoin-pin add --encrypt` stores, and what a gateway serves for its root CID: an outer CAR holding encrypted.fee, whose ciphertext is the inner CAR of hello.txt. The inspector finds the envelope inside the CAR.',
    items: [{ label: `Outer CAR, base64 (root ${rootCid})`, text: car.toString('base64'), file: 'upload.car' }],
  },
  {
    title: 'A self-contained Share link',
    about:
      'An open link: it carries its own Access key (k=), so the link alone opens the upload. Turn on Danger mode to open it here.',
    items: [{ label: 'Share link', text: open.link }],
  },
  {
    title: 'A Share link with a detached Access key',
    about:
      'A restricted link: the Access key is sent separately. Turn on Danger mode and paste the key into the key box to open it.',
    items: [
      { label: 'Share link', text: restricted.link },
      { label: 'Access key', text: restricted.accessKey },
    ],
  },
  {
    title: 'A Grant for the whole keyspace (kk)',
    about:
      'One link from the owner, as the console grants a session key at login: node "keyspace", no further delegation.',
    items: [
      { label: 'Grant', text: await grant(root('keyspace', session, 0), 'keyspace', session) },
      { label: 'Session key (Danger mode, key box)', text: `SESSION_KEY=${session.privateKey}` },
    ],
  },
  {
    title: 'A Grant for a scope',
    about:
      'One link from the owner for scope "team" only: it opens uploads in team and below, not the rest of the keyspace.',
    items: [
      { label: 'Grant', text: await grant(root('scope:team', team, 0), 'scope:team', team) },
      { label: 'Session key (Danger mode, key box)', text: `SESSION_KEY=${team.privateKey}` },
    ],
  },
  {
    title: 'A nested claim chain',
    about:
      'Two links: the owner grants a session key the keyspace with one level of delegation, and the session key narrows it to scope "team/alice" for an agent.',
    items: [
      { label: 'Grant', text: await grant(nested, 'scope:team/alice', agent) },
      { label: "Agent's key (Danger mode, key box)", text: `SESSION_KEY=${agent.privateKey}` },
    ],
  },
]

await writeFile(new URL('../src/samples.json', import.meta.url), `${JSON.stringify(samples, null, 2)}\n`)
console.log(
  `wrote ${samples.length} samples; upload CAR ${car.length} B, envelope ${envelope.length} B, root ${rootCid}`
)
