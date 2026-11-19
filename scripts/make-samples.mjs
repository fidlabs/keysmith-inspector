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
const { openGroupKeyGrant } = await import(join(fp, 'dist/common/group-key-grant.js'))
const { calculate } = await import(join(fp, 'node_modules/@filoz/synapse-core/dist/src/piece/index.js'))

const VIEWER = 'https://viewer.invalid/' // the fragment is what matters; no viewer holds this sample upload
const CHAIN_ID = 314159n // calibration
const EXPIRES = 4102444800 // 2100-01-01
const b64 = (bytes) => Buffer.from(bytes).toString('base64url')
const key = () => {
  const privateKey = generatePrivateKey()
  return { privateKey, account: privateKeyToAccount(privateKey) }
}

// The owner wallet and its group key, as filecoin-pin derives them.
const owner = key().account
const ref = { owner: owner.address, groupKeyId: defaultGroupKeyId(owner.address) }
const { groupKey, descriptor } = await ks.deriveGroupKey(owner, ref)

// 1. `add --encrypt`: inner UnixFS CAR → FEE → encrypted.fee → outer UnixFS CAR.
async function upload(target) {
  const dir = await mkdtemp(join(tmpdir(), 'inspector-samples-'))
  const plaintext = join(dir, 'hello.txt')
  await writeFile(plaintext, 'Hello from the Keysmith Inspector samples.\n')
  const pieceKey = newPieceKey(target)
  await encryptPath(plaintext, join(dir, ENCRYPTED_FILE_NAME), pieceKey)
  const { carPath, rootCid } = await createCarFromPath(join(dir, ENCRYPTED_FILE_NAME))
  const car = await readFile(carPath)
  const envelope = await readFile(join(dir, ENCRYPTED_FILE_NAME))
  await rm(dir, { recursive: true })
  await rm(carPath, { force: true })
  return { pieceKey, rootCid, car, envelope }
}
const { pieceKey, rootCid, car, envelope } = await upload(ks.writeTarget(descriptor, groupKey))
const inner = new Uint8Array(
  await new Response(new Blob([envelope]).stream().pipeThrough(fee.decrypt(ks.keyResolver(groupKey)))).arrayBuffer()
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
    groupKey,
    node,
    bearer: bearer.account.address,
    maxDepth,
    expires: EXPIRES,
  })

const session = key()
const team = key()
const delegator = key()
const agent = key()
const sessionGrant = root('groupKey', session, 0)
const sessionRoot = await root('groupKey', delegator, 1)

// 7, 8. The Authorization header for one gated fetch of a piece (an outer CAR), signed by the chain's final bearer and
// checked as the gate checks it. As keysmith's authorizationHeader() builds it; use that once a release has it.
async function header(bearer, chain, piece) {
  const pieceCid = (await calculate(piece.car)).bytes
  const now = Math.floor(Date.now() / 1000)
  const request = await ks.signRequest(bearer.account, chain, { pieceCid, expires: now + 240 })
  const presentation = ks.encodePresentation(chain, request)
  const labels = piece.pieceKey.appMetadata
  const served = await ks.verifyPresentation(presentation, { pieceCid, piece: labels, chainId: CHAIN_ID, now })
  assert.equal(served.bearer, bearer.account.address)
  return `Authorization: FOC-Grant ${b64(presentation)}`
}
const nested = ks.delegateClaim(delegator.account, sessionRoot.chain, {
  parentKey: sessionRoot.nodeKey,
  node: 'group:team/alice',
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
    title: 'A Grant for the whole group key',
    about:
      'One link from the owner, as the console grants a session key at login: node "groupKey", no further delegation.',
    items: [
      { label: 'Grant', text: await grant(sessionGrant, 'groupKey', session) },
      { label: 'Session key (Danger mode, key box)', text: `SESSION_KEY=${session.privateKey}` },
    ],
  },
  {
    title: 'A Grant for a group',
    about:
      'One link from the owner for group "team" only: it opens uploads in team and below, not the rest of the group key.',
    items: [
      { label: 'Grant', text: await grant(root('group:team', team, 0), 'group:team', team) },
      { label: 'Session key (Danger mode, key box)', text: `SESSION_KEY=${team.privateKey}` },
    ],
  },
  {
    title: 'A nested claim chain',
    about:
      'Two links: the owner grants a session key the group key with one level of delegation, and the session key narrows it to group "team/alice" for an agent.',
    items: [
      { label: 'Grant', text: await grant(nested, 'group:team/alice', agent) },
      { label: "Agent's key (Danger mode, key box)", text: `SESSION_KEY=${agent.privateKey}` },
    ],
  },
  {
    title: 'An Authorization header for a gated fetch',
    about:
      "What a client sends Curio to fetch the upload above: the group key Grant's claim chain, and a request signed by its session key naming the upload's piece. A real header is good for 4 minutes; this one has long expired.",
    items: [
      { label: 'Authorization header', text: await header(session, (await sessionGrant).chain, { pieceKey, car }) },
    ],
  },
  {
    title: 'An Authorization header from a nested claim chain',
    about:
      'The nested chain above, presented: the owner gives a session key the group key with one level of delegation, that key narrows it to group "team/alice" for an agent, and the agent signs the request for a piece in team/alice. A real header is good for 4 minutes; this one has long expired.',
    items: [
      {
        label: 'Authorization header',
        text: await header(
          agent,
          (await nested).chain,
          await upload(ks.writeTarget(descriptor, groupKey, 'team/alice'))
        ),
      },
    ],
  },
  ...(await privateSamples()),
]

// 9, 10, 11. A private upload (add --private): its share links carry a Delivery and the providers (s=), and a reader
// fetches /download/<piece> with a request it signs. The upload above stands in for the private one.
async function privateSamples() {
  const pieceCid = (await calculate(car)).toString()
  const target = { pieceCid, providers: ['https://sp.invalid/pdp'], chainId: Number(CHAIN_ID) }
  const byOwner = await createShare({
    sender: { owner },
    rootCid,
    labels,
    mode: 'open',
    viewer: VIEWER,
    private: target,
  })
  // A session key holds a Grant for group team that allows one more link, and delegates a piece in team/alice to the
  // link's key: the chain narrows a group to a piece, which keysmith verifies only with the piece's labels.
  const member = key()
  const opened = await openGroupKeyGrant(await grant(root('group:team', member, 1), 'group:team', member), {
    sessionKey: member.privateKey,
    walletAddress: owner.address,
    chainId: Number(CHAIN_ID),
  })
  const inTeam = await upload(ks.writeTarget(descriptor, groupKey, 'team/alice'))
  const bySession = await createShare({
    sender: { grants: [opened], sessionKey: member.privateKey },
    rootCid: inTeam.rootCid,
    labels: inTeam.pieceKey.appMetadata,
    mode: 'open',
    viewer: VIEWER,
    private: { ...target, pieceCid: (await calculate(inTeam.car)).toString() },
  })
  const token = (await header(session, (await sessionGrant).chain, { pieceKey, car })).slice(
    'Authorization: FOC-Grant '.length
  )
  return [
    {
      title: "A private upload's Share link, from the owner",
      about:
        "An open link to a private upload (add --private): d= is a Delivery, one root claim from the owner for this piece, borne by the link's Access key, with the piece CID as its locator; s= names the providers. Turn on Danger mode to open it.",
      items: [{ label: 'Share link', text: byOwner.link }],
    },
    {
      title: "A private upload's Share link, from a session key",
      about:
        "An upload in group team/alice, shared by a session key: its Grant for group team, then a piece claim it delegates to the link's Access key (two links). keysmith verifies a chain that narrows a group to a piece only with the piece's labels, so Danger mode opens it unverified and says so.",
      items: [{ label: 'Share link', text: bySession.link }],
    },
    {
      title: 'A foc_grant request URL',
      about:
        "The query form of an Authorization header, as the viewer fetches a private upload: the session key's grant chain and its request for the upload's piece, as Curio's gate reads them. This one has long expired.",
      items: [{ label: 'Request URL', text: `https://sp.invalid/pdp/download/${pieceCid}?foc_grant=${token}` }],
    },
  ]
}

await writeFile(new URL('../src/samples.json', import.meta.url), `${JSON.stringify(samples, null, 2)}\n`)
console.log(
  `wrote ${samples.length} samples; upload CAR ${car.length} B, envelope ${envelope.length} B, root ${rootCid}`
)
