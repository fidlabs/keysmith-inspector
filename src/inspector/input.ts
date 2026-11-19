/**
 * Pasted text → bytes to inspect. Recognises the text forms Keysmith and filecoin-pin print, and
 * refuses anything shaped like a private key: pasting one into a web page is a habit worth
 * breaking. Danger mode (`{ danger: true }`) accepts keys instead and returns them as `key`.
 */
import { type Hex, hexToBytes } from 'viem'

export type Parsed =
  // key: a private key from the paste (danger mode only); keyOnly: the bytes are that key, not a structure
  // of: which of several comma-separated Grants in one value this is (filecoin-pin's GROUP_KEY_GRANT holds one per group)
  | {
      ok: true
      bytes: Uint8Array
      source: string
      notes: string[]
      key?: Hex
      keyOnly?: boolean
      of?: { index: number; count: number }
    }
  | { ok: false; refusal: string }

export interface Options {
  danger?: boolean // accept private keys instead of refusing them
  pick?: number // which Grant of a comma-separated list to show, from 0
}

const PRIVATE_KEY_REFUSAL =
  'This looks like a private key. The inspector does not decode keys, and you should not paste one into any web page: treat it as exposed if it was real.'

/** `session.env` / dotenv variables that hold a private key. */
const SECRET_VARS = new Set(['SESSION_KEY', 'PRIVATE_KEY'])
const DOTENV = /^([A-Z][A-Z0-9_]*)=(.*)$/s

const toHex = (bytes: Uint8Array) => `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}` as Hex

/** A private key as bytes, in danger mode, or the refusal. */
function keyResult(bytes: Uint8Array, source: string, refusal: string, danger: boolean): Parsed {
  if (!danger) return { ok: false, refusal: `${refusal} ${PRIVATE_KEY_REFUSAL}` }
  if (bytes.length !== 32)
    return { ok: false, refusal: `${source} is ${bytes.length} bytes, not a 32-byte private key.` }
  return { ok: true, bytes, source, notes: [], key: toHex(bytes), keyOnly: true }
}

/** A whole `session.env`: the grant to inspect, plus the session key in danger mode. */
function parseEnvFile(lines: string[], danger: boolean, pick: number): Parsed {
  const vars = lines.map((line) => DOTENV.exec(line) as unknown as [string, string, string])
  const secret = vars.find(([, name]) => SECRET_VARS.has(name))
  if (secret && !danger) return { ok: false, refusal: `${secret[1]} holds a private key. ${PRIVATE_KEY_REFUSAL}` }
  const grant = vars.find(([, name, value]) => name.endsWith('_GRANT') || value.startsWith('fgr1_'))
  const first = grant ?? secret
  if (!first)
    return { ok: false, refusal: 'Dotenv lines, but none holds a Grant (a *_GRANT variable or an fgr1_ value).' }
  const parsed = parseText(first[0], { danger, pick })
  if (!parsed.ok || !secret || parsed.keyOnly) return parsed
  const key = parseText(secret[0], { danger })
  if (!key.ok) return key
  return { ...parsed, key: key.key, notes: [...parsed.notes, `Opening it with ${secret[1]}.`] }
}

function decodeBase64(text: string): Uint8Array {
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/')
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) throw new Error('not hex, base64 or base64url')
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4))
  return Uint8Array.from(binary, (c) => c.charCodeAt(0))
}

/** Hex (with or without 0x), else base64 or base64url. */
export function bytesFromText(text: string): Uint8Array {
  const clean = text.replace(/\s+/g, '')
  if (/^(0x)?[0-9a-fA-F]+$/.test(clean) && clean.replace(/^0x/, '').length % 2 === 0) {
    return hexToBytes(`0x${clean.replace(/^0x/, '')}` as Hex)
  }
  return decodeBase64(clean)
}

/** A share link's fragment, as filecoin-pin writes it: `v1/<root cid>&d=<grant>[&k=<Access key>]`. */
/** The providers a private upload's link names (`s=`): comma-separated, URI-encoded http(s) URLs. Null if one isn't. */
function providersOf(value: string | undefined): string[] | null {
  if (value == null || value === '') return []
  const urls: string[] = []
  for (const part of value.split(',')) {
    try {
      const url = new URL(decodeURIComponent(part))
      if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) return null
      urls.push(url.toString().replace(/\/+$/, ''))
    } catch {
      return null
    }
  }
  return urls
}

function parseShareLink(fragment: string, danger: boolean): Parsed {
  const version = fragment.slice(0, fragment.indexOf('/'))
  if (version !== 'v1') return { ok: false, refusal: `An unknown share link version: ${JSON.stringify(version)}.` }
  const [rootCid, ...params] = fragment.slice('v1/'.length).split('&')
  const values = new Map<string, string>()
  for (const param of params) {
    const at = param.indexOf('=')
    const name = at < 0 ? param : param.slice(0, at)
    if (!['d', 's', 'k'].includes(name) || values.has(name))
      return { ok: false, refusal: `A v1 share link with an unexpected part: ${JSON.stringify(name)}.` }
    values.set(name, param.slice(at + 1))
  }
  const grant = values.get('d')
  const access = values.get('k')
  const providers = providersOf(values.get('s'))
  if (providers === null)
    return { ok: false, refusal: 'A share link whose s= names a provider that is not an http(s) URL.' }
  if (!rootCid || !grant)
    return { ok: false, refusal: 'A v1 share link, but not of the form v1/<root cid>&d=<grant>[&k=<Access key>].' }
  let bytes: Uint8Array
  try {
    bytes = decodeBase64(grant)
  } catch {
    return { ok: false, refusal: 'A v1 share link whose d= part is not base64url.' }
  }
  // A CBOR array is a Delivery: a private upload's link, which also carries the right to fetch it.
  const delivery = bytes[0] != null && bytes[0] >> 5 === 4
  const notes = [
    delivery
      ? `Share link v1 for the private upload with root CID ${rootCid}. It carries a Delivery: a claim chain whose final claim names the piece (its CID is the claim's locator) and is borne by the link's Access key, plus the piece key wrapped to it. The reader signs a request with the Access key and fetches /download/<piece> on the authenticated path.`
      : `Share link v1 for the upload with root CID ${rootCid}. It carries a grant wrapped to the link's Access key.`,
  ]
  if (providers.length > 0) notes.push(`Providers that hold the piece (s=): ${providers.join(', ')}.`)
  let key: Hex | undefined
  if (access != null) {
    const open = parseText(access, { danger })
    if (danger && !open.ok) return open
    key = open.ok ? open.key : undefined
    notes.push(
      `An open link: it carries its Access key (k=), so anyone who has the link can open the upload. Treat the link itself as a secret. ${
        danger ? 'Opening it with that key.' : 'The key was not decoded or shown.'
      }`
    )
  } else {
    notes.push(
      `A restricted link: its Access key is sent separately.${danger ? ' Paste it into the key box to open it.' : ''}`
    )
  }
  return { ok: true, bytes, source: 'share link grant', notes, key }
}

/** The Basic-auth user and cookie name Curio reads a grant from, plain and URL-escaped. */
const GRANT_NAMES = new Set(['FOC Grant', 'FOC%20Grant'])
const GRANT_COOKIE = /(?:^|;)\s*FOC(?: |%20)Grant=/

type Token = { token: string; source: string; notes: string[] } | { refusal: string }

/** A `foc_grant` query parameter, in a URL or on its own, as the viewer and Curio's gate use it. */
const GRANT_QUERY = /(?:^|[?&])foc_grant=([^&#\s]*)/

/**
 * A grant token as Curio's gate takes it from a request (curio lib/keysmith, `Credential`): `Authorization: FOC-Grant
 * <token>`, a bare `Authorization: <token>`, Basic auth as user `FOC Grant`, a `FOC Grant` cookie, or a `foc_grant`
 * query parameter (a `/download/` URL, as the viewer fetches a private upload). Null for none of these. Other
 * credentials in the paste (another user's password, other cookies) are never decoded or shown.
 */
function curioToken(text: string): Token | null {
  const notes: string[] = []
  const query = /^Authorization:/i.test(text) ? null : GRANT_QUERY.exec(text)
  if (query) {
    let token: string
    try {
      token = decodeURIComponent(query[1] as string)
    } catch {
      return { refusal: 'A foc_grant query whose value is not URL-encoded text.' }
    }
    if (!token) return { refusal: 'A foc_grant query with no value: no grant.' }
    const piece = /\/download\/([a-z0-9]+)/i.exec(text)?.[1]
    if (piece) notes.push(`A request for piece ${piece} on the authenticated path (/download/).`)
    return { token, source: 'foc_grant query', notes }
  }
  const auth = /^Authorization:\s*(.*)$/is.exec(text)
  let value = auth ? (auth[1] as string).trim() : text
  let source: string | undefined
  const basic = /^Basic\s+(\S+)$/i.exec(value)
  const cookie = auth ? null : /^Cookie:\s*(.*)$/is.exec(text)
  if (basic) {
    let pair: string
    try {
      pair = atob(basic[1] as string)
    } catch {
      return { refusal: 'Basic auth whose credentials are not base64.' }
    }
    const colon = pair.indexOf(':')
    const user = colon < 0 ? pair : pair.slice(0, colon)
    if (!GRANT_NAMES.has(user)) {
      return {
        refusal:
          'Basic auth for another user: Curio reads a grant only from user "FOC Grant" (or "FOC%20Grant"). Its password was not decoded or shown.',
      }
    }
    value = pair.slice(colon + 1).trim()
    if (colon < 0 || !value)
      return { refusal: `Basic auth as user ${JSON.stringify(user)}, but with no password: no grant.` }
    source = `Authorization: Basic, user ${JSON.stringify(user)}`
  } else if (cookie || GRANT_COOKIE.test(text)) {
    const grants = (cookie ? (cookie[1] as string) : text)
      .split(';')
      .map((part) => part.trim())
      .filter((part) => GRANT_NAMES.has(part.slice(0, part.indexOf('='))) && part.indexOf('=') < part.length - 1)
      .map((part) => part.slice(part.indexOf('=') + 1))
    if (grants.length === 0) {
      return {
        refusal: 'A Cookie header with no "FOC Grant" cookie, the one Curio reads. Its other cookies were not shown.',
      }
    }
    value = grants.reduce((best, grant) => (grant.length > best.length ? grant : best))
    source = 'FOC Grant cookie'
    if (grants.length > 1) notes.push(`${grants.length} FOC Grant cookies: Curio uses the longest, shown here.`)
  }
  const scheme = /^FOC-Grant\s+(\S+)$/i.exec(value)
  if (scheme) {
    if (!value.startsWith('FOC-Grant ')) {
      notes.push('Curio matches the scheme exactly, "FOC-Grant" and a space: it refuses this spelling.')
    }
    value = scheme[1] as string
    source ??= 'FOC-Grant header'
  } else if (!auth && !source) return null
  source ??= 'Authorization header'
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(value)) {
    if (/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
      notes.push('Standard base64 (+ or /): Curio reads base64url only, and refuses this.')
    } else return { refusal: `${source}, but its value is not a base64url grant: Curio refuses it.` }
  }
  return { token: value, source, notes }
}

export function parseText(raw: string, { danger = false, pick = 0 }: Options = {}): Parsed {
  let text = raw.trim()
  const notes: string[] = []
  let source = 'pasted bytes'

  // A whole session.env, several dotenv lines.
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
  if (lines.length > 1 && lines.every((line) => DOTENV.test(line))) return parseEnvFile(lines, danger, pick)

  // A single dotenv line, as `session.env` holds it.
  const line = DOTENV.exec(text)
  let secretVar: string | undefined
  if (line) {
    const [, name, value] = line as unknown as [string, string, string]
    if (SECRET_VARS.has(name)) {
      if (!danger) return { ok: false, refusal: `${name} holds a private key. ${PRIVATE_KEY_REFUSAL}` }
      secretVar = name
    }
    text = value.trim()
    source = name
  }

  // Several Grants in one value, comma-separated, as filecoin-pin stores one per group: show the picked one.
  const grants = text.split(',').map((part) => part.trim())
  if (grants.length > 1 && grants.every((part) => part.startsWith('fgr1_'))) {
    const index = Math.min(Math.max(pick, 0), grants.length - 1)
    const parsed = parseText(grants[index] as string, { danger })
    if (!parsed.ok) return parsed
    return {
      ...parsed,
      source: line ? `${source}, Grant ${index + 1} of ${grants.length}` : parsed.source,
      notes: [
        ...parsed.notes,
        `This holds ${grants.length} Grants, comma-separated (one per group). Showing Grant ${index + 1}.`,
      ],
      of: { index, count: grants.length },
    }
  }

  if (/^fak1_/.test(text)) {
    let bytes: Uint8Array
    try {
      bytes = decodeBase64(text.slice('fak1_'.length))
    } catch {
      return { ok: false, refusal: 'An Access key (fak1_…), but not base64url.' }
    }
    return keyResult(
      bytes,
      'Access key (fak1_)',
      'This is an Access key (fak1_…): the private key that opens a share link.',
      danger
    )
  }
  const link = /(?:^|#)(v\d+\/.*)$/s.exec(text)
  if (link) return parseShareLink(link[1] as string, danger)

  const curio = curioToken(text)
  if (curio && 'refusal' in curio) return { ok: false, refusal: curio.refusal }
  if (curio) {
    text = curio.token
    source = curio.source
    notes.push(...curio.notes)
  } else if (text.startsWith('fgr1_')) {
    text = text.slice('fgr1_'.length)
    source = 'Grant (fgr1_)'
  }

  let bytes: Uint8Array
  try {
    // A request token is base64url, as Curio decodes it, even when every character is also hex.
    bytes = curio ? decodeBase64(text) : bytesFromText(text)
  } catch {
    return {
      ok: false,
      refusal: 'Not hex, base64 or base64url, nor a Grant, share link or FOC-Grant header this inspector knows.',
    }
  }
  // 32 bare bytes are a key, not a structure: secp256k1 private keys and Keysmith node keys alike.
  if (secretVar || bytes.length === 32) {
    return keyResult(
      bytes,
      secretVar ?? 'pasted bytes',
      secretVar ? `${secretVar} holds a private key.` : 'These are 32 bare bytes.',
      danger
    )
  }
  return { ok: true, bytes, source, notes }
}
