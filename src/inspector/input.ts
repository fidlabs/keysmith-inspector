/**
 * Pasted text → bytes to inspect. Recognises the text forms Keysmith and filecoin-pin print, and
 * refuses anything shaped like a private key: pasting one into a web page is a habit worth
 * breaking. Danger mode (`{ danger: true }`) accepts keys instead and returns them as `key`.
 */
import { type Hex, hexToBytes } from 'viem'

export type Parsed =
  // key: a private key from the paste (danger mode only); keyOnly: the bytes are that key, not a structure
  | { ok: true; bytes: Uint8Array; source: string; notes: string[]; key?: Hex; keyOnly?: boolean }
  | { ok: false; refusal: string }

export interface Options {
  danger?: boolean // accept private keys instead of refusing them
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
  if (bytes.length !== 32) return { ok: false, refusal: `${source} is ${bytes.length} bytes, not a 32-byte private key.` }
  return { ok: true, bytes, source, notes: [], key: toHex(bytes), keyOnly: true }
}

/** A whole `session.env`: the grant to inspect, plus the session key in danger mode. */
function parseEnvFile(lines: string[], danger: boolean): Parsed {
  const vars = lines.map((line) => DOTENV.exec(line) as unknown as [string, string, string])
  const secret = vars.find(([, name]) => SECRET_VARS.has(name))
  if (secret && !danger) return { ok: false, refusal: `${secret[1]} holds a private key. ${PRIVATE_KEY_REFUSAL}` }
  const grant = vars.find(([, name, value]) => name.endsWith('_GRANT') || value.startsWith('fgr1_'))
  const first = grant ?? secret
  if (!first) return { ok: false, refusal: 'Dotenv lines, but none holds a Grant (a *_GRANT variable or an fgr1_ value).' }
  const parsed = parseText(first[0], { danger })
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

/** A share link's fragment: `v1/<root cid>/<delivery>[/<secret>]` (filecoin-pin#779). */
function parseShareLink(fragment: string, danger: boolean): Parsed {
  const [version, rootCid, delivery, secret, ...rest] = fragment.split('/')
  if (version !== 'v1') return { ok: false, refusal: `An unknown share link version: ${JSON.stringify(version)}.` }
  if (!rootCid || !delivery || rest.length > 0) return { ok: false, refusal: 'A v1 share link, but not of the form v1/<root cid>/<delivery>[/<secret>].' }
  const notes = [`Share link v1 for the upload with encrypted root CID ${rootCid}.`]
  let key: Hex | undefined
  if (secret?.startsWith('fak1_') && danger) {
    const access = parseText(secret, { danger })
    if (!access.ok) return access
    key = access.key
    notes.push('This link carries its Access key (a restricted link): anyone who has the link can read the upload. Opening it with that key.')
  } else if (secret?.startsWith('fak1_')) {
    notes.push(
      'This link carries its Access key (a restricted link): anyone who has the link can read the upload. The key was not decoded or shown. Treat the link itself as a secret.'
    )
  } else if (secret?.startsWith('pw1.')) {
    notes.push('Password mode: the link carries the password salt. The password is not in the link.')
  } else if (secret) {
    notes.push(`The link ends with an unknown secret form (${JSON.stringify(secret.slice(0, 5))}…), which was ignored.`)
  } else {
    notes.push('The Access key is not in the link: it is sent separately.')
  }
  return { ok: true, bytes: decodeBase64(delivery), source: 'share link delivery', notes, key }
}

export function parseText(raw: string, { danger = false }: Options = {}): Parsed {
  let text = raw.trim()
  const notes: string[] = []
  let source = 'pasted bytes'

  // A whole session.env, several dotenv lines.
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
  if (lines.length > 1 && lines.every((line) => DOTENV.test(line))) return parseEnvFile(lines, danger)

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

  if (/^fak1_/.test(text)) {
    let bytes: Uint8Array
    try {
      bytes = decodeBase64(text.slice('fak1_'.length))
    } catch {
      return { ok: false, refusal: 'An Access key (fak1_…), but not base64url.' }
    }
    return keyResult(bytes, 'Access key (fak1_)', 'This is an Access key (fak1_…): the private key that opens a share link.', danger)
  }
  const hash = text.indexOf('#v1/')
  if (hash !== -1 || text.startsWith('v1/')) return parseShareLink(hash === -1 ? text : text.slice(hash + 1), danger)

  const header = /^(Authorization:\s*)?FOC-Grant\s+(\S+)$/i.exec(text)
  if (header) {
    text = header[2] as string
    source = 'FOC-Grant header'
  } else if (text.startsWith('fgr1_')) {
    text = text.slice('fgr1_'.length)
    source = 'Grant (fgr1_)'
  }

  let bytes: Uint8Array
  try {
    bytes = bytesFromText(text)
  } catch {
    return { ok: false, refusal: 'Not hex, base64 or base64url, nor a Grant, share link or FOC-Grant header this inspector knows.' }
  }
  // 32 bare bytes are a key, not a structure: secp256k1 private keys and Keysmith node keys alike.
  if (secretVar || bytes.length === 32) {
    return keyResult(bytes, secretVar ?? 'pasted bytes', secretVar ? `${secretVar} holds a private key.` : 'These are 32 bare bytes.', danger)
  }
  return { ok: true, bytes, source, notes }
}
