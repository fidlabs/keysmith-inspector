import { decodeGrant, openDelivery, unwrapWith } from '@filoz/keysmith'
import { useEffect, useMemo, useState } from 'react'
import { type Hex, toHex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { envelopeInCar, inspectBytes, type View } from './inspector/describe.ts'
import { parseText } from './inspector/input.ts'
import { Samples } from './Samples.tsx'

/** Bytes shown in the hex view; the field list still covers everything. */
const SHOWN = 4096

const toBase64Url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

function title(view: View): string {
  switch (view.kind) {
    case 'piece':
      return 'A FEE-encrypted piece'
    case 'grant':
      return view.chain
        ? `A Keysmith delivery: claim chain + grant, ${view.chain.links.length} link(s), fetching until ${new Date(view.chain.expires * 1000).toLocaleString()}`
        : 'A Keysmith grant'
    case 'presentation':
      return view.chain
        ? `A FOC-Grant presentation: ${view.chain.links.length} link(s) and a request${view.request ? `, valid until ${new Date(view.request.expires * 1000).toLocaleString()}` : ''}`
        : 'A FOC-Grant presentation'
    default:
      return 'Unrecognised bytes'
  }
}

/** Danger mode: what a private key is, and what it opens (a delivery with its claim chain, or a bare grant). */
function KeyPanel({ privateKey, grant }: { privateKey: Hex; grant?: { bytes: Uint8Array; chained: boolean } }) {
  const account = useMemo(() => {
    try {
      return privateKeyToAccount(privateKey)
    } catch {
      return null
    }
  }, [privateKey])
  const { bytes, chained } = grant ?? {}
  const [opened, setOpened] = useState<{ key?: Hex; node?: string; error?: string } | null>(null)
  useEffect(() => {
    setOpened(null)
    if (!bytes || !account) return
    const opening = chained
      ? openDelivery(privateKey, bytes).then(({ key, claim }) => ({ key, node: claim.node }))
      : unwrapWith(privateKey, bytes).then((key) => ({ key, node: decodeGrant(bytes).node }))
    opening.then(
      ({ key, node }) => setOpened({ key: toHex(key), node }),
      (err: Error) => setOpened({ error: err.message })
    )
  }, [privateKey, bytes, chained, account])

  return (
    <div className="notice notice-error stack">
      <strong>Key material</strong>
      <span className="small">
        <span className="muted">Private key: </span>
        <span className="mono-wrap">{privateKey}</span>
      </span>
      {account ? (
        <>
          <span className="small">
            <span className="muted">As a secp256k1 key, its address: </span>
            <span className="mono-wrap">{account.address}</span>
          </span>
          <span className="small">
            <span className="muted">Public key: </span>
            <span className="mono-wrap">{account.publicKey}</span>
          </span>
        </>
      ) : (
        <span className="small">Not a valid secp256k1 private key (it may be a Keysmith node key).</span>
      )}
      {opened?.key ? (
        <span className="small">
          <span className="muted">Opens it. Unwrapped key for node {JSON.stringify(opened.node)}: </span>
          <span className="mono-wrap">{opened.key}</span>
        </span>
      ) : null}
      {opened?.error ? <span className="small">Does not open it: {opened.error}</span> : null}
    </div>
  )
}

export function Inspector() {
  const [danger, setDanger] = useState(false)
  const [input, setInput] = useState<{ bytes: Uint8Array; source: string; notes: string[]; key?: Hex; keyOnly?: boolean } | null>(null)
  const [pasted, setPasted] = useState('')
  const [keyText, setKeyText] = useState('') // danger mode: the key to open a delivery with, sent apart from it
  const [error, setError] = useState<string | null>(null)
  const [active, setActive] = useState<number | null>(null)
  const [copied, setCopied] = useState(false)

  const view: View | null = useMemo(() => (input ? inspectBytes(input.bytes) : null), [input])
  const load = (bytes: Uint8Array, source: string, notes: string[] = [], key?: Hex, keyOnly?: boolean) => {
    setError(null)
    setActive(null)
    setCopied(false)
    const inner = envelopeInCar(bytes)
    if (inner) {
      notes = [
        ...notes,
        `A CAR of ${bytes.length} B, as filecoin-pin stores an encrypted upload. Showing the FEE envelope (encrypted.fee) in its block ${inner.block}, from byte ${inner.offset}; if the file spans several blocks, this is only the first. The envelope's ciphertext is the inner CAR of the original files.`,
      ]
      bytes = inner.bytes
    }
    setInput({ bytes, source, notes, key, keyOnly })
  }
  const loadFile = (file: File) =>
    file.arrayBuffer().then(
      (buffer) => load(new Uint8Array(buffer), file.name),
      (err: Error) => setError(err.message)
    )
  const inspect = (text: string, keyBox: string) => {
    const parsed = parseText(text, { danger })
    const key = danger && keyBox.trim() ? parseText(keyBox, { danger }) : null
    if (!parsed.ok || (key && !(key.ok && key.keyOnly))) {
      setInput(null)
      setError(!parsed.ok ? parsed.refusal : key && !key.ok ? `Key box: ${key.refusal}` : 'Key box: that is not a private key.')
    } else if (key?.ok) {
      load(parsed.bytes, parsed.source, [...parsed.notes, 'Opening it with the key from the key box.'], key.key, parsed.keyOnly)
    } else load(parsed.bytes, parsed.source, parsed.notes, parsed.key, parsed.keyOnly)
  }

  const owners = useMemo(() => {
    const byte: number[] = []
    for (const [i, f] of (view?.fields ?? []).entries()) for (let b = f.start; b < Math.min(f.end, SHOWN); b++) byte[b] = i
    return byte
  }, [view])
  const activeField = active != null ? view?.fields[active] : undefined

  return (
    <div className="stack">
      <div className={`danger${danger ? ' on' : ''}`}>
        <label className="switch">
          <input
            type="checkbox"
            role="switch"
            checked={danger}
            onChange={(event) => {
              setDanger(event.target.checked)
              // Leaving danger mode forgets any key on screen or in the key box.
              if (!event.target.checked) {
                setKeyText('')
                if (input?.key) setInput(null)
              }
            }}
          />
          <span>
            <strong>Danger mode</strong>: decode private keys and Access keys, and open deliveries with them
          </span>
        </label>
        {danger ? (
          <p className="small">Use only throwaway or test keys: treat any real key you paste here as exposed. Turning this off clears every key from the page.</p>
        ) : null}
      </div>
      <div className="inputs">
        <div className="input-col">
          <span className="caption">Drop a piece (encrypted.fee) or a grant file</span>
          <label
            className="dropzone"
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault()
              const file = event.dataTransfer.files[0]
              if (file) void loadFile(file)
            }}
          >
            <input
              type="file"
              onChange={(event) => {
                const file = event.target.files?.[0]
                if (file) void loadFile(file)
              }}
            />
            <span>Drop it here, or choose one</span>
          </label>
        </div>
        <div className="input-col">
          <label htmlFor="paste" className="caption">
            Or paste: a Grant (fgr1_…), a share link, an Authorization: FOC-Grant header, a KEYSPACE_GRANT= line, or hex / base64 / base64url bytes
          </label>
          <textarea
            id="paste"
            rows={4}
            value={pasted}
            spellCheck={false}
            onChange={(event) => setPasted(event.target.value)}
            placeholder="fgr1_gwGB…"
          />
          <div className="stack controls">
            {danger ? (
              <label className="field">
                <span>Key to open it with, if it was sent separately: an Access key (fak1_…), a SESSION_KEY= line or a hex private key</span>
                <input
                  type="text"
                  className="mono"
                  value={keyText}
                  spellCheck={false}
                  autoComplete="off"
                  onChange={(event) => setKeyText(event.target.value)}
                  placeholder="fak1_…"
                />
              </label>
            ) : null}
            <div className="row">
              <button type="button" className="button primary" disabled={!pasted.trim()} onClick={() => inspect(pasted, keyText)}>
                Inspect
              </button>
            </div>
          </div>
        </div>
      </div>
      {error ? <p className="notice notice-error">{error}</p> : null}

      {input?.key ? (
        <KeyPanel privateKey={input.key} grant={!input.keyOnly && view?.kind === 'grant' ? { bytes: input.bytes, chained: !!view.chain } : undefined} />
      ) : null}

      {input && view && !input.keyOnly ? (
        <>
          <div className="row">
            <strong>{title(view)}</strong>
            <span className="muted small">
              {input.source} · {input.bytes.length} B
              {view.kind === 'piece'
                ? ` · ${view.algorithm} · ${view.envelopeSize} B envelope + ${input.bytes.length - view.envelopeSize} B ciphertext, ${view.chunkCount} chunk(s)`
                : ''}
            </span>
            {view.kind === 'grant' || view.kind === 'presentation' ? (
              <button
                type="button"
                className="button ghost compact"
                onClick={() => void navigator.clipboard.writeText(toBase64Url(input.bytes)).then(() => setCopied(true))}
              >
                {copied ? 'Copied' : 'Copy as base64url'}
              </button>
            ) : null}
          </div>
          {input.notes.map((note) => (
            <p key={note} className="notice notice-info">
              {note}
            </p>
          ))}
          {view.kind === 'unknown' ? <p className="notice notice-warn">{view.reason}</p> : null}
          {(view.kind === 'grant' || view.kind === 'presentation') && view.strictError ? (
            <p className="notice notice-error">Keysmith refuses this: {view.strictError}</p>
          ) : null}
          {(view.kind === 'grant' || view.kind === 'presentation') && !view.strictError ? (
            <p className="notice notice-ok">Keysmith's strict decoder accepts it. Signatures are not checked here.</p>
          ) : null}
          <div className="bytes-view">
            <div className="hex" onMouseLeave={() => setActive(null)}>
              {Array.from({ length: Math.ceil(Math.min(input.bytes.length, SHOWN) / 16) }, (_, row) => (
                <div key={row} className="hex-row">
                  <span className="offset">{(row * 16).toString(16).padStart(4, '0')}</span>
                  {Array.from(input.bytes.subarray(row * 16, Math.min(row * 16 + 16, SHOWN)), (byte, i) => {
                    const at = row * 16 + i
                    const owner = owners[at]
                    const group = owner != null ? view.fields[owner]?.group : 'none'
                    const lit = activeField && at >= activeField.start && at < activeField.end
                    return (
                      <span key={at} className={`byte g-${group}${lit ? ' lit' : ''}`} onMouseEnter={() => setActive(owner ?? null)}>
                        {byte.toString(16).padStart(2, '0')}
                      </span>
                    )
                  })}
                </div>
              ))}
              {input.bytes.length > SHOWN ? <div className="muted small">… {input.bytes.length - SHOWN} more bytes</div> : null}
            </div>
            <ol className="fields" onMouseLeave={() => setActive(null)}>
              {view.fields.map((f, i) => (
                <li
                  key={`${f.start}:${f.label}`}
                  className={`g-${f.group} depth-${Math.min(f.depth, 4)}${active === i ? ' lit' : ''}`}
                  onMouseEnter={() => setActive(i)}
                >
                  <span className="field-name">{f.label}</span>
                  {f.value ? <span className="mono field-value">{f.value}</span> : null}
                  <span className="muted small">
                    @{f.start}–{f.end} ({f.end - f.start} B){f.note ? ` · ${f.note}` : ''}
                  </span>
                </li>
              ))}
            </ol>
          </div>
          {view.kind === 'grant' && view.aad ? (
            <p className="small">
              <span className="muted">Authenticated bytes, deterministic CBOR [v, node, owner, keyspace]: </span>
              <span className="mono-wrap">{view.aad}</span>
            </p>
          ) : null}
        </>
      ) : null}

      <Samples
        danger={danger}
        onInspect={(text) => {
          setPasted(text)
          inspect(text, keyText)
          window.scrollTo({ top: 0, behavior: 'smooth' })
        }}
        onUseKey={(text) => {
          setKeyText(text)
          window.scrollTo({ top: 0, behavior: 'smooth' })
        }}
      />
    </div>
  )
}
