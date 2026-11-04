import { useState } from 'react'
import samples from './samples.json' with { type: 'json' }

/** Throwaway test data to try (made by scripts/make-samples.mjs), folded away until opened. */
export function Samples({
  danger,
  onInspect,
  onUseKey,
}: {
  danger: boolean
  onInspect: (text: string) => void
  onUseKey: (text: string) => void
}) {
  const [copied, setCopied] = useState<string | null>(null)
  const copy = (id: string, text: string) => void navigator.clipboard.writeText(text).then(() => setCopied(id))
  const download = (name: string, base64: string) => {
    const url = URL.createObjectURL(new Blob([Uint8Array.from(atob(base64), (c) => c.charCodeAt(0))]))
    const link = document.createElement('a')
    link.href = url
    link.download = name
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  return (
    <details className="samples">
      <summary>Test data to try</summary>
      <p className="muted small">
        Made with throwaway keys for an upload that is stored nowhere. The keys below are test keys: paste them only with Danger mode on, into the key box.
      </p>
      {samples.map((sample) => (
        <section key={sample.title} className="stack sample">
          <strong>{sample.title}</strong>
          <span className="muted small">{sample.about}</span>
          {sample.items.map((item, i) => {
            const id = `${sample.title}/${item.label}`
            const isKey = i > 0
            return (
              <div key={id} className="field">
                <span>{item.label}</span>
                <textarea readOnly rows={item.text.length > 200 ? 3 : 1} value={item.text} spellCheck={false} />
                <div className="row">
                  <button type="button" className="button ghost compact" onClick={() => copy(id, item.text)}>
                    {copied === id ? 'Copied' : 'Copy'}
                  </button>
                  {isKey ? (
                    <button
                      type="button"
                      className="button ghost compact"
                      disabled={!danger}
                      title={danger ? undefined : 'Turn on Danger mode first'}
                      onClick={() => onUseKey(item.text)}
                    >
                      Put in key box
                    </button>
                  ) : (
                    <button type="button" className="button ghost compact" onClick={() => onInspect(item.text)}>
                      Inspect
                    </button>
                  )}
                  {'file' in item && item.file ? (
                    <button type="button" className="button ghost compact" onClick={() => download(item.file, item.text)}>
                      Download {item.file}
                    </button>
                  ) : null}
                </div>
              </div>
            )
          })}
        </section>
      ))}
    </details>
  )
}
