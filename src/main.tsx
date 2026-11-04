import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { Inspector } from './Inspector.tsx'
import './styles.css'

function App() {
  return (
    <main className="page">
      <header className="brand">
        <h1>Keysmith Inspector</h1>
        <p>
          See what is inside a Keysmith grant, delivery, FOC-Grant header, share link or FEE-encrypted piece, byte by
          byte. Hover a field or a byte to see the other.
        </p>
        <p className="notice notice-ok small">
          Everything runs in your browser. This page makes no network requests: its Content Security Policy forbids
          them, which you can check in your browser's developer tools.
        </p>
      </header>
      <Inspector />
      <footer className="muted small">
        Built on <a href="https://www.npmjs.com/package/@filoz/keysmith">@filoz/keysmith</a> and{' '}
        <a href="https://www.npmjs.com/package/filecoin-encryption-envelope">filecoin-encryption-envelope</a>.
      </footer>
    </main>
  )
}

createRoot(document.getElementById('root') as HTMLElement).render(
  <StrictMode>
    <App />
  </StrictMode>
)
