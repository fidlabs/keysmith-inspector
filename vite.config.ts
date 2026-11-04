import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'

/**
 * The built page may load its own scripts and styles and nothing else: no network requests at
 * all (`connect-src 'none'`), so "nothing leaves your browser" is enforced by the browser and
 * anyone can check it in devtools. Build only: the dev server needs its websocket and inline
 * module preamble.
 */
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ')

const contentSecurityPolicy = (): Plugin => ({
  name: 'content-security-policy',
  apply: 'build',
  transformIndexHtml: (html) =>
    html.replace('<head>', `<head>\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />`),
})

export default defineConfig({
  // Relative asset paths, so the build works from any subpath (GitHub Pages serves it under /<repo>/).
  base: './',
  build: { target: 'es2022' },
  plugins: [react(), contentSecurityPolicy()],
})
