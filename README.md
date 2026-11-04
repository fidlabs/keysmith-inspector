# Keysmith Inspector

See what is inside a [Keysmith](https://www.npmjs.com/package/@filoz/keysmith) grant, delivery,
`FOC-Grant` header, share link or [FEE](https://www.npmjs.com/package/filecoin-encryption-envelope)-encrypted
piece, byte by byte. Hover a field to light up its bytes, or a byte to find its field.

It accepts:

- a Grant as filecoin-pin prints it (`fgr1_…`), or a `GROUP_KEY_GRANT=` / `KEYSPACE_GRANT=` line from `session.env`
- a share link as filecoin-pin writes it (`…#v1/<root cid>&d=<grant>[&k=<Access key>]`): the grant is shown, and an
  Access key in the link is never decoded
- an `Authorization: FOC-Grant …` header: the claim chain and the request a gating provider checks
- a FEE envelope file (`encrypted.fee`), or the CAR an encrypted upload is stored as (the envelope inside it is shown),
  or raw bytes as hex, base64 or base64url

By default it refuses anything shaped like a private key (`SESSION_KEY=`, `PRIVATE_KEY=`, `fak1_…`, 32 bare bytes):
a web page is the wrong place to paste one.

**Danger mode** (a switch, off on every page load) accepts them instead, for test and throwaway keys. It shows the
key's address and public key, and opens a delivery with it: an open share link with its own `fak1_` key, a whole
`session.env` (grant plus `SESSION_KEY`), or any link or Grant with a key pasted into the separate key box (for links
whose Access key was sent separately), showing the unwrapped key. Turning the switch off clears the key box and any key
on the page.

A folded "Test data to try" section at the bottom has samples made with throwaway keys: an encrypted upload, open and
restricted share links, and Grants for a keyspace, a scope and a two-link chain.

Everything runs in the browser. The built page carries a Content Security Policy with `connect-src 'none'`, so it
cannot make network requests; check it in your browser's developer tools.

## Develop

Requires Node 24 and pnpm (`corepack enable`).

```bash
pnpm install
pnpm dev        # http://localhost:5173
pnpm test       # node --test on the parsing code
pnpm check      # tsc
pnpm build      # static site in dist/
```

The samples (`src/samples.json`) are made with filecoin-pin's own code, from a built checkout next to this one:

```bash
FILECOIN_PIN=../filecoin-pin node scripts/make-samples.mjs
```

## Deploy

`dist/` is a static site with relative asset paths, so it can be served from any host and any subpath. Pushing to
`main` deploys it to GitHub Pages through `.github/workflows/pages.yml`; enable it once under the repository's
Settings → Pages → Source: GitHub Actions.
