# Cinder

**Share a secret once. Then it's gone.**

Cinder is a zero-knowledge one-time secret sharer. You paste a password, an API
key, a private note — it gets encrypted in your browser, and you get a link that
works exactly once. The server never sees the plaintext, never sees the key, and
deletes the ciphertext on the first successful read.

No accounts. No database. No third-party requests. No analytics.

---

## How the crypto works

```
              browser                                server
  ┌───────────────────────────────┐      ┌────────────────────────────┐
  │ 1. secret                     │      │                            │
  │ 2. AES-256-GCM encrypt        │      │                            │
  │ 3. POST ciphertext ───────────┼─────▶│ 4. store opaque blob       │
  │                               │      │    + optional scrypt hash  │
  │ 5. link = /s/:id#k=<raw key>  │      │                            │
  └───────────────────────────────┘      └────────────────────────────┘
                 │
                 ▼  recipient opens link
  ┌───────────────────────────────┐      ┌────────────────────────────┐
  │ 7. POST /reveal ──────────────┼─────▶│ 6. delete + return blob    │
  │ 8. decrypt with key           │◀─────┼────────────────────────────┤
  │    from the URL fragment      │      │    (record is now gone)    │
  └───────────────────────────────┘      └────────────────────────────┘
```

The key travels in the **URL fragment** (`#k=...`). Browsers never send the
fragment to a server — it is stripped before the request leaves the machine — so
the key stays out of access logs, proxy logs, and `Referer` headers by
construction, not by policy.

What the server can see: the length of your secret, when it was created, and
whether it has a passphrase. That is the entire list.

### Threat model

Cinder protects against:

* **A server compromise.** A full dump of the store contains only ciphertexts.
  There is no key material on the server to decrypt them with.
* **Logs and infrastructure.** The key never reaches the server, so it is not in
  any request log along the path.
* **The link outliving the secret.** Reads are single-use and atomic; expiry is
  enforced on read, not by a background job that might not have run.
* **Shoulder-surfing on the wire.** TLS in transit, AES-GCM at rest.
* **A wrong guess burning the secret.** A bad passphrase does *not* consume the
  record, so an attacker who guesses the id cannot destroy what they cannot read.

Cinder does **not** protect against:

* A compromised client — a malicious browser extension or an infected device
  sees the plaintext before it is ever encrypted. Nothing server-side fixes that.
* The recipient screenshotting or copying the secret after reading it. Once it
  is on their screen, it is theirs.
* Anyone who has the full link *and* the passphrase. Use a different channel for
  the passphrase, or it is doing no work.
* Link previewers that issue a real `POST`. See below.

### Why reveal is a POST

Link scanners, chat preview bots and browser prefetchers all issue `GET`. If
reveal were a `GET`, pasting a Cinder link into Slack would silently burn the
secret before the recipient ever clicked it. So metadata is `GET` (safe, no side
effects) and reveal is `POST` (consuming).

This is a real limitation to know about: any tool that follows a link *and* posts
to it will consume the secret. That is the correct trade — a secret that gets
destroyed by an over-eager previewer is annoying; one that survives forever
because nothing could trigger it is useless.

---

## Run it

```bash
git clone https://github.com/danielol237/cinder.git
cd cinder
npm start
```

No install step — there are no dependencies. Node 18.17+.

Open <http://localhost:3000>.

```bash
npm test              # 51 tests, ~6s
npm run test:coverage # with coverage
```

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | Listen port |
| `CINDER_TRUST_PROXY` | unset | Set to `1` only behind a proxy that overwrites `X-Forwarded-For`, so rate limiting keys on the real client IP |

### Docker

```bash
docker build -t cinder .
docker run -p 3000:3000 cinder
```

### Deploy to Netlify

Live instance: **<https://guileless-empanada-7a964a.netlify.app>**

Netlify runs the same app in two pieces:

* `public/` is served as static files.
* `netlify/functions/api.mjs` is the API, with records in **Netlify Blobs** so
  secrets survive between invocations and across regions.

`_redirects` maps `/api/*` onto the function and `/s/*` onto the app shell.

To deploy your own:

```bash
npm i -g netlify-cli
netlify deploy --prod
```

Or drag the repo folder onto <https://app.netlify.com/drop>.

The only behavioural difference from the Node server is the rate limiter:
Blobs is not a counter, so it uses a coarse per-minute marker rather than an
exact sliding window. Same limits, less precision.

---

## Architecture

```
src/
  server.js      HTTP layer: routing, validation, headers, rate limiting
  store.js       in-memory record store, single-use reads, scrypt hashing
  rateLimit.js   sliding-window limiter
netlify/
  functions/api.mjs  same API on Netlify Functions + Blobs
public/
  index.html     app shell
  app.js         UI + router
  crypto.js      AES-GCM + base64url — shared by browser and tests
  styles.css     the whole visual system, no framework
test/
  crypto.test.js  round trips, tampering, key handling
  store.test.js   expiry, single-use, passphrase, capacity
  server.test.js  HTTP contract, headers, rate limits, traversal
  e2e.test.js     encrypt → store → reveal → decrypt, with real crypto
```

`public/crypto.js` is imported by both the browser and the Node test suite. The
code the tests exercise is byte-for-byte the code that runs in production —
there is no test-only reimplementation to drift out of sync.

### Design decisions

**In-memory store, not a database.** A one-time secret has a lifetime measured in
hours. Persisting it to disk adds an attack surface (backups, snapshots, replicas)
and buys nothing, because the whole point is that it disappears. The trade-off is
that a restart loses unread secrets — acceptable for a 5-minute-to-7-day window,
and documented rather than hidden.

**No dependencies.** The entire dependency tree is empty. Every line that handles
your plaintext is in this repo and small enough to read in one sitting. For a
security tool, "you can audit it" beats "it has a nice ORM".

**Rate limiting on both endpoints, separately.** Creating and revealing are
different attacks: create is a storage flood, reveal is an id-guessing sweep. One
shared bucket would let an attacker starve the other.

**Hard caps everywhere.** 128 KB per ciphertext, 10k live records, 256 KB request
bodies. Unbounded anything is a denial-of-service waiting for a quiet afternoon.

**Strict CSP.** `default-src 'self'`, no inline script, no `eval`, no third-party
origins. If script injection were possible, the key in the fragment would be
readable by the injected script — so script injection is made impossible rather
than merely unlikely.

---

## API

### `POST /api/secrets`

```json
{ "ciphertext": "base64url...", "ttlMs": 86400000, "passphrase": "optional" }
```

`201` → `{ "id": "...", "expiresAt": 1750000000000 }`

Allowed `ttlMs`: `300000`, `3600000`, `86400000`, `604800000`. Passphrase, when
present, must be 8–256 characters.

### `GET /api/secrets/:id`

Metadata only, does not consume.

`200` → `{ "exists": true, "requiresPassphrase": false, "createdAt": 0, "expiresAt": 0 }`

### `POST /api/secrets/:id/reveal`

Consuming. Body may carry `{ "passphrase": "..." }`.

`200` → `{ "ciphertext": "base64url..." }`
`403` → `{ "error": "bad_passphrase" }` — record is preserved
`404` → `{ "error": "not_found" | "expired" }`

### `GET /api/health`

`200` → `{ "status": "ok", "live": 0 }`

---

## License

MIT — see [LICENSE](LICENSE).
