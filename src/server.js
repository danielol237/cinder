import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SecretStore, StoreError, DEFAULT_TTL_MS, MAX_CIPHERTEXT_LENGTH } from './store.js';
import { RateLimiter } from './rateLimit.js';

const PUBLIC_DIR = fileURLToPath(new URL('../public/', import.meta.url));

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
};

/**
 * Every response gets these. The CSP is the load-bearing one: the decryption
 * key lives in the URL fragment, so we forbid inline script, eval, and any
 * third-party origin. If an attacker can inject script, the key is theirs.
 */
const SECURITY_HEADERS = {
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
  ].join('; '),
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  'Cache-Control': 'no-store',
};

const MAX_BODY_BYTES = 256 * 1024;

const ALLOWED_TTLS = new Set([5 * 60_000, 60 * 60_000, 24 * 60 * 60_000, 7 * 24 * 60 * 60_000]);

function send(res, status, body, headers = {}) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Content-Type': typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    ...headers,
  });
  res.end(payload);
}

function json(res, status, body, headers) {
  send(res, status, body, headers);
}

/**
 * Read a request body, refusing anything over the cap.
 *
 * On overflow the remaining bytes are drained rather than the socket being
 * destroyed: killing the connection mid-body means the client sees a reset
 * instead of the 413 we are trying to send it.
 */
function readBody(req, limit = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;

    req.on('data', (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > limit) {
        settled = true;
        req.resume();
        reject(Object.assign(new Error('body too large'), { code: 'too_large' }));
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks).toString('utf8'));
    });

    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
  });
}

function clientIp(req) {
  // Trusting X-Forwarded-For is only correct behind a proxy that overwrites it.
  // CINDER_TRUST_PROXY opts in to that; otherwise the socket address is used.
  if (process.env.CINDER_TRUST_PROXY === '1') {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.length > 0) {
      return forwarded.split(',')[0].trim();
    }
  }
  return req.socket.remoteAddress ?? 'unknown';
}

/** Serve a file from public/, refusing traversal. */
async function serveStatic(res, pathname) {
  const relative = pathname === '/' ? 'index.html' : pathname.slice(1);
  const resolved = normalize(join(PUBLIC_DIR, relative));
  if (!resolved.startsWith(PUBLIC_DIR.endsWith(sep) ? PUBLIC_DIR : PUBLIC_DIR + sep)) {
    return json(res, 403, { error: 'forbidden' });
  }

  try {
    const file = await readFile(resolved);
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': MIME[extname(resolved)] ?? 'application/octet-stream',
      'Content-Length': file.length,
    });
    res.end(file);
  } catch {
    json(res, 404, { error: 'not_found' });
  }
}

/**
 * Build the HTTP server.
 *
 * Kept as a factory so tests can spin up an isolated instance on port 0
 * without touching module-level state.
 */
export function createApp({ store = new SecretStore(), createLimiter, revealLimiter } = {}) {
  const limiterForCreate =
    createLimiter ?? new RateLimiter({ limit: 10, windowMs: 60_000 });
  const limiterForReveal =
    revealLimiter ?? new RateLimiter({ limit: 20, windowMs: 60_000 });

  return async function handler(req, res) {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const { pathname } = url;

    try {
      if (pathname === '/api/health' && req.method === 'GET') {
        return json(res, 200, { status: 'ok', live: store.size });
      }

      // ---- create ------------------------------------------------------
      if (pathname === '/api/secrets' && req.method === 'POST') {
        const limit = limiterForCreate.hit(clientIp(req));
        if (!limit.allowed) {
          return json(res, 429, { error: 'rate_limited' }, { 'Retry-After': String(limit.retryAfterSeconds) });
        }

        let body;
        try {
          body = JSON.parse(await readBody(req));
        } catch (err) {
          if (err?.code === 'too_large') return json(res, 413, { error: 'payload_too_large' });
          return json(res, 400, { error: 'invalid_json' });
        }

        const ciphertext = body?.ciphertext;
        if (typeof ciphertext !== 'string' || ciphertext.length === 0) {
          return json(res, 400, { error: 'missing_ciphertext' });
        }
        if (ciphertext.length > MAX_CIPHERTEXT_LENGTH) {
          return json(res, 413, { error: 'ciphertext_too_large' });
        }

        const ttlMs = body?.ttlMs === undefined ? DEFAULT_TTL_MS : Number(body.ttlMs);
        if (!ALLOWED_TTLS.has(ttlMs)) {
          return json(res, 400, { error: 'invalid_ttl', allowed: [...ALLOWED_TTLS] });
        }

        const passphrase = body?.passphrase;
        if (passphrase !== undefined && passphrase !== null) {
          if (typeof passphrase !== 'string' || passphrase.length < 8 || passphrase.length > 256) {
            return json(res, 400, { error: 'invalid_passphrase' });
          }
        }

        const { id, expiresAt } = store.put(ciphertext, { ttlMs, passphrase: passphrase || undefined });
        return json(res, 201, { id, expiresAt });
      }

      // ---- metadata ----------------------------------------------------
      const metaMatch = /^\/api\/secrets\/([A-Za-z0-9_-]{1,64})$/.exec(pathname);
      if (metaMatch && req.method === 'GET') {
        const meta = store.peek(metaMatch[1]);
        if (!meta) return json(res, 404, { error: 'not_found' });
        return json(res, 200, meta);
      }

      // ---- reveal ------------------------------------------------------
      // POST, not GET, on purpose. Link scanners, chat previews and browser
      // prefetchers all issue GETs; a one-time secret must not be burned by
      // something the recipient never even saw.
      const revealMatch = /^\/api\/secrets\/([A-Za-z0-9_-]{1,64})\/reveal$/.exec(pathname);
      if (revealMatch && req.method === 'POST') {
        const limit = limiterForReveal.hit(clientIp(req));
        if (!limit.allowed) {
          return json(res, 429, { error: 'rate_limited' }, { 'Retry-After': String(limit.retryAfterSeconds) });
        }

        let body = {};
        const raw = await readBody(req);
        if (raw.length > 0) {
          try {
            body = JSON.parse(raw);
          } catch {
            return json(res, 400, { error: 'invalid_json' });
          }
        }

        const result = store.consume(revealMatch[1], { passphrase: body?.passphrase });
        if (!result.ok) {
          const status = result.reason === 'bad_passphrase' ? 403 : 404;
          return json(res, status, { error: result.reason });
        }
        return json(res, 200, { ciphertext: result.ciphertext });
      }

      if (pathname.startsWith('/api/')) {
        return json(res, 404, { error: 'not_found' });
      }

      if (req.method !== 'GET' && req.method !== 'HEAD') {
        return json(res, 405, { error: 'method_not_allowed' }, { Allow: 'GET, HEAD' });
      }

      // Client-side route: /s/:id renders the reveal page.
      if (/^\/s\/[A-Za-z0-9_-]{1,64}$/.test(pathname)) {
        return serveStatic(res, '/');
      }

      return serveStatic(res, pathname);
    } catch (err) {
      if (err instanceof StoreError) {
        const status = err.code === 'store_full' ? 503 : 400;
        return json(res, status, { error: err.code });
      }
      // Never leak internals to the client.
      console.error('[cinder] unhandled', err);
      return json(res, 500, { error: 'internal_error' });
    }
  };
}

export function startServer({ port = Number(process.env.PORT ?? 3000), host = '0.0.0.0', ...options } = {}) {
  const store = options.store ?? new SecretStore();
  store.startSweeper();
  const server = createServer(createApp({ ...options, store }));
  return new Promise((resolve) => {
    server.listen(port, host, () => {
      const address = server.address();
      resolve({ server, store, port: typeof address === 'object' ? address.port : port });
    });
  });
}

// Only boot when executed directly, so importing this file in tests is free.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { port } = await startServer();
  console.log(`cinder listening on http://localhost:${port}`);
}
