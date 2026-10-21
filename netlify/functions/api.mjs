// Netlify Function port of the Cinder API.
//
// Same contract as src/server.js, but the record store is Netlify Blobs so it
// survives between invocations. The server still only ever holds ciphertext:
// nothing here can decrypt a secret, because the key never leaves the link.
//
// Endpoints (all reachable at /api/*):
//   POST /api/secrets
//   GET  /api/secrets/:id
//   POST /api/secrets/:id/reveal
//   GET  /api/health

import { getStore } from '@netlify/blobs';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_CIPHERTEXT_LENGTH = 128 * 1024;
const MAX_BODY_BYTES = 256 * 1024;
const ALLOWED_TTLS = new Set([5 * 60_000, 60 * 60_000, 24 * 60 * 60_000, 7 * 24 * 60 * 60_000]);

const SCRYPT_KEYLEN = 32;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

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

const store = () => getStore({ name: 'cinder-secrets', consistency: 'strong' });

/* ------------------------------------------------------------------ helpers */

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...SECURITY_HEADERS,
      'Content-Type': 'application/json; charset=utf-8',
      ...headers,
    },
  });
}

function generateId() {
  return randomBytes(18).toString('base64url');
}

function hashPassphrase(passphrase) {
  const salt = randomBytes(16);
  const derived = scryptSync(passphrase.normalize('NFKC'), salt, SCRYPT_KEYLEN, SCRYPT_PARAMS);
  return [
    'scrypt',
    SCRYPT_PARAMS.N,
    SCRYPT_PARAMS.r,
    SCRYPT_PARAMS.p,
    salt.toString('base64url'),
    derived.toString('base64url'),
  ].join('$');
}

function verifyPassphrase(passphrase, stored) {
  if (typeof passphrase !== 'string' || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const [, n, r, p, saltB64, hashB64] = parts;
  let salt;
  let expected;
  try {
    salt = Buffer.from(saltB64, 'base64url');
    expected = Buffer.from(hashB64, 'base64url');
  } catch {
    return false;
  }
  if (salt.length === 0 || expected.length !== SCRYPT_KEYLEN) return false;

  const actual = scryptSync(passphrase.normalize('NFKC'), salt, SCRYPT_KEYLEN, {
    N: Number(n),
    r: Number(r),
    p: Number(p),
  });
  return timingSafeEqual(actual, expected);
}

/**
 * Coarse rate limit.
 *
 * Netlify Blobs is not a counter, so this is best-effort: a short-lived marker
 * key per client per minute. It stops casual abuse without pretending to be a
 * precise limiter. Real protection is the CDN and the small blast radius of a
 * one-time secret.
 */
async function rateLimited(ip, bucket, limit) {
  const minute = Math.floor(Date.now() / 60_000);
  const key = `rl:${bucket}:${ip}:${minute}`;
  const s = store();
  const current = Number((await s.get(key)) ?? '0');
  if (current >= limit) return true;
  await s.set(key, String(current + 1));
  return false;
}

function clientIp(req) {
  return (
    req.headers.get('x-nf-client-connection-ip') ??
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    'unknown'
  );
}

async function readJson(req) {
  const text = await req.text();
  if (text.length > MAX_BODY_BYTES) return { error: 'payload_too_large' };
  if (text.length === 0) return { value: {} };
  try {
    return { value: JSON.parse(text) };
  } catch {
    return { error: 'invalid_json' };
  }
}

/* ------------------------------------------------------------------- routes */

async function createSecret(req) {
  const ip = clientIp(req);
  if (await rateLimited(ip, 'create', 10)) {
    return json(429, { error: 'rate_limited' }, { 'Retry-After': '60' });
  }

  const parsed = await readJson(req);
  if (parsed.error === 'payload_too_large') return json(413, { error: 'payload_too_large' });
  if (parsed.error) return json(400, { error: parsed.error });

  const { ciphertext, ttlMs, passphrase } = parsed.value ?? {};

  if (typeof ciphertext !== 'string' || ciphertext.length === 0) {
    return json(400, { error: 'missing_ciphertext' });
  }
  if (ciphertext.length > MAX_CIPHERTEXT_LENGTH) {
    return json(413, { error: 'ciphertext_too_large' });
  }

  const ttl = ttlMs === undefined ? DEFAULT_TTL_MS : Number(ttlMs);
  if (!ALLOWED_TTLS.has(ttl)) {
    return json(400, { error: 'invalid_ttl', allowed: [...ALLOWED_TTLS] });
  }

  if (passphrase !== undefined && passphrase !== null) {
    if (typeof passphrase !== 'string' || passphrase.length < 8 || passphrase.length > 256) {
      return json(400, { error: 'invalid_passphrase' });
    }
  }

  const id = generateId();
  const now = Date.now();
  await store().setJSON(id, {
    ciphertext,
    passphraseHash: passphrase ? hashPassphrase(passphrase) : null,
    createdAt: now,
    expiresAt: now + ttl,
  });

  return json(201, { id, expiresAt: now + ttl });
}

async function peekSecret(id) {
  const record = await store().get(id, { type: 'json' });
  if (!record) return json(404, { error: 'not_found' });
  if (record.expiresAt <= Date.now()) {
    await store().delete(id);
    return json(404, { error: 'not_found' });
  }
  return json(200, {
    exists: true,
    requiresPassphrase: record.passphraseHash !== null,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
  });
}

async function revealSecret(req, id) {
  const ip = clientIp(req);
  if (await rateLimited(ip, 'reveal', 20)) {
    return json(429, { error: 'rate_limited' }, { 'Retry-After': '60' });
  }

  const parsed = await readJson(req);
  if (parsed.error === 'payload_too_large') return json(413, { error: 'payload_too_large' });
  if (parsed.error) return json(400, { error: parsed.error });

  const s = store();
  const record = await s.get(id, { type: 'json' });
  if (!record) return json(404, { error: 'not_found' });

  if (record.expiresAt <= Date.now()) {
    await s.delete(id);
    return json(404, { error: 'expired' });
  }

  if (record.passphraseHash !== null) {
    if (!verifyPassphrase(parsed.value?.passphrase ?? '', record.passphraseHash)) {
      // A wrong guess must not destroy a secret the attacker cannot read.
      return json(403, { error: 'bad_passphrase' });
    }
  }

  await s.delete(id);
  return json(200, { ciphertext: record.ciphertext });
}

/* ------------------------------------------------------------------ handler */

export default async function handler(req) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, '') || '/';

  try {
    if (path === '/health' && req.method === 'GET') {
      return json(200, { status: 'ok', runtime: 'netlify' });
    }

    if (path === '/secrets' && req.method === 'POST') {
      return await createSecret(req);
    }

    const meta = /^\/secrets\/([A-Za-z0-9_-]{1,64})$/.exec(path);
    if (meta && req.method === 'GET') {
      return await peekSecret(meta[1]);
    }

    const reveal = /^\/secrets\/([A-Za-z0-9_-]{1,64})\/reveal$/.exec(path);
    if (reveal && req.method === 'POST') {
      return await revealSecret(req, reveal[1]);
    }

    return json(404, { error: 'not_found' });
  } catch (err) {
    console.error('[cinder] unhandled', err);
    return json(500, { error: 'internal_error' });
  }
}

export const config = {
  path: '/api/*',
};
