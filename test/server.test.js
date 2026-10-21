import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createApp } from '../src/server.js';
import { SecretStore } from '../src/store.js';

/** Boot the app on an ephemeral port and return a small fetch helper. */
async function boot(options = {}) {
  const store = options.store ?? new SecretStore();
  const server = createServer(createApp({ ...options, store }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  const call = async (path, init = {}) => {
    const response = await fetch(base + path, {
      headers: { 'Content-Type': 'application/json' },
      ...init,
    });
    const text = await response.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    return { status: response.status, headers: response.headers, body };
  };

  return {
    base,
    call,
    store,
    close: () =>
      new Promise((resolve) => {
        // fetch keeps sockets alive; without this, close() waits on them and
        // every test file pays a multi-second teardown tax.
        server.closeAllConnections?.();
        server.close(resolve);
      }),
  };
}

test('health endpoint reports liveness and record count', async (t) => {
  const app = await boot();
  t.after(app.close);

  const res = await app.call('/api/health');
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { status: 'ok', live: 0 });
});

test('create then reveal returns the ciphertext exactly once', async (t) => {
  const app = await boot();
  t.after(app.close);

  const created = await app.call('/api/secrets', {
    method: 'POST',
    body: JSON.stringify({ ciphertext: 'opaque-blob' }),
  });
  assert.equal(created.status, 201);
  assert.equal(typeof created.body.id, 'string');
  assert.ok(created.body.expiresAt > Date.now());

  const revealed = await app.call(`/api/secrets/${created.body.id}/reveal`, {
    method: 'POST',
    body: '{}',
  });
  assert.equal(revealed.status, 200);
  assert.equal(revealed.body.ciphertext, 'opaque-blob');

  const again = await app.call(`/api/secrets/${created.body.id}/reveal`, {
    method: 'POST',
    body: '{}',
  });
  assert.equal(again.status, 404);
  assert.equal(again.body.error, 'not_found');
});

test('GET on a reveal path does not consume the secret', async (t) => {
  const app = await boot();
  t.after(app.close);

  const created = await app.call('/api/secrets', {
    method: 'POST',
    body: JSON.stringify({ ciphertext: 'preview-safe' }),
  });

  // A link preview bot issuing GET must not burn the record.
  const preview = await app.call(`/api/secrets/${created.body.id}/reveal`);
  assert.equal(preview.status, 404);

  const real = await app.call(`/api/secrets/${created.body.id}/reveal`, {
    method: 'POST',
    body: '{}',
  });
  assert.equal(real.status, 200);
  assert.equal(real.body.ciphertext, 'preview-safe');
});

test('metadata is readable without consuming', async (t) => {
  const app = await boot();
  t.after(app.close);

  const created = await app.call('/api/secrets', {
    method: 'POST',
    body: JSON.stringify({ ciphertext: 'meta', passphrase: 'longenough' }),
  });

  const meta = await app.call(`/api/secrets/${created.body.id}`);
  assert.equal(meta.status, 200);
  assert.equal(meta.body.exists, true);
  assert.equal(meta.body.requiresPassphrase, true);

  const stillThere = await app.call(`/api/secrets/${created.body.id}`);
  assert.equal(stillThere.status, 200);
});

test('passphrase-protected secrets need the passphrase to reveal', async (t) => {
  const app = await boot();
  t.after(app.close);

  const created = await app.call('/api/secrets', {
    method: 'POST',
    body: JSON.stringify({ ciphertext: 'guarded', passphrase: 'open sesame please' }),
  });

  const wrong = await app.call(`/api/secrets/${created.body.id}/reveal`, {
    method: 'POST',
    body: JSON.stringify({ passphrase: 'nope nope nope' }),
  });
  assert.equal(wrong.status, 403);
  assert.equal(wrong.body.error, 'bad_passphrase');

  const missing = await app.call(`/api/secrets/${created.body.id}/reveal`, {
    method: 'POST',
    body: '{}',
  });
  assert.equal(missing.status, 403);

  const right = await app.call(`/api/secrets/${created.body.id}/reveal`, {
    method: 'POST',
    body: JSON.stringify({ passphrase: 'open sesame please' }),
  });
  assert.equal(right.status, 200);
  assert.equal(right.body.ciphertext, 'guarded');
});

test('create rejects a missing or non-string ciphertext', async (t) => {
  const app = await boot();
  t.after(app.close);

  for (const payload of [{}, { ciphertext: '' }, { ciphertext: 42 }, { ciphertext: null }]) {
    const res = await app.call('/api/secrets', { method: 'POST', body: JSON.stringify(payload) });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'missing_ciphertext');
  }
});

test('create rejects malformed json', async (t) => {
  const app = await boot();
  t.after(app.close);

  const res = await app.call('/api/secrets', { method: 'POST', body: '{not json' });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_json');
});

test('create rejects ttls that are not on the allowlist', async (t) => {
  const app = await boot();
  t.after(app.close);

  for (const ttlMs of [1, 60_000, 999_999_999, 'soon']) {
    const res = await app.call('/api/secrets', {
      method: 'POST',
      body: JSON.stringify({ ciphertext: 'x', ttlMs }),
    });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'invalid_ttl');
  }
});

test('create rejects a too-short passphrase', async (t) => {
  const app = await boot();
  t.after(app.close);

  const res = await app.call('/api/secrets', {
    method: 'POST',
    body: JSON.stringify({ ciphertext: 'x', passphrase: 'short' }),
  });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_passphrase');
});

test('oversized bodies are refused', async (t) => {
  const app = await boot();
  t.after(app.close);

  const res = await app.call('/api/secrets', {
    method: 'POST',
    body: JSON.stringify({ ciphertext: 'a'.repeat(300_000) }),
  });
  assert.equal(res.status, 413);
});

test('create is rate limited', async (t) => {
  const app = await boot();
  t.after(app.close);

  let last;
  for (let i = 0; i < 12; i += 1) {
    last = await app.call('/api/secrets', {
      method: 'POST',
      body: JSON.stringify({ ciphertext: `blob-${i}` }),
    });
  }
  assert.equal(last.status, 429);
  assert.equal(last.body.error, 'rate_limited');
  assert.ok(Number(last.headers.get('retry-after')) >= 1);
});

test('reveal is rate limited independently of create', async (t) => {
  const app = await boot();
  t.after(app.close);

  let last;
  for (let i = 0; i < 22; i += 1) {
    last = await app.call('/api/secrets/nonexistentid/reveal', { method: 'POST', body: '{}' });
  }
  assert.equal(last.status, 429);

  // Create should still work: separate buckets.
  const created = await app.call('/api/secrets', {
    method: 'POST',
    body: JSON.stringify({ ciphertext: 'still fine' }),
  });
  assert.equal(created.status, 201);
});

test('unknown api routes 404 as json', async (t) => {
  const app = await boot();
  t.after(app.close);

  const res = await app.call('/api/nope');
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'not_found');
});

test('security headers are present on api responses', async (t) => {
  const app = await boot();
  t.after(app.close);

  const res = await app.call('/api/health');
  const csp = res.headers.get('content-security-policy');
  assert.ok(csp.includes("default-src 'self'"));
  assert.ok(csp.includes("frame-ancestors 'none'"));
  assert.ok(csp.includes("object-src 'none'"));
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(res.headers.get('cache-control'), 'no-store');
});

test('the index page is served with a locked-down CSP', async (t) => {
  const app = await boot();
  t.after(app.close);

  const res = await fetch(`${app.base}/`);
  const html = await res.text();

  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /text\/html/);
  assert.ok(html.includes('Cinder'));
  // No inline script: the CSP forbids it, so a page that ships one is broken.
  assert.equal(/<script(?![^>]*\bsrc=)/.test(html), false);
});

test('client-side reveal routes serve the app shell', async (t) => {
  const app = await boot();
  t.after(app.close);

  const res = await fetch(`${app.base}/s/abcdefghijklmnop`);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /<!DOCTYPE html>/i);
});

test('path traversal is refused', async (t) => {
  const app = await boot();
  t.after(app.close);

  for (const path of ['/../package.json', '/..%2fpackage.json', '/%2e%2e/package.json']) {
    const res = await fetch(app.base + path);
    assert.ok([403, 404].includes(res.status), `${path} returned ${res.status}`);
    const text = await res.text();
    assert.equal(text.includes('"dependencies"'), false);
  }
});

test('non-GET on the app shell is refused', async (t) => {
  const app = await boot();
  t.after(app.close);

  const res = await app.call('/', { method: 'DELETE' });
  assert.equal(res.status, 405);
});

test('expired secrets disappear from the api', async (t) => {
  let now = Date.now();
  const store = new SecretStore({ now: () => now });
  const app = await boot({ store });
  t.after(app.close);

  const created = await app.call('/api/secrets', {
    method: 'POST',
    body: JSON.stringify({ ciphertext: 'short-lived', ttlMs: 300_000 }),
  });
  assert.equal(created.status, 201);

  now += 300_001;

  const meta = await app.call(`/api/secrets/${created.body.id}`);
  assert.equal(meta.status, 404);

  const reveal = await app.call(`/api/secrets/${created.body.id}/reveal`, { method: 'POST', body: '{}' });
  assert.equal(reveal.status, 404);
});

test('the server never stores a key or a plaintext', async (t) => {
  const app = await boot();
  t.after(app.close);

  const created = await app.call('/api/secrets', {
    method: 'POST',
    body: JSON.stringify({ ciphertext: 'only-ciphertext-here' }),
  });

  const reveal = await app.call(`/api/secrets/${created.body.id}/reveal`, { method: 'POST', body: '{}' });
  assert.deepEqual(Object.keys(reveal.body), ['ciphertext']);
});
