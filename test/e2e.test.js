// End-to-end: the flow a real user goes through, with real crypto.
//
// This is the test that matters most. It proves the browser half and the server
// half agree: encrypt with the key, hand the server only the ciphertext, get it
// back once, decrypt with the key that travelled in the link fragment.

import './setup.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createApp } from '../src/server.js';
import { SecretStore } from '../src/store.js';
import { encryptSecret, decryptSecret, exportKey, generateKey, importKey } from '../public/crypto.js';

async function boot() {
  const store = new SecretStore();
  const server = createServer(createApp({ store }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  const post = async (path, body) => {
    const res = await fetch(base + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body ?? {}),
    });
    return { status: res.status, body: await res.json() };
  };

  return {
    base,
    post,
    store,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(resolve);
      }),
  };
}

/** Mirror of what the client does when it builds a link. */
async function shareSecret(app, plaintext, options = {}) {
  const key = await generateKey();
  const ciphertext = await encryptSecret(plaintext, key);
  const created = await app.post('/api/secrets', { ciphertext, ...options });
  assert.equal(created.status, 201, 'create should succeed');
  return {
    id: created.body.id,
    keyFragment: await exportKey(key),
    expiresAt: created.body.expiresAt,
  };
}

async function openLink(app, { id, keyFragment }, body) {
  const revealed = await app.post(`/api/secrets/${id}/reveal`, body);
  if (revealed.status !== 200) return revealed;
  const plaintext = await decryptSecret(revealed.body.ciphertext, await importKey(keyFragment));
  return { status: 200, plaintext };
}

test('full round trip: share, open once, then gone', async (t) => {
  const app = await boot();
  t.after(app.close);

  const secret = 'postgres://admin:s3cret@db.internal:5432/prod';
  const link = await shareSecret(app, secret);

  const opened = await openLink(app, link);
  assert.equal(opened.status, 200);
  assert.equal(opened.plaintext, secret);

  const second = await openLink(app, link);
  assert.equal(second.status, 404);
});

test('the store holds no plaintext and no key', async (t) => {
  const app = await boot();
  t.after(app.close);

  const link = await shareSecret(app, 'needle-in-here');

  // Serialise everything the process is holding for this secret.
  const internals = [];
  for (const value of Object.values(app.store)) internals.push(JSON.stringify(value));
  const everything = internals.join('');

  assert.equal(everything.includes('needle-in-here'), false, 'plaintext must not be in the store');
  assert.equal(everything.includes(link.keyFragment), false, 'the key must not be in the store');

  // And the public API leaks neither.
  const revealed = await app.post(`/api/secrets/${link.id}/reveal`, {});
  assert.deepEqual(Object.keys(revealed.body), ['ciphertext']);
});

test('passphrase protects the secret end to end', async (t) => {
  const app = await boot();
  t.after(app.close);

  const link = await shareSecret(app, 'double locked', { passphrase: 'second factor here' });

  const noPass = await openLink(app, link);
  assert.equal(noPass.status, 403);

  const wrongPass = await openLink(app, link, { passphrase: 'second factor herr' });
  assert.equal(wrongPass.status, 403);

  const right = await openLink(app, link, { passphrase: 'second factor here' });
  assert.equal(right.status, 200);
  assert.equal(right.plaintext, 'double locked');
});

test('a link with the wrong key cannot decrypt the ciphertext', async (t) => {
  const app = await boot();
  t.after(app.close);

  const link = await shareSecret(app, 'mine');
  const otherKey = await exportKey(await generateKey());

  const revealed = await app.post(`/api/secrets/${link.id}/reveal`, {});
  assert.equal(revealed.status, 200);

  await assert.rejects(async () => {
    await decryptSecret(revealed.body.ciphertext, await importKey(otherKey));
  }, 'a wrong key must not silently produce garbage');
});

test('two secrets are independent: reading one does not touch the other', async (t) => {
  const app = await boot();
  t.after(app.close);

  const a = await shareSecret(app, 'alpha');
  const b = await shareSecret(app, 'beta');

  assert.equal((await openLink(app, a)).plaintext, 'alpha');
  assert.equal((await openLink(app, b)).plaintext, 'beta');
  assert.equal((await openLink(app, a)).status, 404);
  assert.equal((await openLink(app, b)).status, 404);
});

test('a large secret survives the whole pipeline', async (t) => {
  const app = await boot();
  t.after(app.close);

  const secret = 'BEGIN KEY\n' + 'A'.repeat(60_000) + '\nEND KEY';
  const link = await shareSecret(app, secret);

  const opened = await openLink(app, link);
  assert.equal(opened.status, 200);
  assert.equal(opened.plaintext, secret);
});

test('unicode secrets survive the whole pipeline', async (t) => {
  const app = await boot();
  t.after(app.close);

  const secret = 'пароль: 密码 🔐 mật-khẩu';
  const link = await shareSecret(app, secret);
  assert.equal((await openLink(app, link)).plaintext, secret);
});
