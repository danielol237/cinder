import test from 'node:test';
import assert from 'node:assert/strict';
import { SecretStore, StoreError, generateId, hashPassphrase, verifyPassphrase, DEFAULT_TTL_MS } from '../src/store.js';

test('put returns an id and expiry, and stores the ciphertext verbatim', () => {
  const now = 1_000_000;
  const store = new SecretStore({ now: () => now });
  const { id, expiresAt } = store.put('abc123');

  assert.equal(typeof id, 'string');
  assert.ok(id.length >= 20, 'id should carry real entropy');
  assert.equal(expiresAt, now + DEFAULT_TTL_MS);
  assert.equal(store.size, 1);
});

test('ids are unique across many writes', () => {
  const store = new SecretStore();
  const ids = new Set();
  for (let i = 0; i < 2000; i += 1) ids.add(store.put('x').id);
  assert.equal(ids.size, 2000);
});

test('generateId produces url-safe characters only', () => {
  for (let i = 0; i < 200; i += 1) {
    assert.match(generateId(), /^[A-Za-z0-9_-]+$/);
  }
});

test('consume returns the ciphertext once, then reports not_found', () => {
  const store = new SecretStore();
  const { id } = store.put('the-payload');

  assert.deepEqual(store.consume(id), { ok: true, ciphertext: 'the-payload' });
  assert.deepEqual(store.consume(id), { ok: false, reason: 'not_found' });
  assert.equal(store.size, 0);
});

test('consume on an unknown id is not_found, not an exception', () => {
  const store = new SecretStore();
  assert.deepEqual(store.consume('does-not-exist'), { ok: false, reason: 'not_found' });
});

test('expired secrets are reported as expired and are dropped', () => {
  let now = 0;
  const store = new SecretStore({ now: () => now });
  const { id } = store.put('gone', { ttlMs: 1000 });

  now = 1001;
  assert.deepEqual(store.consume(id), { ok: false, reason: 'expired' });
  assert.equal(store.size, 0);
});

test('a secret is readable up to the expiry instant, and dead at it', () => {
  let now = 0;
  const store = new SecretStore({ now: () => now });
  const { id } = store.put('edge', { ttlMs: 1000 });

  now = 999;
  assert.deepEqual(store.consume(id), { ok: true, ciphertext: 'edge' });

  now = 0;
  const second = store.put('edge-2', { ttlMs: 1000 }).id;
  now = 1000;
  assert.deepEqual(store.consume(second), { ok: false, reason: 'expired' });
});

test('peek exposes metadata without consuming the record', () => {
  const store = new SecretStore();
  const { id } = store.put('peekable');

  const meta = store.peek(id);
  assert.equal(meta.exists, true);
  assert.equal(meta.requiresPassphrase, false);
  assert.equal(store.size, 1);

  assert.equal(store.consume(id).ok, true);
  assert.equal(store.peek(id), null);
});

test('passphrase-protected secrets require the right passphrase', () => {
  const store = new SecretStore();
  const { id } = store.put('locked', { passphrase: 'correct horse battery' });

  assert.equal(store.peek(id).requiresPassphrase, true);
  assert.deepEqual(store.consume(id, { passphrase: 'wrong' }), { ok: false, reason: 'bad_passphrase' });
  assert.deepEqual(store.consume(id), { ok: false, reason: 'bad_passphrase' });
  assert.equal(store.size, 1, 'a failed attempt must not burn the record');
  assert.deepEqual(store.consume(id, { passphrase: 'correct horse battery' }), { ok: true, ciphertext: 'locked' });
});

test('passphrase hashes are salted: same input, different hashes', () => {
  const a = hashPassphrase('hunter2hunter2');
  const b = hashPassphrase('hunter2hunter2');
  assert.notEqual(a, b);
  assert.ok(a.startsWith('scrypt$'));
  assert.equal(verifyPassphrase('hunter2hunter2', a), true);
  assert.equal(verifyPassphrase('hunter2hunter2', b), true);
});

test('verifyPassphrase rejects malformed hashes instead of throwing', () => {
  for (const bad of ['', 'nope', 'scrypt$1$2$3', 'scrypt$a$b$c$d$e', null, undefined, 42]) {
    assert.equal(verifyPassphrase('anything', bad), false);
  }
});

test('verifyPassphrase handles unicode passphrases consistently', () => {
  const stored = hashPassphrase('café-ñandú-日本語');
  assert.equal(verifyPassphrase('café-ñandú-日本語', stored), true);
  // NFKC normalisation means the decomposed form matches too.
  assert.equal(verifyPassphrase('cafe\u0301-ñandú-日本語', stored), true);
});

test('put rejects empty, oversized, and non-string ciphertext', () => {
  const store = new SecretStore();
  assert.throws(() => store.put(''), StoreError);
  assert.throws(() => store.put(null), StoreError);
  assert.throws(() => store.put(123), StoreError);
  assert.throws(() => store.put('a'.repeat(200_000)), (err) => err.code === 'ciphertext_too_large');
});

test('put rejects a non-positive ttl', () => {
  const store = new SecretStore();
  assert.throws(() => store.put('x', { ttlMs: 0 }), (err) => err.code === 'invalid_ttl');
  assert.throws(() => store.put('x', { ttlMs: -5 }), (err) => err.code === 'invalid_ttl');
  assert.throws(() => store.put('x', { ttlMs: Number.NaN }), (err) => err.code === 'invalid_ttl');
});

test('sweep removes only expired records', () => {
  let now = 0;
  const store = new SecretStore({ now: () => now });
  store.put('short', { ttlMs: 100 });
  store.put('long', { ttlMs: 10_000 });

  now = 500;
  assert.equal(store.sweep(), 1);
  assert.equal(store.size, 1);
});

test('capacity limit rejects writes rather than growing without bound', () => {
  const store = new SecretStore({ maxRecords: 3 });
  store.put('a');
  store.put('b');
  store.put('c');
  assert.throws(() => store.put('d'), (err) => err.code === 'store_full');
});

test('capacity limit frees space when expired records are swept', () => {
  let now = 0;
  const store = new SecretStore({ now: () => now, maxRecords: 2 });
  store.put('a', { ttlMs: 10 });
  store.put('b', { ttlMs: 10 });

  now = 100;
  const { id } = store.put('c');
  assert.equal(store.size, 1);
  assert.deepEqual(store.consume(id), { ok: true, ciphertext: 'c' });
});
