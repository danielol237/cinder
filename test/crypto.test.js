import './setup.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKey,
  exportKey,
  importKey,
  encryptSecret,
  decryptSecret,
  toB64url,
  fromB64url,
  KEY_BYTES,
} from '../public/crypto.js';

test('base64url round-trips arbitrary bytes', () => {
  for (const length of [0, 1, 2, 3, 15, 16, 17, 255, 1024]) {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i += 1) bytes[i] = (i * 37 + 11) % 256;
    const encoded = toB64url(bytes);
    assert.match(encoded, /^[A-Za-z0-9_-]*$/);
    assert.deepEqual(fromB64url(encoded), bytes);
  }
});

test('fromB64url rejects non-base64url input', () => {
  assert.throws(() => fromB64url('not valid!'));
  assert.throws(() => fromB64url(null));
  assert.throws(() => fromB64url('a+b/c='));
});

test('encrypt then decrypt returns the original plaintext', async () => {
  const key = await generateKey();
  const secret = '[REDACTED_TOKEN]';

  const blob = await encryptSecret(secret, key);
  assert.match(blob, /^[A-Za-z0-9_-]+$/);
  assert.equal(await decryptSecret(blob, key), secret);
});

test('plaintext never appears in the ciphertext blob', async () => {
  const key = await generateKey();
  const secret = 'correct-horse-battery-staple';
  const blob = await encryptSecret(secret, key);
  const decoded = new TextDecoder('utf-8', { fatal: false }).decode(fromB64url(blob));
  assert.equal(decoded.includes(secret), false);
});

test('the same plaintext encrypts differently every time', async () => {
  const key = await generateKey();
  const a = await encryptSecret('repeat me', key);
  const b = await encryptSecret('repeat me', key);
  assert.notEqual(a, b, 'a reused IV would make these identical');
});

test('decrypting with the wrong key fails loudly', async () => {
  const key = await generateKey();
  const other = await generateKey();
  const blob = await encryptSecret('private', key);
  await assert.rejects(() => decryptSecret(blob, other));
});

test('tampering with the ciphertext is detected', async () => {
  const key = await generateKey();
  const blob = await encryptSecret('do not touch', key);

  const bytes = fromB64url(blob);
  // Flip one bit in the last byte of ciphertext (past the 12-byte IV).
  bytes[bytes.length - 1] ^= 0x01;
  await assert.rejects(() => decryptSecret(toB64url(bytes), key));
});

test('tampering with the IV is detected', async () => {
  const key = await generateKey();
  const blob = await encryptSecret('do not touch', key);

  const bytes = fromB64url(blob);
  bytes[0] ^= 0xff;
  await assert.rejects(() => decryptSecret(toB64url(bytes), key));
});

test('a truncated payload is rejected', async () => {
  const key = await generateKey();
  await assert.rejects(() => decryptSecret(toB64url(new Uint8Array(8)), key));
  await assert.rejects(() => decryptSecret('', key));
});

test('exported keys are 32 bytes and import back to a working key', async () => {
  const key = await generateKey();
  const exported = await exportKey(key);

  assert.equal(fromB64url(exported).length, KEY_BYTES);
  assert.match(exported, /^[A-Za-z0-9_-]{43}$/);

  const imported = await importKey(exported);
  const blob = await encryptSecret('round trip', key);
  assert.equal(await decryptSecret(blob, imported), 'round trip');
});

test('importKey rejects keys of the wrong length', async () => {
  await assert.rejects(() => importKey(toB64url(new Uint8Array(16))));
  await assert.rejects(() => importKey('not-a-key'));
});

test('unicode and large payloads survive the round trip', async () => {
  const key = await generateKey();

  const unicode = 'пароль-🔐-密码-ñañá';
  assert.equal(await decryptSecret(await encryptSecret(unicode, key), key), unicode);

  const large = 'A'.repeat(100_000);
  assert.equal(await decryptSecret(await encryptSecret(large, key), key), large);
});

test('empty string is a valid plaintext', async () => {
  const key = await generateKey();
  assert.equal(await decryptSecret(await encryptSecret('', key), key), '');
});
