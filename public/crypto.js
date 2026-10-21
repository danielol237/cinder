// Shared crypto primitives for Cinder.
//
// Deliberately framework-free and dependency-free: this module runs unchanged
// in the browser and under Node's test runner, so the code the tests exercise
// is literally the code users run.

const IV_BYTES = 12;
export const KEY_BYTES = 32;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** WebCrypto, wherever we are. Node exposes it as globalThis.crypto in 19+; in 18 it is on the crypto module. */
export function subtle() {
  const webcrypto = globalThis.crypto;
  if (!webcrypto?.subtle) throw new Error('WebCrypto unavailable in this runtime');
  return webcrypto;
}

export function randomBytes(length) {
  return subtle().getRandomValues(new Uint8Array(length));
}

export function toB64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64url(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new Error('invalid base64url');
  }
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** A fresh AES-256-GCM key. Extractable, because it has to travel in the link. */
export async function generateKey() {
  return subtle().subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function exportKey(key) {
  return toB64url(new Uint8Array(await subtle().subtle.exportKey('raw', key)));
}

export async function importKey(encoded) {
  const raw = fromB64url(encoded);
  if (raw.length !== KEY_BYTES) throw new Error('invalid key length');
  return subtle().subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}

/**
 * Encrypt plaintext and pack it as base64url(iv || ciphertext).
 *
 * A fresh random IV per message is mandatory for GCM: reusing one under the
 * same key breaks confidentiality outright.
 */
export async function encryptSecret(plaintext, key) {
  if (typeof plaintext !== 'string') throw new TypeError('plaintext must be a string');
  const iv = randomBytes(IV_BYTES);
  const ciphertext = new Uint8Array(
    await subtle().subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(plaintext)),
  );
  const combined = new Uint8Array(iv.length + ciphertext.length);
  combined.set(iv, 0);
  combined.set(ciphertext, iv.length);
  return toB64url(combined);
}

/** Reverse of encryptSecret. Throws if the key is wrong or the blob was altered. */
export async function decryptSecret(blob, key) {
  const combined = fromB64url(blob);
  if (combined.length <= IV_BYTES) throw new Error('payload too short');
  const plaintext = await subtle().subtle.decrypt(
    { name: 'AES-GCM', iv: combined.subarray(0, IV_BYTES) },
    key,
    combined.subarray(IV_BYTES),
  );
  return decoder.decode(plaintext);
}
