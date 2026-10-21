import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

/** Default lifetime for a stored secret: 24 hours. */
export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

/** Hard ceiling on a single ciphertext payload (base64url characters). */
export const MAX_CIPHERTEXT_LENGTH = 128 * 1024;

/** Hard ceiling on total live records, so a flood cannot exhaust memory. */
export const MAX_RECORDS = 10_000;

const ID_BYTES = 18;
const SCRYPT_KEYLEN = 32;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

/**
 * Generate an unguessable record id. 18 bytes of CSPRNG output gives
 * 144 bits of entropy, encoded as 24 URL-safe characters.
 */
export function generateId() {
  return randomBytes(ID_BYTES).toString('base64url');
}

/**
 * Hash an access passphrase. scrypt is deliberately slow, which is what
 * makes an offline guess against a stolen store expensive.
 *
 * Returns a self-describing string: scrypt$N$r$p$salt$hash
 */
export function hashPassphrase(passphrase, salt = randomBytes(16)) {
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

/**
 * Verify a passphrase against a stored hash in constant time.
 * Any malformed hash is treated as a non-match rather than throwing.
 */
export function verifyPassphrase(passphrase, stored) {
  if (typeof passphrase !== 'string' || typeof stored !== 'string') return false;

  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const [, n, r, p, saltB64, hashB64] = parts;
  let expected;
  let salt;
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

export class StoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'StoreError';
    this.code = code;
  }
}

/**
 * In-memory store for opaque ciphertext blobs.
 *
 * The store never sees plaintext and never sees a decryption key: it holds
 * an encrypted blob, an optional passphrase hash, and an expiry timestamp.
 * That is the whole point — a full dump of this process gains nothing.
 *
 * Reads are single-use and atomic. Node runs this on one thread, so the
 * check-then-delete below cannot interleave with another request.
 */
export class SecretStore {
  #records = new Map();
  #now;
  #maxRecords;
  #sweeper = null;

  constructor({ now = () => Date.now(), maxRecords = MAX_RECORDS } = {}) {
    this.#now = now;
    this.#maxRecords = maxRecords;
  }

  get size() {
    return this.#records.size;
  }

  /**
   * Store a ciphertext blob.
   * @param {string} ciphertext base64url-encoded ciphertext
   * @param {object} [options]
   * @param {number} [options.ttlMs] lifetime in milliseconds
   * @param {string} [options.passphrase] optional access passphrase
   * @returns {{ id: string, expiresAt: number }}
   */
  put(ciphertext, { ttlMs = DEFAULT_TTL_MS, passphrase } = {}) {
    if (typeof ciphertext !== 'string' || ciphertext.length === 0) {
      throw new StoreError('invalid_ciphertext', 'ciphertext must be a non-empty string');
    }
    if (ciphertext.length > MAX_CIPHERTEXT_LENGTH) {
      throw new StoreError('ciphertext_too_large', 'ciphertext exceeds the size limit');
    }
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new StoreError('invalid_ttl', 'ttlMs must be a positive number');
    }
    if (this.#records.size >= this.#maxRecords) {
      this.sweep();
      if (this.#records.size >= this.#maxRecords) {
        throw new StoreError('store_full', 'store is at capacity');
      }
    }

    const id = generateId();
    const now = this.#now();
    this.#records.set(id, {
      ciphertext,
      passphraseHash: passphrase ? hashPassphrase(passphrase) : null,
      createdAt: now,
      expiresAt: now + ttlMs,
    });

    return { id, expiresAt: now + ttlMs };
  }

  /** Metadata only. Does not consume the record. */
  peek(id) {
    const record = this.#records.get(id);
    if (!record) return null;
    if (record.expiresAt <= this.#now()) {
      this.#records.delete(id);
      return null;
    }
    return {
      exists: true,
      requiresPassphrase: record.passphraseHash !== null,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
    };
  }

  /**
   * Read and destroy a secret.
   *
   * Returns `{ ok: true, ciphertext }` on success, or `{ ok: false, reason }`
   * where reason is 'not_found' | 'expired' | 'bad_passphrase'.
   *
   * A wrong passphrase does NOT burn the record — otherwise anyone who guessed
   * the id could destroy a secret they cannot read.
   */
  consume(id, { passphrase } = {}) {
    const record = this.#records.get(id);
    if (!record) return { ok: false, reason: 'not_found' };

    if (record.expiresAt <= this.#now()) {
      this.#records.delete(id);
      return { ok: false, reason: 'expired' };
    }

    if (record.passphraseHash !== null) {
      if (!verifyPassphrase(passphrase ?? '', record.passphraseHash)) {
        return { ok: false, reason: 'bad_passphrase' };
      }
    }

    this.#records.delete(id);
    return { ok: true, ciphertext: record.ciphertext };
  }

  /** Remove expired records. Returns how many were dropped. */
  sweep() {
    const now = this.#now();
    let removed = 0;
    for (const [id, record] of this.#records) {
      if (record.expiresAt <= now) {
        this.#records.delete(id);
        removed += 1;
      }
    }
    return removed;
  }

  /**
   * Start a background sweeper so expired records free memory even when
   * nobody is reading them. Unref'd so it never holds the process open.
   */
  startSweeper(intervalMs = 60_000) {
    if (this.#sweeper) return;
    this.#sweeper = setInterval(() => this.sweep(), intervalMs);
    this.#sweeper.unref?.();
  }

  stopSweeper() {
    if (this.#sweeper) clearInterval(this.#sweeper);
    this.#sweeper = null;
  }

  clear() {
    this.#records.clear();
  }
}
