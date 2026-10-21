/**
 * Sliding-window rate limiter, in memory.
 *
 * Kept deliberately small: one bucket per key, holding the timestamps of
 * recent hits. Stale buckets are evicted so the map cannot grow without
 * bound on a long-lived process.
 */
export class RateLimiter {
  #hits = new Map();
  #limit;
  #windowMs;
  #now;
  #maxKeys;

  constructor({ limit = 30, windowMs = 60_000, now = () => Date.now(), maxKeys = 50_000 } = {}) {
    this.#limit = limit;
    this.#windowMs = windowMs;
    this.#now = now;
    this.#maxKeys = maxKeys;
  }

  /**
   * Record a hit for `key`.
   * @returns {{ allowed: boolean, remaining: number, retryAfterSeconds: number }}
   */
  hit(key) {
    const now = this.#now();
    const cutoff = now - this.#windowMs;

    let timestamps = this.#hits.get(key);
    if (!timestamps) {
      if (this.#hits.size >= this.#maxKeys) this.#evict(cutoff);
      timestamps = [];
      this.#hits.set(key, timestamps);
    }

    // Drop anything outside the window.
    let drop = 0;
    while (drop < timestamps.length && timestamps[drop] <= cutoff) drop += 1;
    if (drop > 0) timestamps.splice(0, drop);

    if (timestamps.length >= this.#limit) {
      const oldest = timestamps[0];
      const retryAfterSeconds = Math.max(1, Math.ceil((oldest + this.#windowMs - now) / 1000));
      return { allowed: false, remaining: 0, retryAfterSeconds };
    }

    timestamps.push(now);
    return {
      allowed: true,
      remaining: this.#limit - timestamps.length,
      retryAfterSeconds: 0,
    };
  }

  #evict(cutoff) {
    for (const [key, timestamps] of this.#hits) {
      if (timestamps.length === 0 || timestamps[timestamps.length - 1] <= cutoff) {
        this.#hits.delete(key);
      }
    }
  }

  reset() {
    this.#hits.clear();
  }
}
