// Test bootstrap.
//
// Node 18 does not expose `globalThis.crypto` by default (it became a global
// in 19). The crypto module under test is written for the browser, so instead
// of importing node:crypto inside it we inject the same WebCrypto surface here.
// This keeps the module the tests exercise byte-for-byte identical to the one
// that ships to browsers.
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true,
    writable: true,
  });
}
