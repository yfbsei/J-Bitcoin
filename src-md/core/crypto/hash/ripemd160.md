# RIPEMD160 Hash — `ripemd160.js`

Provides a pure JavaScript implementation of the RIPEMD160 hash algorithm. The function is used in Bitcoin address creation as part of the HASH160 operation (`sha256` followed by `ripemd160`).

Key features:

- 🔐 No external dependencies
- 🏎️ Reasonable performance for browser or Node use
- 📦 Returns raw `Buffer` output

---

## 🧪 Example

```js
import rmd160 from './ripemd160.js';
const digest = rmd160(Buffer.from('hello'));
console.log(digest.toString('hex'));
```

---

## 🧠 API Reference

### `rmd160(data)`
Computes RIPEMD160 over `Buffer`, `Uint8Array`, or string input.

- **Parameters:** `data` `{Buffer|Uint8Array|string}`
- **Returns:** `{Buffer}` 20‑byte hash

**Exports:** default function `rmd160`.

