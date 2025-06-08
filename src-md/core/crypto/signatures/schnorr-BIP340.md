# Schnorr Signatures (BIP340) — `schnorr-BIP340.js`

Implements [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) Schnorr signatures for the `secp256k1` curve and includes Taproot-oriented utilities. The module exposes helpers for signing, verification and key recovery with hardened input validation.

Highlights:

- 📏 Fixed 64‑byte signature format
- 🔑 Support for x-only public keys
- 🔒 Built‑in `SchnorrError` and `SchnorrValidator` classes

---

## 🧪 Examples

### Sign and Verify
```js
import Schnorr from './schnorr-BIP340.js';

const sig = await Schnorr.sign('K...', 'message');
const ok = await Schnorr.verify(sig, 'message', publicKey);
```

### Get Public Key From WIF
```js
const pub = await Schnorr.retrieve_public_key('K...');
```

---

## 🧠 API Reference

### `Schnorr.sign(privateKey, message, auxRand?)`
Returns a 64‑byte signature. `privateKey` may be WIF or raw.

### `Schnorr.verify(signature, message, publicKey)`
Checks a signature against a message and x-only public key.

### `Schnorr.retrieve_public_key(privateKey)`
Derives the x-only public key from a private key.

**Exports:** `SchnorrError`, `SchnorrValidator`, `EnhancedSchnorr` (as `Enhanced`), constants, and default object `Schnorr`.

