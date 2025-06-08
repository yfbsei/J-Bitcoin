# BIP32 Master Key Generation — `master-key.js`

Generates the root extended keys for a hierarchical deterministic wallet. The implementation follows [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) with additional validation to reject weak keys and securely wipe intermediate buffers.

Key features:

- ✅ Validates seed size and network parameters
- 🔒 Rejects invalid master keys (IL ≥ n or zero)
- ♻️ Optional retry logic via `generateMasterKeySecure`
- 🧪 Built‑in test vector validation

---

## 🧪 Examples

### Generate Master Keys from Seed
```js
import { generateMasterKey } from './master-key.js';

const seed = '000102030405060708090a0b0c0d0e0f';
const [keys, fmt] = generateMasterKey(seed, 'main');
console.log(keys.extendedPrivateKey);
```

### Secure Generation with Automatic Retry
```js
import { generateMasterKeySecure } from './master-key.js';
const [keys] = generateMasterKeySecure(seed, 'test');
```

---

## 🧠 API Reference

### `generateMasterKey(seedHex, network = 'main')`
Returns `[HDKeys, format]` where `HDKeys` contains `extendedPrivateKey` and `extendedPublicKey`.

### `generateMasterKeySecure(seedHex, network = 'main')`
Wraps `generateMasterKey` with additional validation and retry logic.

### `validateMasterKeyGeneration()`
Runs an internal test using the official BIP32 vector.

### `BIP32SecurityUtils`
Helper class providing seed and extended key validators.

**Exports:** `BIP32SecurityUtils`, `ENHANCED_BIP32_CONSTANTS`, `generateMasterKey`, `generateMasterKeySecure`, `validateMasterKeyGeneration`.

