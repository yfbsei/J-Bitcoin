# Validation Utilities — `validation.js`

Contains a set of reusable validation helpers for addresses, keys and BIP39 mnemonics. Functions use constant‑time comparisons and rate limiting to avoid timing attacks.

Highlights:

- ✔️ Validate WIF keys and address formats
- 📏 Check derivation paths and threshold parameters
- 🧰 Secure random helpers for test vectors

---

## 🧪 Example

```js
import { validatePrivateKey, validateAddress } from './validation.js';

assertValid(validatePrivateKey('K...'));
assertValid(validateAddress('bc1q...'));
```

---

## 🧠 API Reference

### `validatePrivateKey(wif)`
Returns `{ ok, error }` after checking Base58 checksum.

### `validateAddress(addr)`
Detects network and verifies checksum.

### `validateMnemonic(words)`
Validates BIP39 mnemonic phrases.

### `assertValid(result)`
Throws `ValidationError` if `result.ok` is false.

**Exports:** `ValidationError`, `ValidationSecurityUtils`, `SECURITY_CONSTANTS`, `validateNetwork`, `validateHexString`, `validatePrivateKey`, `validateWIFPrivateKey`, `validateDerivationPath`, `validateThresholdParams`, `validateMnemonic`, `validateAddress`, `validateBufferLength`, `validateNumberRange`, `assertValid`, `getValidationStatus`.

