# BIP32 Key Derivation — `derive()`

This module implements **BIP32 hierarchical deterministic key derivation**, allowing the creation of a full tree of private and public cryptographic keys from a single master key.

It supports both **hardened** and **non-hardened** derivations using elliptic curve cryptography (secp256k1), making it compatible with BIP44, BIP49, and BIP84 paths. The derivation process is secure, deterministic, and compliant with industry standards.

> 🔒 Hardened derivation requires access to private keys and is recommended for sensitive paths.  
> 🔑 Non-hardened derivation allows watch-only wallets using public keys.

---

## 🧪 Examples

### Derive BIP44 Account Keys
```js
import { fromSeed } from './fromSeed.js';
import derive from './derive.js';

const seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const [masterKeys, masterFormat] = fromSeed(seed, "main");

const [accountKeys, accountFormat] = derive("m/44'/0'/0'", masterKeys.HDpri, masterFormat);
const [changeKeys, changeFormat] = derive("m/0", accountKeys.HDpri, accountFormat);
const [addressKeys, addressFormat] = derive("m/0", changeKeys.HDpri, changeFormat);

console.log("Final address key:", addressKeys.HDpub);
```

### Derive Public Key Only (Non-Hardened)
```js
const [publicDerived, _] = derive("m/0/1/2", masterKeys.HDpub, masterFormat);
console.log("Public-derived key:", publicDerived.HDpub);
console.log("Private key:", publicDerived.HDpri); // null
```

### Handle Hardened Path Errors
```js
try {
  // Will fail due to hardened path with public key
  derive("m/0'", masterKeys.HDpub, masterFormat);
} catch (error) {
  console.log(error.message); // "Public Key can't derive from hardend path"
}
```

### Derive BIP49 P2SH-wrapped SegWit Path
```js
const [segwitKeys, segwitFormat] = derive("m/49'/0'/0'/0/0", masterKeys.HDpri, masterFormat);
console.log("Depth:", segwitFormat.depth);
console.log("Child index:", segwitFormat.childIndex);
console.log("Parent fingerprint:", segwitFormat.parentFingerPrint.toString('hex'));
```

### Derive First 10 Addresses (Iteratively)
```js
let currentKeys = masterKeys;
let currentFormat = masterFormat;
const pathSteps = ["44'", "0'", "0'", "0"];

for (const step of pathSteps) {
  [currentKeys, currentFormat] = derive(`m/${step}`, currentKeys.HDpri, currentFormat);
}

for (let i = 0; i < 10; i++) {
  const [addrKeys, _] = derive(`m/${i}`, currentKeys.HDpri, currentFormat);
  console.log(`Address ${i}:`, addrKeys.HDpub);
}
```

---

## 🧠 API Reference

### `derive(path, key, serialization_format)`
Derives a child key from a BIP32 path.

#### Parameters:
- `path` `{string}` – Derivation path (e.g. `"m/44'/0'/0'/0/0"`)
- `key` `{string}` – Extended key (`xprv`/`xpub`, `tprv`/`tpub`)
- `serialization_format` `{Object}` – Metadata from `fromSeed`

#### Returns:
- `[DerivedKeyPair, Object]`  
  - `HDpri`: Extended private key or `null`  
  - `HDpub`: Extended public key  
  - Updated serialization format for chaining

#### Throws:
- `Error`: If hardened path is used with public key  
- `Error`: If path or key format is invalid  
- `Error`: If derived key is invalid

#### Usage Notes:
- Supports both hardened and non-hardened derivation
- Public key derivation allowed only for non-hardened paths
- Output keys are BIP32 compliant
- Works with Bitcoin mainnet and testnet keys

---

## 📖 Specification Compliance

- [BIP32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP44: Multi-Account Hierarchy](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [BIP49 / BIP84: SegWit Compatible Paths](https://github.com/bitcoin/bips)

```diff
+ Fully compatible with all BIP32-compliant wallets and libraries.
```
