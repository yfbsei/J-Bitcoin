# BIP39 Mnemonic Generator & Seed Derivation — `BIP39`

This module implements the [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) standard for generating **mnemonic phrases** and converting them into cryptographic **seeds**. It supports secure 12-word phrase generation, checksum validation, and PBKDF2-HMAC-SHA512-based seed derivation with optional passphrases.

> 🔐 Designed for deterministic Bitcoin wallets  
> ✅ Compatible with BIP32 / BIP44 key derivation  
> 💬 English wordlist included

---

## 🧪 Examples

### Generate Random Mnemonic and Seed
```js
const { mnemonic, seed } = BIP39.random('my-secure-passphrase');
console.log(mnemonic); // e.g. "abandon ability able about ..."
console.log(seed);     // Hex string (64 bytes / 512 bits)
```

### Validate a Mnemonic Phrase
```js
const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const isValid = BIP39.checkSum(mnemonic); // true
```

### Convert Mnemonic to Seed
```js
const seed = BIP39.seed(mnemonic, "passphrase");
console.log(seed); // Hex string
```

### Strict Seed Conversion With Validation
```js
try {
  const secureSeed = BIP39.mnemonic2seed(mnemonic, "passphrase");
} catch (error) {
  console.error(error.message); // "Invalid checksum: Mnemonic phrase validation failed"
}
```

---

## 🧠 API Reference

### `BIP39.random(passphrase = '')`
Generates a valid 12-word mnemonic and its derived seed.

- **Returns:** `{ mnemonic: string, seed: string }`
- **Throws:** Error if checksum fails (extremely rare)

---

### `BIP39.mnemonic()`
Generates a 12-word mnemonic phrase with a valid checksum.

- **Returns:** `{string}` 12-word phrase

---

### `BIP39.seed(mnemonic, passphrase)`
Converts a mnemonic to a cryptographic seed (no checksum check).

- **Returns:** `{string}` Hex-encoded 512-bit seed  
- **Params:**  
  - `mnemonic` `{string}`  
  - `passphrase` `{string}` (optional)

---

### `BIP39.mnemonic2seed(mnemonic, passphrase)`
Strict version of `.seed()` — validates checksum before derivation.

- **Returns:** `{string}` Hex-encoded 512-bit seed  
- **Throws:** Error if checksum is invalid

---

### `BIP39.checkSum(mnemonic)`
Validates the checksum of a mnemonic phrase.

- **Returns:** `{boolean}` true if valid, false otherwise

---

## 🔐 Security Notes

- Entropy is 128-bit (16 bytes) — matches standard wallets
- Derived seed is 64 bytes, suitable for BIP32 master key generation
- Mnemonics should be stored securely and backed up
- Passphrases are optional but recommended for added security
- Never transmit mnemonics or seeds over insecure channels

---

## 📖 Standards Compliance

- ✅ BIP39: Mnemonic → Seed  
- ✅ Interoperable with Ledger, Trezor, Electrum, MetaMask, etc.  
- ✅ Works with BIP32/BIP44 for HD wallet generation

```diff
+ Use with `fromSeed()` and `derive()` to build full HD key hierarchies.
```
