# Schnorr Signatures (BIP340) — `schnorr_sig`

This module implements [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) compliant **Schnorr signatures** using the `secp256k1` curve for Bitcoin. It offers improved efficiency and privacy over traditional ECDSA signatures.

Key advantages over ECDSA:

- 📉 **Smaller signature size** (64 bytes fixed)
- ➕ **Key and signature aggregation** (multi-sig ready)
- 🧮 **Linear arithmetic** for better multisig protocols
- 🔒 **Non-malleable** by design
- ⚡ **Faster batch verification**

---

## 🧪 Usage Examples

### Sign a Message
```js
const privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
const signature = schnorr_sig.sign(privateKey, "Hello Schnorr!");
```

### Verify a Signature
```js
const publicKey = schnorr_sig.retrieve_public_key(privateKey);
const isValid = schnorr_sig.verify(signature, "Hello Schnorr!", publicKey);
console.log(isValid); // true
```

### Use Custom Auxiliary Randomness
```js
const aux = new Uint8Array(32).fill(0xab);
const signature = schnorr_sig.sign(privateKey, "Hello Schnorr!", aux);
```

---

## 🔍 API Reference

### `schnorr_sig.sign(private_key, message, auxRand?)`
Signs a UTF-8 message using the private key and optional auxiliary randomness.

- **Parameters:**
  - `private_key` `{string}` – WIF-encoded private key
  - `message` `{string}` – Message to sign
  - `auxRand` `{Uint8Array}` – *(Optional)* 32-byte auxiliary randomness
- **Returns:** `{Uint8Array}` 64-byte Schnorr signature (R.x || s)
- **Throws:** If signing fails or key is invalid

---

### `schnorr_sig.verify(signature, message, public_key)`
Verifies a Schnorr signature against a message and public key.

- **Parameters:**
  - `signature` `{Uint8Array}` – 64-byte BIP340 signature
  - `message` `{string}` – Original message
  - `public_key` `{Uint8Array}` – 32-byte x-only public key
- **Returns:** `{boolean}` `true` if valid, `false` otherwise

---

### `schnorr_sig.retrieve_public_key(private_key)`
Derives a 32-byte x-only public key from a WIF private key.

- **Parameters:**
  - `private_key` `{string}` – WIF-encoded private key
- **Returns:** `{Uint8Array}` 32-byte x-only public key
- **Throws:** If the private key is invalid

---

## 🧠 Behind the Scenes

- Implements full BIP340 flow including even-Y enforcement
- Uses auxiliary randomness to defend against nonce leakage attacks
- Outputs deterministic or randomized signatures depending on aux input
- Compliant with Taproot and future soft forks using Schnorr signatures

---

## 📌 Notes

- Schnorr uses **x-only public keys** (32 bytes)
- Auxiliary randomness (`auxRand`) adds protection against side-channel attacks
- Suitable for modern Bitcoin applications like Taproot, MuSig, and batch signing

```diff
+ Use Schnorr signatures to upgrade your wallet and smart contracts to Bitcoin’s latest cryptographic standards.
```
