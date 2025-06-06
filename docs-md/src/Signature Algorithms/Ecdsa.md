# ECDSA Signing & Verification — `ECDSA`

This module provides full support for [ECDSA](https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm) (Elliptic Curve Digital Signature Algorithm) operations using the **secp256k1** curve (used by Bitcoin). It includes:

- 🔐 **Secure signing** with deterministic k-values (RFC 6979)
- ✅ **Signature verification** with public key
- 🔄 **Public key recovery** using signature + message

---

## 🧪 Examples

### Sign a Message
```js
const privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
const [signature, recoveryId] = ECDSA.sign(privateKey, "Hello Bitcoin!");
```

### Verify a Signature
```js
const isValid = ECDSA.verify(signature, "Hello Bitcoin!", publicKey);
console.log(isValid); // true
```

### Recover Public Key from Signature
```js
const pubKey = ECDSA.retrieve_public_key("Hello Bitcoin!", signature, recoveryId);
```

---

## 🧠 API Reference

### `ECDSA.sign(private_key, message)`
Signs a UTF-8 string message using a WIF-encoded private key.

- **Parameters:**
  - `private_key` `{string}` – WIF format private key (e.g. starts with "L", "K", or "5")
  - `message` `{string}` – Message to sign
- **Returns:** `[signature: Uint8Array, recoveryId: number]`
- **Throws:** Error if signing fails

---

### `ECDSA.verify(signature, message, public_key)`
Verifies a signature against a message and public key.

- **Parameters:**
  - `signature` `{Uint8Array}` – DER-encoded signature
  - `message` `{string}` – Message that was signed
  - `public_key` `{Uint8Array}` – Compressed or uncompressed public key
- **Returns:** `{boolean}` true if valid, false otherwise

---

### `ECDSA.retrieve_public_key(message, signature, recovery)`
Recovers the public key used to create a signature, given the original message and the recovery ID.

- **Parameters:**
  - `message` `{string}` – Message that was signed
  - `signature` `{Uint8Array}` – Signature from `.sign()`
  - `recovery` `{number}` – Recovery ID from `.sign()` (0–3)
- **Returns:** `{Uint8Array}` Compressed public key (33 bytes)

---

## 🔐 Security Notes

- Uses `secp256k1` curve as per Bitcoin standard
- Deterministic signatures prevent nonce-based vulnerabilities
- Private keys must be securely stored and never exposed

---

## 📌 Notes

- Public key recovery is useful in protocols like Ethereum or verifying messages without transmitting public keys
- This module can integrate with your BIP32/BIP39 flow to provide a complete signing stack

```diff
+ Use this module to securely sign and verify messages on Bitcoin-compatible systems.
```
