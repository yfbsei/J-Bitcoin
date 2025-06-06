
# Threshold Signature Scheme (TSS) for Distributed Cryptography

This project provides a full-featured JavaScript implementation of a **Threshold Signature Scheme (TSS)** using Shamir's Secret Sharing and elliptic curve cryptography over `secp256k1`.

## 📜 Description

The `ThresholdSignature` class enables:
- Distributed key generation (JVRSS)
- Secret sharing and recovery using polynomials
- Threshold ECDSA signing without reconstructing the private key
- Additive and multiplicative operations on shared secrets
- Inverse sharing (used in ECDSA signatures)

It is useful for applications such as:
- Multi-signature wallets
- Escrow systems
- Decentralized authorization
- Distributed key custody

> ⚠️ This code is meant for educational purposes and prototyping. Not audited for production use.

## 🧪 Example Usage

### Basic Signature

```js
import ThresholdSignature from './ThresholdSignature.js';

const tss = new ThresholdSignature(3, 2);

const signature = tss.sign("Send 5 BTC to Alice");

const verified = ThresholdSignature.verify_threshold_signature(
  tss.public_key,
  signature.msgHash,
  signature.sig
);

console.log("Signature valid:", verified); // true
```

---


## 📚 API Reference

### Constructor

```js
new ThresholdSignature(groupSize = 3, threshold = 2)
```

Creates a new threshold signing scheme with `groupSize` participants and `threshold` required to sign.

---

### `sign(message: string): ThresholdSignatureResult`

Generates a threshold ECDSA signature for the given message.

### `privite_key(shares?: BN[]): BN`

Reconstructs the private key (only if necessary). Avoid in live environments.

### `shares_to_points(shares: BN[]): [number, BN][]`

Converts share array into Lagrange interpolation format.

### `addss(a_shares: BN[], b_shares: BN[]): BN`

Adds two secrets via share-wise addition.

### `pross(a_shares: BN[], b_shares: BN[]): BN`

Securely multiplies two secrets (requires 2t+1 shares).

### `invss(a_shares: BN[]): BN[]`

Computes modular inverse of a shared secret.

### `verify_threshold_signature(pubkey, msgHash, sig): boolean`

Verifies a signature generated with this scheme.

---


### Corporate 3-of-5 Signing

```js
const corporate = new ThresholdSignature(5, 3);

// 5 executive shares
const executives = corporate.shares;

// Any 3 can sign
const sig = corporate.sign("Quarterly payout");

const isValid = ThresholdSignature.verify_threshold_signature(
  corporate.public_key,
  sig.msgHash,
  sig.sig
);
console.log("Verified:", isValid);
```

---

### Emergency Private Key Recovery

```js
const backup = new ThresholdSignature(3, 2);

// Only if threshold is met
const privKey = backup.privite_key();
console.log("Reconstructed private key:", privKey.toString('hex'));
```

---

## 🔐 Security Notice

- Never reconstruct the private key unless necessary.
- Use threshold signature operations to maintain decentralization.
- Do not reuse nonce shares.

---

## 📖 References

- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [Threshold Cryptography](https://en.wikipedia.org/wiki/Threshold_cryptosystem)
- [Fast Multiparty Threshold ECDSA](https://eprint.iacr.org/2019/114.pdf)
- [noble-curves](https://github.com/paulmillr/noble-curves)

---

## 🧑‍💻 Author

**yfbsei**  
MIT License · Educational Use Only
