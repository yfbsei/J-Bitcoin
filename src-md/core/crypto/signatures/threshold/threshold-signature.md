# Threshold Signature Scheme — `threshold-signature.js`

Implements a flexible threshold ECDSA scheme inspired by the Nakasendo whitepaper. It uses Shamir's secret sharing and polynomial commitments to allow distributed signing without revealing private keys.

Main characteristics:

- ➗ Splits a master secret across multiple participants
- 🔐 Nonce manager to prevent reuse and enforce canonical signatures
- 📜 Polynomial utilities for verifiable secret sharing

---

## 🧪 Example

```js
import ThresholdSignature from './threshold-signature.js';

const tss = new ThresholdSignature(3, 2); // 2 of 3 scheme
const shares = tss.generateShares();
const sig = tss.sign(shares.slice(0, 2), msgHash);
const ok = tss.verify(sig, msgHash);
```

---

## 🧠 API Reference

### `new ThresholdSignature(groupSize, threshold)`
Creates a new scheme instance.

### `generateShares()`
Returns hex shares for each participant.

### `sign(shares, msgHash)`
Produces a deterministic ECDSA signature from a subset of shares.

### `verify(signature, msgHash)`
Validates a threshold signature.

**Exports:** default class `ThresholdSignature`.

