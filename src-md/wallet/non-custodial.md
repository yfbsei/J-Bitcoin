# Threshold Wallet — `non-custodial.js`

Implements a multi-party threshold wallet where signing keys are never held in a single location. Built on top of the threshold signature scheme and Taproot utilities.

Highlights:

- 👥 Distributed key generation and signing
- 🔑 Shares can be combined to reconstruct the private key when needed
- 🛡️ Rate limiting and secure memory cleanup

---

## 🧪 Example

```js
import Non_Custodial_Wallet from './non-custodial.js';

const wallet = new Non_Custodial_Wallet('main', 3, 2); // 2-of-3
console.log(wallet.address);
```

---

## 🧠 API Reference

### `new Non_Custodial_Wallet(network, groupSize, threshold)`
Creates a wallet instance with the given parameters.

### `sign(message)`
Returns a threshold signature using available shares.

### `verify(signature, message)`
Verifies a threshold signature.

### `getSummary()`
Returns an object describing network and participant information.

**Exports:** default class `Non_Custodial_Wallet`.

