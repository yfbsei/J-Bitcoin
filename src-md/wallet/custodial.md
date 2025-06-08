# Custodial Wallet — `custodial.js`

Provides a traditional single-user HD wallet built on BIP32/BIP39. Keys are stored locally and standard ECDSA signatures are used for spending. The module integrates with the transaction builder and UTXO manager.

Key features:

- 🔐 Deterministic key derivation from a master seed
- 💼 Simple signing and verification helpers
- 🛡️ Optional passphrase encryption and secure memory wiping

---

## 🧪 Example

```js
import Custodial_Wallet from './custodial.js';

const [keys, fmt] = generateMasterKey(seedHex, 'main');
const wallet = new Custodial_Wallet('main', keys, fmt);
console.log(wallet.address);
```

---

## 🧠 API Reference

### `new Custodial_Wallet(network, masterKeys, format)`
Creates a wallet instance using master keys from `master-key.js`.

### `sign(message)`
Returns an ECDSA signature for the provided message.

### `verify(signature, message)`
Verifies a signature using the wallet's public key.

### `getSummary()`
Returns network, address and derivation information.

**Exports:** default class `Custodial_Wallet`.
