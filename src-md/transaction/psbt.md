# Partially Signed Bitcoin Transactions — `psbt.js`

Simplified PSBT processor implementing the essentials of [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki). The class manages PSBT fields, signing, and finalization with optional Taproot extensions.

Key features:

- ✍️ Append or combine PSBT inputs/outputs
- 🔑 Sign with ECDSA or Schnorr modules
- 🔗 Export final transactions for broadcast

---

## 🧪 Example

```js
import { EnhancedPSBT } from './psbt.js';

const psbt = new EnhancedPSBT('main');
psbt.addInput({...});
psbt.addOutput({...});
const finalTx = psbt.finalize();
```

---

## 🧠 API Reference

### `new EnhancedPSBT(network)`
Creates an empty PSBT for the given network.

### `addInput(input)` / `addOutput(output)`
Modifies the PSBT with new data.

### `combine(otherPsbt)`
Merges data from another PSBT instance.

### `finalize()`
Produces a complete transaction ready to broadcast.

**Exports:** `PSBTError`, `PSBTSecurityUtils`, `PSBT_CONSTANTS`, `EnhancedPSBT`.

