# UTXO Manager — `utxo-manager.js`

Handles coin selection and fee estimation for wallets. Implements multiple selection strategies (largest-first, accumulative) and interfaces with the transaction builder for RBF fee bumps.

Key aspects:

- 🎯 Choose UTXOs by value, age or privacy scoring
- 🔗 Query mempool APIs for fee suggestions
- 🔄 Consolidation and RBF helper methods

---

## 🧪 Example

```js
import { UTXOManager } from './utxo-manager.js';

const mgr = new UTXOManager(utxos);
const { inputs, change } = await mgr.selectForAmount(50000);
```

---

## 🧠 API Reference

### `new UTXOManager(utxoList)`
Creates a manager with an initial set of UTXOs.

### `selectForAmount(value, strategy?)`
Returns `{inputs, change}` sufficient to fund `value`.

### `estimateFeeRate()`
Fetches current fee recommendations.

**Exports:** `UTXOManagerError`, `UTXOSecurityUtils`, `UTXOSelectionStrategies`, `FeeEstimationService`, `UTXOManager`, `UTXO_CONSTANTS`.

