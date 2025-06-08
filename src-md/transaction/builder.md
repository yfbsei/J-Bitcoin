# Transaction Builder — `builder.js`

Creates immutable Bitcoin transactions using a PSBT-first workflow. Supports legacy, SegWit and Taproot inputs with automatic fee estimation and change output generation.

Features:

- 🧱 Add inputs/outputs while keeping previous versions immutable
- 🏷️ Generate PSBT data for external signing
- 🔄 RBF fee bumping helpers

---

## 🧪 Example

```js
import { TransactionBuilder } from './builder.js';

const txb = new TransactionBuilder('main');
txb.addInput(prevTxId, 0);
txb.addOutput(address, 10000);
const psbt = txb.export();
```

---

## 🧠 API Reference

### `new TransactionBuilder(network)`
Constructs a builder for `network` (`'main'` or `'test'`).

### `addInput(txid, vout, sequence?)`
Appends an input to the transaction.

### `addOutput(address, value)`
Appends an output in satoshis.

### `export()`
Returns the underlying PSBT object.

**Exports:** `TransactionBuilderError`, `TransactionSecurityUtils`, `TransactionBuilder`, `TRANSACTION_CONSTANTS`.

