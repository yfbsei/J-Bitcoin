# Taproot Control Block — `control-block.js`

Implements BIP341 control block parsing and validation. A control block proves inclusion of a script path inside a Taproot tree and specifies the internal key and parity used to tweak the output key.

Highlights:

- 📄 Extracts leaf version, internal key and merkle path
- ✔️ Verifies merkle inclusion using `TaprootMerkleTree`
- 🔐 `ControlBlockError` for structured errors

---

## 🧪 Example

```js
import { TaprootControlBlock } from './control-block.js';

const cb = new TaprootControlBlock(buffer);
console.log(cb.leafVersion, cb.merklePath.length);
```

---

## 🧠 API Reference

### `new TaprootControlBlock(buffer)`
Parses a serialized control block.

### `verify(targetHash)`
Checks that the merkle path commits to `targetHash`.

### `getInfo()`
Returns an object describing version, parity and internal key.

**Exports:** `ControlBlockError`, `ControlBlockSecurityUtils`, `TaprootControlBlock`, `CONTROL_BLOCK_CONSTANTS`.

