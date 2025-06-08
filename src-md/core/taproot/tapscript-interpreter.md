# Tapscript Interpreter — `tapscript-interpreter.js`

Implements a minimal interpreter for the [BIP342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki) Tapscript rules. It handles modified opcodes, signature budgets and success paths used in Taproot script validation.

Highlights:

- 🧮 Executes Tapscript with configurable resource limits
- 🔑 Integrates Schnorr signature verification
- 🛡️ `TapscriptError` for detailed failures

---

## 🧪 Example

```js
import { TapscriptInterpreter } from './tapscript-interpreter.js';

const ctx = new TapscriptInterpreter();
ctx.execute(witnessStack, script, controlBlock);
```

---

## 🧠 API Reference

### `new TapscriptInterpreter(options?)`
Creates an interpreter instance with optional limits.

### `execute(stack, script, controlBlock)`
Runs the script against a witness stack and control block.

### `getStatus()`
Returns internal metrics such as consumed budget.

**Exports:** `TapscriptError`, `TapscriptSecurityUtils`, `TapscriptExecutionContext`, `TapscriptInterpreter`, `TAPSCRIPT_CONSTANTS`, `OPCODES`.

