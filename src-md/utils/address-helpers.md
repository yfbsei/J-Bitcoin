# Address Utilities — `address-helpers.js`

Collection of helper functions for encoding and validating traditional Base58Check addresses. Includes bit-conversion helpers used by the Bech32 module and network detection utilities.

Capabilities:

- 🔍 Decode legacy addresses and verify checksums
- 🔄 Convert 8‑bit groups to 5‑bit for Bech32 encoding
- 🛡️ Security helpers such as constant-time comparisons

---

## 🧪 Example

```js
import { decodeLegacyAddress } from './address-helpers.js';

const info = decodeLegacyAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
console.log(info.addressType); // 'P2PKH'
```

---

## 🧠 API Reference

### `decodeLegacyAddress(address)`
Returns `{ prefix, hash160Hex, addressType }`.

### `convertBitGroups(data, fromBits, toBits, pad?)`
Converts arrays between bit widths.

### `getNetworkFromAddress(address)`
Detects the Bitcoin network from a legacy address.

**Exports:** `AddressUtilError`, `AddressSecurityUtils`, `SECURITY_CONSTANTS`, `decodeLegacyAddress`, `convertBitGroups`, `convertChecksumTo5Bit`, `validateAndDecodeLegacyAddress`, `detectAddressFormat`, `normalizeAddress`, `compareAddresses`, `getNetworkFromAddress`, `isAddressForNetwork`, `getAddressUtilsStatus`, `validateImplementation`.

