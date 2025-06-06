# Bitcoin Key Decoding Module

## Overview

This module provides utility functions to **decode**:

- Wallet Import Format (WIF) private keys
- Legacy Base58Check Bitcoin addresses

These utilities are essential for retrieving the raw binary cryptographic key material used in Bitcoin wallet operations.

---

## Functions

### `privateKey_decode(wif: string): Uint8Array`

Decodes a WIF-encoded private key into a raw 32-byte private key.

**WIF Format Breakdown:**
- 1 byte: Network version (e.g., 0x80 for mainnet)
- 32 bytes: Private key
- 1 byte (optional): Compression flag (0x01)
- 4 bytes: Checksum

**Returns:**
- `Uint8Array(32)` raw private key bytes

**Example:**
```js
const privBytes = privateKey_decode("L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS");
console.log(Buffer.from(privBytes).toString('hex'));
// "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
```

---

### `legacyAddress_decode(address: string): Uint8Array`

Decodes a legacy Base58Check Bitcoin address to retrieve the 20-byte HASH160.

**Address Format:**
- 1 byte: Version byte (0x00, 0x05, 0x6f, 0xc4, etc.)
- 20 bytes: HASH160 of public key or script
- 4 bytes: Checksum

**Returns:**
- `Uint8Array(20)` HASH160 value

**Example:**
```js
const hash160 = legacyAddress_decode("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
console.log(Buffer.from(hash160).toString('hex'));
// "76a04053bda0a88bda5177b86a15c3b29f559873"
```

---

## Use Cases

- Extract private keys from WIF to sign transactions.
- Decode Bitcoin addresses to validate or convert them.
- Validate correspondence between address and public key.

---

## Dependencies

- `base58-js`: For Base58Check decoding
- Node.js `Buffer`

---

## License

MIT License © yfbsei
