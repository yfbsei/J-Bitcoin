# Bitcoin Address Utility Module

## Overview

This module provides utility functions for handling Bitcoin addresses, including:

- **Base58Check address decoding**
- **Bit-width conversion** for Bech32/Base32 compatibility
- **Checksum formatting** for Base32 encoding

These functions are typically used in the construction and parsing of both legacy and SegWit (Bech32) Bitcoin addresses.

---

## Functions

### `decode_legacy_address(legacy_addr: string): [string, string]`

Decodes a Base58Check Bitcoin address and extracts network info and HASH160.

**Parameters:**
- `legacy_addr` (string): Legacy P2PKH Bitcoin address

**Returns:**
- `[network_prefix, hash160]` as an array

**Example:**
```js
const [prefix, hash] = decode_legacy_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
// prefix = "bc", hash = "76a04053bda0a88bda5177b86a15c3b29f559873"
```

---

### `convertBits(data: Uint8Array, from: number, to: number): Uint8Array`

Converts a buffer of data from one bit width to another (e.g. 8 → 5 or 5 → 8). This is essential for encoding addresses in Bech32 format.

**Parameters:**
- `data` (Uint8Array): Input data
- `from` (number): Original bit size (usually 8)
- `to` (number): Desired bit size (e.g., 5)

**Returns:**
- Converted `Uint8Array` with new bit-width

**Example:**
```js
const fiveBit = convertBits(new Uint8Array([0xFF, 0x80, 0x00]), 8, 5);
// [31, 30, 0, 0, 0]
```

---

### `checksum_5bit(checksum: number): Uint8Array`

Encodes a numeric checksum into 8 × 5-bit format (for Bech32).

**Parameters:**
- `checksum` (number): Typically 10-digit checksum from Bech32

**Returns:**
- `Uint8Array` of 8 values, each a 5-bit segment

**Example:**
```js
const arr = checksum_5bit(0x1234567890);
// Uint8Array [16, 18, 6, 22, 15, 4, 18, 0]
```

---

## Dependencies

- `base58-js`: Used for Base58Check decoding.
- Standard Node.js `Buffer` API

---

## License

MIT License © yfbsei
