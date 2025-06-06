# Bech32 / Bech32m Address Encoding — `BECH32`

This module provides full support for encoding Bitcoin SegWit addresses using the [Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) (BIP173) and [Bech32m](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki) standards. It supports:

- ⚡ **P2WPKH address generation** (version 0 witness)
- 🔐 **Bech32m encoding** for v1+ witnesses
- 🧩 **Custom prefix encoding** for arbitrary data
- ✅ **Checksum validation** and HRP expansion

This is useful for applications involving native SegWit address creation, QR code generation, and testnet/mainnet compatibility.

---

## 🧪 Examples

### Convert a Legacy Address to SegWit P2WPKH
```js
const legacyAddr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
const segwitAddr = BECH32.to_P2WPKH(legacyAddr);
console.log(segwitAddr);
// "bc1qhkfq3zahaqkkzx5mjnamwjsfpw3tvke7v6aaph"
```

### Encode Custom Data with Bech32 Prefix
```js
const encoded = BECH32.data_to_bech32("hello", "48656c6c6f20576f726c64", "bech32");
console.log(encoded);
// "hello1dpjkcmr0vpmkxettv9xjqn50p2u"
```

### Encode Witness Program to Bech32
```js
const witnessProgram = new Uint8Array([0, ...Buffer.from('00112233445566778899aabbccddeeff00112233', 'hex')]);
const address = BECH32.encode("bc", witnessProgram, "bech32");
console.log(address);
// e.g. "bc1q..."
```

---

## 🧠 API Reference

### `BECH32.encode(prefix, data, encoding)`
Encodes a witness program or binary data into a Bech32 or Bech32m address.

- **Parameters:**
  - `prefix` `{string}` – Human Readable Part (e.g. `"bc"`, `"tb"`)
  - `data` `{Uint8Array|Buffer}` – Binary witness program (5-bit format)
  - `encoding` `{string}` – `'bech32'` (v0) or `'bech32m'` (v1+)
- **Returns:** `{string}` Bech32-encoded address

---

### `BECH32.polymod(values)`
Computes a polynomial checksum used by Bech32 encoding.

- **Parameters:** `values` `{Buffer|Uint8Array}`
- **Returns:** `{number}` 30-bit checksum value

---

### `BECH32.expandHRP(prefix)`
Expands the Human Readable Part into a format for checksum calculation.

- **Parameters:** `prefix` `{string}`
- **Returns:** `{Buffer}` Expanded prefix bytes

---

### `BECH32.to_P2WPKH(witness_program)`
Converts a Base58Check legacy address to a SegWit Bech32 address.

- **Parameters:** `witness_program` `{string}` – Legacy address
- **Returns:** `{string}` Bech32 P2WPKH address  
- **Throws:** Error if address is invalid

---

### `BECH32.data_to_bech32(prefix, hex, encoding)`
Encodes arbitrary hex data with a custom prefix and returns a Bech32-encoded string.

- **Parameters:**
  - `prefix` `{string}` – Custom HRP (e.g., `"hello"`)
  - `hex` `{string}` – Hex-encoded payload
  - `encoding` `{string}` – `'bech32'` or `'bech32m'`
- **Returns:** `{string}` Custom Bech32 address  
- **Throws:** Error if resulting address is longer than 90 characters

---

## ⚙️ Internals

This module leverages:
- `convertBits()` — for bit-width conversion (8-bit → 5-bit)
- `checksum_5bit()` — for checksum expansion to 5-bit format
- `base32_encode()` — for final string encoding

---

## 📖 BIP Standards

- [BIP173: Bech32 (v0)](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
- [BIP350: Bech32m (v1+)](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)

---

## 📌 Notes

- Bech32 addresses start with `"bc1..."` (mainnet) or `"tb1..."` (testnet)
- Bech32m is required for Taproot (v1) and future witness versions
- Max length for a valid Bech32 address is **90 characters**

```diff
+ Use this module to safely upgrade from legacy Base58 addresses to SegWit!
```
