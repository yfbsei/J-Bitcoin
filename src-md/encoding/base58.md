
# Base58Check Encoding for Bitcoin

This module implements **Base58Check encoding**, a checksummed base58 encoding format used extensively in Bitcoin for addresses, private keys (WIF), and extended keys (xpub/xprv). It ensures human-readable output with built-in error detection via a double SHA256 checksum.

## 📜 Description

- Encodes binary data using Bitcoin's Base58 alphabet
- Appends 4-byte checksum (double SHA256) before encoding
- Ensures high error detection (1 in 4.3 billion chance of undetected corruption)

---

## 🧪 Examples

### Encode WIF Private Key

```js
const privateKeyBytes = Buffer.concat([
  Buffer.from([0x80]),
  Buffer.from('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35', 'hex'),
  Buffer.from([0x01])
]);
console.log(b58encode(privateKeyBytes));
// → "L5HgWvFghocq1FmxSjKNaGhVN8f67p6xYg5pY7M8FE77HXwHtGGu"
```

### Encode Bitcoin Address

```js
const hash160 = Buffer.from('76a04053bda0a88bda5177b86a15c3b29f559873', 'hex');
const addressBytes = Buffer.concat([
  Buffer.from([0x00]),  // Mainnet prefix
  hash160
]);
console.log(b58encode(addressBytes));
// → "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
```

### Extended Key (xpub)

```js
const extendedKeyData = Buffer.concat([
  Buffer.from([0x04, 0x88, 0xb2, 0x1e]),
  Buffer.from([0x00]),
  Buffer.alloc(4, 0),
  Buffer.alloc(4, 0),
  Buffer.from('873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508', 'hex'),
  Buffer.from('0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2', 'hex')
]);
console.log(b58encode(extendedKeyData));
// → "xpub661MyMwAqRbcFtXgS5sYJABqqG9..."
```
---

## 📚 API Reference

### `b58encode(buffer: Buffer): string`

Encodes a binary buffer to a Base58Check string.

#### Parameters
- `buffer` *(Buffer)*: Binary data to encode

#### Returns
- *(string)*: Base58Check-encoded string

#### Throws
- If input is not a `Buffer`
- If Base58 encoding fails (rare)

---

## 🔐 Security

- Uses **double SHA256 checksum** to detect transmission errors
- Common single-character mistakes are always detected
- **Not encryption** — only integrity protection
- Always validate checksum during decoding

---

## 📖 References

- [Bitcoin Wiki - Base58Check](https://en.bitcoin.it/wiki/Base58Check_encoding)
- [RFC 4648 - Base Encodings](https://tools.ietf.org/html/rfc4648)

---

## 🧑‍💻 Author

**yfbsei**  
Version: 1.0.0  
MIT License
