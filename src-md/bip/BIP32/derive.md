# BIP32 Key Derivation

Enhanced BIP32 hierarchical deterministic key derivation with critical security fixes and comprehensive validation.

## Description

This module implements BIP32 child key derivation with support for both hardened and non-hardened derivation paths. It includes critical fixes for key serialization, proper validation, and secure memory management throughout the derivation process. The implementation ensures proper 32-byte key serialization and prevents timing attacks.

## Example

```javascript
import { derive } from 'j-bitcoin';

// Derive child key from extended private key
const parentKey = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const derivationPath = "m/44'/0'/0'/0/0";

const childKey = derive(derivationPath, parentKey, {
    depth: 5,
    network: 'main'
});

console.log('Child Private Key:', childKey.privKey.key.toString('hex'));
console.log('Child Public Key:', childKey.pubKey.key.toString('hex'));

// Derive from public key (non-hardened only)
const parentPubKey = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const nonHardenedPath = "m/0/0";

const pubChildKey = derive(nonHardenedPath, parentPubKey, {
    depth: 2,
    network: 'main'
});

console.log('Child Public Key from Parent Public:', pubChildKey.pubKey.key.toString('hex'));
```

## API Reference

### Functions

#### `derive(path, key, serialization_format)`
Derives a child key from a parent extended key following BIP32 specification.

**Parameters:**
- `path` (string) - BIP32 derivation path (e.g., "m/44'/0'/0'/0/0")
- `key` (string) - Base58-encoded extended key (xprv/xpub or tprv/tpub)
- `serialization_format` (Object) - Serialization format configuration
  - `depth` (number) - Current depth in derivation tree
  - `network` (string) - Network type ('main' or 'test')

**Returns:**
- Object with derived key information:
  - `privKey` (Object|null) - Private key material (if deriving from private key)
    - `key` (Buffer) - 32-byte private key
    - `versionByteNum` (number) - Version byte for WIF encoding
  - `pubKey` (Object) - Public key material and elliptic curve point
    - `key` (Buffer) - 33-byte compressed public key
    - `points` (Object) - Elliptic curve point for operations
  - `chainCode` (Buffer) - 32-byte chain code for further derivation
  - `depth` (number) - Depth in derivation tree

**Throws:**
- `Error` - If derivation path format is invalid
- `Error` - If extended key format is incorrect
- `Error` - If attempting hardened derivation from public key
- `Error` - If child key is invalid (extremely rare)

### Path Format

#### Supported Path Formats
- `m/44'/0'/0'/0/0` - Full BIP44 path with hardened components
- `m/0/1/2` - Non-hardened derivation path
- `m/44'/0'` - Partial hardened path

#### Hardened vs Non-Hardened
- **Hardened** (`'` suffix): Requires private key, provides additional security
- **Non-Hardened**: Can derive from public key, allows extended public key functionality

### Security Features

- **Leading Zero Preservation** - Critical fix for 32-byte key serialization (~0.39% of keys affected)
- **Comprehensive Path Validation** - Validates derivation path format and indices
- **Secure Memory Management** - Clears intermediate values after use
- **Timing Attack Protection** - Constant-time operations where applicable
- **Edge Case Handling** - Proper handling of invalid child keys with retry logic
- **Input Validation** - Thorough validation of all input parameters

### Error Codes

- `INVALID_DERIVATION_PATH` - Path format is incorrect
- `INVALID_EXTENDED_KEY` - Extended key format is invalid
- `HARDENED_FROM_PUBLIC` - Cannot derive hardened path from public key
- `INVALID_CHILD_KEY` - Generated child key is invalid
- `DERIVATION_DEPTH_EXCEEDED` - Derivation depth too high
- `INDEX_OUT_OF_RANGE` - Index exceeds 32-bit range