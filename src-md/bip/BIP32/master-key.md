# BIP32 Master Key Generation

Enhanced BIP32 master key generation implementation with critical security fixes for hierarchical deterministic wallet creation.

## Description

This module provides secure master key generation following BIP32 specifications. It includes comprehensive validation to ensure generated keys are cryptographically valid, implements retry logic for invalid keys, and provides secure memory management for sensitive operations. The implementation includes critical fixes for invalid master key detection and cross-implementation compatibility.

## Example

```javascript
import { generateMasterKey } from 'j-bitcoin';

// Generate master key from seed
const seedHex = "000102030405060708090a0b0c0d0e0f";
const network = 'main';

const masterKey = generateMasterKey(seedHex, network);

console.log('Extended Private Key:', masterKey.extendedPrivateKey);
console.log('Extended Public Key:', masterKey.extendedPublicKey);
console.log('Chain Code:', masterKey.chainCode.toString('hex'));

// Example with testnet
const testnetKey = generateMasterKey(seedHex, 'test');
console.log('Testnet Extended Private Key:', testnetKey.extendedPrivateKey);
```

## API Reference

### Functions

#### `generateMasterKey(seedHex, network)`
Generates a BIP32 master key from a seed with comprehensive validation.

**Parameters:**
- `seedHex` (string) - Hexadecimal seed string (16-64 bytes)
- `network` (string) - Network type ('main' or 'test')

**Returns:**
- Object with master key information:
  - `extendedPrivateKey` (string) - Base58-encoded extended private key (xprv/tprv)
  - `extendedPublicKey` (string) - Base58-encoded extended public key (xpub/tpub)
  - `chainCode` (Buffer) - 32-byte chain code for derivation
  - `privateKey` (Object) - Private key material and metadata
    - `keyMaterial` (Buffer) - 32-byte private key
    - `wifVersionByte` (number) - WIF version byte for network
  - `publicKey` (Object) - Public key material and point
    - `keyMaterial` (Buffer) - 33-byte compressed public key
    - `point` (Object) - Elliptic curve point for operations

**Throws:**
- `Error` - If seed is invalid format or length
- `Error` - If master key generation fails after retry limit
- `Error` - If generated key doesn't meet BIP32 requirements (IL = 0 or IL >= curve order)

### Security Features

- **Invalid Key Detection** - Validates master keys according to BIP32 (IL ≠ 0 and IL < curve order)
- **Retry Logic** - Automatically retries generation for invalid keys (extremely rare ~1 in 2^127)
- **Secure Memory Management** - Clears sensitive data after use with multi-pass clearing
- **Cross-Implementation Compatibility** - Validates against Bitcoin Core test vectors
- **Enhanced Seed Validation** - Comprehensive input validation and boundary checks
- **Weak Key Detection** - Identifies and rejects obviously weak keys

### Error Codes

- `INVALID_SEED_FORMAT` - Seed is not valid hexadecimal
- `INVALID_SEED_LENGTH` - Seed length outside 16-64 byte range
- `INVALID_NETWORK` - Network parameter is not 'main' or 'test'
- `MASTER_KEY_GENERATION_FAILED` - Failed to generate valid key after retry limit
- `WEAK_KEY_DETECTED` - Generated key failed security validation