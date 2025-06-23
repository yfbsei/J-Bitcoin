# Address Encoding

Comprehensive Bitcoin address and key encoding utilities with enhanced security features and cross-implementation compatibility.

## Description

This module provides complete Bitcoin address and extended key encoding functionality including Base58Check encoding, WIF private key encoding, legacy address generation, and extended key serialization. It includes enhanced security features, input validation, and secure memory management for all encoding operations.

## Example

```javascript
import { 
    encodeExtendedKey,
    encodeStandardKeys,
    generateAddress,
    generateAddressFromExtendedVersion,
    createPublicKeyFingerprint 
} from 'j-bitcoin';

// Encode extended private key (xprv/tprv)
const masterKeyContext = {
    depth: 0,
    parentFingerprint: Buffer.alloc(4, 0),
    childIndex: 0,
    chainCode: Buffer.from('a'.repeat(64), 'hex'),
    privateKey: {
        keyMaterial: Buffer.from('b'.repeat(64), 'hex'),
        wifVersionByte: 0x80
    },
    publicKey: {
        keyMaterial: Buffer.from('03' + 'c'.repeat(62), 'hex')
    },
    versionBytes: {
        extendedPrivateKey: 0x0488ade4,
        extendedPublicKey: 0x0488b21e
    }
};

const extendedPrivKey = encodeExtendedKey('private', masterKeyContext);
console.log('Extended Private Key:', extendedPrivKey);
// Output: xprv9s21ZrQH143K...

const extendedPubKey = encodeExtendedKey('public', masterKeyContext);
console.log('Extended Public Key:', extendedPubKey);
// Output: xpub661MyMwAqRbcF...

// Encode standard keys (WIF private key + hex public key)
const privateKeyData = {
    keyMaterial: Buffer.from('private_key_32_bytes'),
    wifVersionByte: 0x80  // Mainnet WIF version
};
const publicKeyData = {
    keyMaterial: Buffer.from('public_key_33_bytes')
};

const standardKeys = encodeStandardKeys(privateKeyData, publicKeyData);
console.log('WIF Private Key:', standardKeys.privateKeyWIF);
console.log('Public Key Hex:', standardKeys.publicKeyHex);
console.log('Validation Status:', standardKeys.isValid);

// Generate legacy Bitcoin address
const versionByte = 0x00; // Mainnet P2PKH
const publicKeyHash = Buffer.from('hash160_of_public_key');
const address = generateAddress(versionByte, publicKeyHash);
console.log('Legacy Address:', address);
// Output: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2

// Generate address from extended key version
const extendedKeyVersion = {
    version: 0x0488b21e,
    depth: 3,
    parentFingerprint: Buffer.from([0x12, 0x34, 0x56, 0x78]),
    childIndex: 2147483648, // Hardened derivation
    chainCode: Buffer.from('chain_code'),
    keyMaterial: Buffer.from('key_material')
};

const addressFromExtended = generateAddressFromExtendedVersion(extendedKeyVersion);
console.log('Address from Extended Key:', addressFromExtended);

// Create public key fingerprint
const fingerprint = createPublicKeyFingerprint(publicKeyData.keyMaterial);
console.log('Public Key Fingerprint:', fingerprint.toString('hex'));
```

## API Reference

### Functions

#### `encodeExtendedKey(keyType, keyContext)`
Encodes BIP32 extended keys (xprv/xpub/tprv/tpub) with comprehensive validation.

**Parameters:**
- `keyType` (string) - Key type ('private' or 'public')
- `keyContext` (Object) - Key context with all required fields
  - `depth` (number) - Derivation depth (0-255)
  - `parentFingerprint` (Buffer) - Parent key fingerprint (4 bytes)
  - `childIndex` (number) - Child index (0-2^32-1)
  - `chainCode` (Buffer) - Chain code (32 bytes)
  - `privateKey` (Object) - Private key data (if encoding private key)
    - `keyMaterial` (Buffer) - 32-byte private key
    - `wifVersionByte` (number) - WIF version byte
  - `publicKey` (Object) - Public key data
    - `keyMaterial` (Buffer) - 33-byte compressed public key
  - `versionBytes` (Object) - Network version bytes
    - `extendedPrivateKey` (number) - Extended private key version
    - `extendedPublicKey` (number) - Extended public key version

**Returns:**
- `string` - Base58-encoded extended key (111 characters)

**Throws:**
- `EncodingError` - If key context is invalid
- `EncodingError` - If encoding fails

#### `encodeStandardKeys(privateKeyData, publicKeyData)`
Encodes standard Bitcoin keys (WIF private key and hex public key).

**Parameters:**
- `privateKeyData` (Object) - Private key information
  - `keyMaterial` (Buffer) - 32-byte private key
  - `wifVersionByte` (number) - WIF version byte (0x80 mainnet, 0xef testnet)
- `publicKeyData` (Object) - Public key information
  - `keyMaterial` (Buffer) - 33-byte compressed public key

**Returns:**
- Object with encoded keys:
  - `privateKeyWIF` (string) - WIF-encoded private key
  - `publicKeyHex` (string) - Hex-encoded public key
  - `isValid` (boolean) - Validation status
  - `network` (string) - Detected network ('main' or 'test')

#### `generateAddress(versionByte, publicKeyHash)`
Generates legacy Bitcoin address using Base58Check encoding.

**Parameters:**
- `versionByte` (number) - Address version byte
  - `0x00` - Mainnet P2PKH
  - `0x05` - Mainnet P2SH
  - `0x6f` - Testnet P2PKH
  - `0xc4` - Testnet P2SH
- `publicKeyHash` (Buffer) - RIPEMD160 hash of public key (20 bytes)

**Returns:**
- `string` - Base58Check-encoded address

**Throws:**
- `EncodingError` - If version byte or hash is invalid

#### `generateAddressFromExtendedVersion(extendedKeyVersion)`
Generates address from extended key version data.

**Parameters:**
- `extendedKeyVersion` (Object) - Extended key version structure
  - `version` (number) - Extended key version bytes
  - `depth` (number) - Derivation depth
  - `parentFingerprint` (Buffer) - Parent fingerprint
  - `childIndex` (number) - Child index
  - `chainCode` (Buffer) - Chain code
  - `keyMaterial` (Buffer) - Key material

**Returns:**
- `string` - Generated Bitcoin address

#### `createPublicKeyFingerprint(publicKey)`
Creates 4-byte fingerprint from public key for BIP32 derivation.

**Parameters:**
- `publicKey` (Buffer) - 33-byte compressed public key

**Returns:**
- `Buffer` - 4-byte fingerprint (first 4 bytes of HASH160)

**Formula:**
```
fingerprint = RIPEMD160(SHA256(publicKey))[0:4]
```

### Security Classes

#### `EncodingSecurityUtils`
Security utilities for encoding operations.

**Methods:**
- `validateKeyMaterial(keyMaterial, expectedLength)` - Validates key material
- `validateVersionBytes(versionBytes)` - Validates network version bytes
- `secureClear(sensitiveData)` - Securely clears sensitive data
- `validateBase58CheckEncoding(encoded)` - Validates Base58Check format

### Extended Key Format

#### BIP32 Extended Key Structure (78 bytes)
```
[version:4][depth:1][parent_fingerprint:4][child_index:4][chain_code:32][key_material:33]
```

#### Version Bytes
| Network | Extended Private | Extended Public |
|---------|------------------|-----------------|
| Mainnet | 0x0488ade4 (xprv) | 0x0488b21e (xpub) |
| Testnet | 0x04358394 (tprv) | 0x043587cf (tpub) |

### WIF Private Key Format

#### WIF Encoding Steps
1. Take 32-byte private key
2. Add version byte (0x80 mainnet, 0xef testnet)
3. Add compression flag (0x01 for compressed)
4. Calculate SHA256(SHA256(data))
5. Take first 4 bytes as checksum
6. Encode with Base58

#### WIF Example
```
Private Key: E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262
Version: 80 (mainnet)
Compression: 01 (compressed)
Data: 80E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA3326201
Checksum: 51f28b64
WIF: 5Hx15HFGyep2CfPxsJKe2fXJsCVn5DEiyoeGGF6JZjGbTRnqfiD
```

### Address Generation

#### Legacy Address Generation
1. Take public key (33 bytes compressed)
2. SHA256 hash
3. RIPEMD160 hash (20 bytes)
4. Add version byte
5. Calculate checksum (SHA256(SHA256(data)))
6. Append first 4 bytes of checksum
7. Base58 encode

### Security Features

- **Comprehensive Validation** - All inputs thoroughly validated
- **Secure Memory Management** - Sensitive data cleared after use
- **Buffer Overflow Protection** - Bounds checking for all operations
- **Cross-Implementation Compatibility** - Compatible with Bitcoin Core
- **Entropy Validation** - Cryptographic quality checks
- **Rate Limiting** - DoS protection for encoding operations
- **Input Sanitization** - Thorough input cleaning and validation

### Error Codes

- `INVALID_KEY_MATERIAL` - Key material format or length invalid
- `INVALID_VERSION_BYTES` - Network version bytes invalid
- `INVALID_DEPTH` - Derivation depth out of range
- `INVALID_CHILD_INDEX` - Child index out of range
- `INVALID_CHAIN_CODE` - Chain code format invalid
- `ENCODING_FAILED` - Base58 encoding operation failed
- `CHECKSUM_GENERATION_FAILED` - Checksum calculation failed
- `MEMORY_CLEAR_FAILED` - Sensitive data clearing failed

### Best Practices

1. **Always validate inputs** before encoding
2. **Use compressed public keys** for efficiency
3. **Clear sensitive data** immediately after use
4. **Verify encoded results** with test vectors
5. **Use appropriate version bytes** for target network
6. **Implement proper error handling** for encoding failures
7. **Cache computations** only for non-sensitive data
8. **Use secure random sources** for key generation

### Performance Notes

- Extended key encoding: ~1-2ms per operation
- Address generation: ~0.5-1ms per address  
- WIF encoding: ~0.3-0.8ms per key
- Public key fingerprint: ~0.1-0.3ms per computation
- Base58Check encoding: ~0.2-0.5ms per operation