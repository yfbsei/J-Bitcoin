# Schnorr Signatures (BIP340)

Comprehensive Schnorr signature implementation following BIP340 specification for Bitcoin Taproot.

## Description

This module provides a complete BIP340-compliant Schnorr signature implementation for Bitcoin Taproot operations. It includes proper tagged hashing, deterministic nonce generation, signature aggregation capabilities, and comprehensive security features including batch verification and enhanced entropy management.

## Example

```javascript
import Schnorr from 'j-bitcoin';

// Basic Schnorr signing (BIP340)
const privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
const message = "Hello Taproot!";

const signature = Schnorr.sign(privateKey, message);
console.log('Schnorr Signature:', signature.signature.toString('hex'));
console.log('Signature Length:', signature.signature.length); // 64 bytes

// Verify signature
const publicKey = Schnorr.getPublicKey(privateKey);
const isValid = Schnorr.verify(signature.signature, message, publicKey);
console.log('Signature valid:', isValid);

// Enhanced Schnorr with auxiliary randomness
const enhanced = new Schnorr.Enhanced();
const auxRand = Buffer.from('additional_randomness_for_security');

const enhancedSig = await enhanced.sign(privateKey, message, auxRand);
console.log('Enhanced signature:', enhancedSig);

// Batch verification (multiple signatures at once)
const signatures = [signature1, signature2, signature3];
const messages = [message1, message2, message3];
const pubKeys = [pubKey1, pubKey2, pubKey3];

const batchValid = Schnorr.batchVerify(signatures, messages, pubKeys);
console.log('Batch verification result:', batchValid);

// Tagged hash (BIP340 utility)
const tag = "BIP0340/challenge";
const data = Buffer.from('challenge_data');
const taggedHash = Schnorr.taggedHash(tag, data);
console.log('Tagged hash:', taggedHash.toString('hex'));
```

## API Reference

### Static Methods

#### `Schnorr.sign(privateKey, message, auxRand = null)`
Signs a message using BIP340 Schnorr signatures.

**Parameters:**
- `privateKey` (string|Buffer) - Private key (32 bytes or WIF format)
- `message` (string|Buffer) - Message to sign (will be hashed if string)
- `auxRand` (Buffer|null) - Auxiliary randomness (32 bytes, optional)

**Returns:**
- Object with signature information:
  - `signature` (Buffer) - 64-byte Schnorr signature
  - `publicKey` (Buffer) - 32-byte x-only public key
  - `challenge` (Buffer) - Challenge hash used
  - `nonce` (Buffer) - Nonce point used (for debugging)

**Throws:**
- `Error` - If private key is invalid
- `Error` - If signing fails

#### `Schnorr.verify(signature, message, publicKey)`
Verifies a BIP340 Schnorr signature.

**Parameters:**
- `signature` (Buffer) - 64-byte Schnorr signature
- `message` (string|Buffer) - Original message
- `publicKey` (Buffer) - 32-byte x-only public key

**Returns:**
- `boolean` - True if signature is valid, false otherwise

#### `Schnorr.getPublicKey(privateKey)`
Derives x-only public key from private key.

**Parameters:**
- `privateKey` (string|Buffer) - Private key

**Returns:**
- `Buffer` - 32-byte x-only public key

#### `Schnorr.taggedHash(tag, data)`
Computes BIP340 tagged hash.

**Parameters:**
- `tag` (string) - Hash tag for domain separation
- `data` (Buffer) - Data to hash

**Returns:**
- `Buffer` - 32-byte tagged hash

**Formula:**
```
TaggedHash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)
```

#### `Schnorr.batchVerify(signatures, messages, publicKeys)`
Efficiently verifies multiple Schnorr signatures.

**Parameters:**
- `signatures` (Array<Buffer>) - Array of 64-byte signatures
- `messages` (Array<Buffer>) - Array of messages
- `publicKeys` (Array<Buffer>) - Array of 32-byte x-only public keys

**Returns:**
- `boolean` - True if all signatures are valid, false otherwise

**Performance:** ~3x faster than individual verification for large batches

### Enhanced Schnorr Class

#### `new Schnorr.Enhanced(options = {})`
Creates enhanced Schnorr instance with advanced features.

**Options:**
- `enableBatchVerification` (boolean) - Enable batch verification (default: true)
- `secureNonceGeneration` (boolean) - Use enhanced nonce generation (default: true)
- `auxiliaryRandomness` (Buffer) - Default auxiliary randomness
- `taggedHashCache` (boolean) - Cache tagged hash computations (default: true)

#### `enhanced.sign(privateKey, message, auxRand = null)`
Enhanced signing with additional security features.

**Parameters:**
- `privateKey` (string|Buffer) - Private key
- `message` (string|Buffer) - Message to sign
- `auxRand` (Buffer|null) - Auxiliary randomness

**Returns:**
- Object with enhanced signature:
  - `signature` (Buffer) - 64-byte signature
  - `metadata` (Object) - Signature metadata
    - `nonce` (string) - Nonce used (hex)
    - `challenge` (string) - Challenge hash (hex)
    - `auxRand` (string) - Auxiliary randomness used (hex)
  - `securityLevel` (string) - Security assessment
  - `bip340Compliant` (boolean) - BIP340 compliance confirmation

#### `enhanced.verify(signature, message, publicKey)`
Enhanced verification with additional checks.

**Returns:**
- Object with verification result:
  - `valid` (boolean) - Whether signature is valid
  - `bip340Compliant` (boolean) - BIP340 compliance
  - `securityChecks` (Object) - Additional validations

### Signature Aggregation

#### `Schnorr.aggregateSignatures(signatures, publicKeys, messages)`
Aggregates multiple Schnorr signatures (MuSig-style).

**Parameters:**
- `signatures` (Array<Buffer>) - Individual signatures
- `publicKeys` (Array<Buffer>) - Corresponding public keys
- `messages` (Array<Buffer>) - Corresponding messages

**Returns:**
- Object with aggregated signature:
  - `signature` (Buffer) - Aggregated signature
  - `aggregatedPublicKey` (Buffer) - Aggregated public key
  - `participants` (number) - Number of participants

### Key Tweaking (Taproot)

#### `Schnorr.tweakPrivateKey(privateKey, tweak)`
Tweaks private key for Taproot key-path spending.

**Parameters:**
- `privateKey` (Buffer) - 32-byte private key
- `tweak` (Buffer) - 32-byte tweak value

**Returns:**
- `Buffer` - Tweaked private key

#### `Schnorr.tweakPublicKey(publicKey, tweak)`
Tweaks public key for Taproot.

**Parameters:**
- `publicKey` (Buffer) - 32-byte x-only public key
- `tweak` (Buffer) - 32-byte tweak value

**Returns:**
- Object with tweaked key:
  - `publicKey` (Buffer) - Tweaked public key
  - `parity` (number) - Y-coordinate parity (0 or 1)

### BIP340 Compliance

#### Tagged Hash Tags
Standard BIP340 tags used:
- `"BIP0340/nonce"` - Nonce generation
- `"BIP0340/aux"` - Auxiliary randomness processing
- `"BIP0340/challenge"` - Challenge hash computation
- `"TapTweak"` - Taproot key tweaking
- `"TapLeaf"` - Taproot script leaf hashing
- `"TapBranch"` - Taproot merkle branch hashing

#### Signature Format
```
signature = r || s
where:
- r: 32-byte x-coordinate of nonce point
- s: 32-byte scalar value
Total: 64 bytes
```

### Security Features

- **BIP340 Compliance** - Full adherence to BIP340 specification
- **Deterministic Nonces** - RFC 6979-style deterministic nonce generation
- **Auxiliary Randomness** - Additional entropy for enhanced security
- **Tagged Hashing** - Domain separation for different use cases
- **Batch Verification** - Efficient verification of multiple signatures
- **Key Tweaking** - Proper Taproot key and signature tweaking
- **Side-Channel Protection** - Protection against timing attacks
- **Secure Random Generation** - Cryptographically secure randomness

### Taproot Integration

#### Script Path Spending
```javascript
// Create script path signature
const scriptLeaf = Buffer.from('script_content');
const merkleRoot = Schnorr.computeMerkleRoot([scriptLeaf]);
const tweak = Schnorr.taggedHash("TapTweak", merkleRoot);
const tweakedPrivKey = Schnorr.tweakPrivateKey(privateKey, tweak);

const signature = Schnorr.sign(tweakedPrivKey, sigHash);
```

#### Key Path Spending
```javascript
// Create key path signature (no script)
const emptyTweak = Buffer.alloc(32, 0);
const tweak = Schnorr.taggedHash("TapTweak", emptyTweak);
const tweakedPrivKey = Schnorr.tweakPrivateKey(privateKey, tweak);

const signature = Schnorr.sign(tweakedPrivKey, sigHash);
```

### Performance Benchmarks

| Operation | Time (ms) | Notes |
|-----------|-----------|--------|
| Sign | 2-4 | Single signature |
| Verify | 1-3 | Single verification |
| Batch Verify (100) | 50-80 | ~3x improvement |
| Key Generation | 0.5-1 | X-only public key |
| Tagged Hash | 0.1-0.3 | Cached computation |

### Error Codes

- `INVALID_PRIVATE_KEY` - Private key invalid for Schnorr
- `INVALID_PUBLIC_KEY` - Public key format invalid
- `INVALID_SIGNATURE` - Signature format or value invalid
- `INVALID_AUX_RAND` - Auxiliary randomness invalid
- `SIGNING_FAILED` - Schnorr signing failed
- `VERIFICATION_FAILED` - Signature verification failed
- `AGGREGATION_FAILED` - Signature aggregation failed
- `TWEAK_FAILED` - Key tweaking operation failed
- `BATCH_VERIFICATION_FAILED` - Batch verification failed

### Best Practices

1. **Always use auxiliary randomness** for additional security
2. **Verify BIP340 compliance** for all operations
3. **Use batch verification** for multiple signatures
4. **Implement proper key tweaking** for Taproot
5. **Cache tagged hash computations** for performance
6. **Validate all inputs** before cryptographic operations
7. **Use secure random generation** for nonces
8. **Clear sensitive data** after use