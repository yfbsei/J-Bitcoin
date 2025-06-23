# ECDSA Signatures

Enhanced ECDSA signature implementation with comprehensive security features and Bitcoin protocol compliance.

## Description

This module provides a complete ECDSA signature implementation for Bitcoin operations including signing, verification, recovery, and validation. It includes enhanced security features such as canonical signature enforcement, nonce reuse prevention, and comprehensive input validation with timing attack protection.

## Example

```javascript
import ECDSA from 'j-bitcoin';

// Basic ECDSA signing
const privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
const message = "Hello Bitcoin!";

const signature = ECDSA.sign(privateKey, message);
console.log('Signature:', signature);
console.log('R:', signature.r.toString('hex'));
console.log('S:', signature.s.toString('hex'));
console.log('Recovery ID:', signature.recovery);

// Verify signature
const publicKey = ECDSA.getPublicKey(privateKey);
const isValid = ECDSA.verify(signature, message, publicKey);
console.log('Signature valid:', isValid);

// Recover public key from signature
const recoveredPubKey = ECDSA.recover(signature, message);
console.log('Recovered public key:', recoveredPubKey.toString('hex'));

// Enhanced signing with options
const enhancedECDSA = new ECDSA.Enhanced({
    enforceCanonical: true,
    extraEntropy: Buffer.from('additional_entropy')
});

const enhancedSig = await enhancedECDSA.sign(privateKey, message, {
    bitcoinMessage: true,
    extraEntropy: Buffer.from('per_message_entropy')
});
console.log('Enhanced signature:', enhancedSig);
```

## API Reference

### Static Methods

#### `ECDSA.sign(privateKey, message, options = {})`
Signs a message using ECDSA with the secp256k1 curve.

**Parameters:**
- `privateKey` (string|Buffer) - Private key in WIF format or as buffer
- `message` (string|Buffer) - Message to sign
- `options` (Object) - Signing options
  - `bitcoinMessage` (boolean) - Use Bitcoin message format
  - `extraEntropy` (Buffer) - Additional entropy for nonce generation
  - `canonical` (boolean) - Enforce canonical signatures (default: true)

**Returns:**
- Object with signature components:
  - `r` (Buffer) - R component (32 bytes)
  - `s` (Buffer) - S component (32 bytes)
  - `recovery` (number) - Recovery ID (0-3)
  - `isCanonical` (boolean) - Whether signature is canonical

**Throws:**
- `Error` - If private key is invalid
- `Error` - If signing fails

#### `ECDSA.verify(signature, message, publicKey, options = {})`
Verifies an ECDSA signature against a message and public key.

**Parameters:**
- `signature` (Object) - Signature object with r, s components
- `message` (string|Buffer) - Original message that was signed
- `publicKey` (string|Buffer) - Public key for verification
- `options` (Object) - Verification options
  - `bitcoinMessage` (boolean) - Use Bitcoin message format
  - `strict` (boolean) - Strict validation mode

**Returns:**
- `boolean` - True if signature is valid, false otherwise

#### `ECDSA.recover(signature, message, options = {})`
Recovers the public key from a signature and message.

**Parameters:**
- `signature` (Object) - Signature with r, s, and recovery components
- `message` (string|Buffer) - Original message
- `options` (Object) - Recovery options

**Returns:**
- `Buffer` - Recovered public key (33 bytes compressed)

**Throws:**
- `Error` - If recovery fails or signature is invalid

#### `ECDSA.getPublicKey(privateKey, compressed = true)`
Derives public key from private key.

**Parameters:**
- `privateKey` (string|Buffer) - Private key
- `compressed` (boolean) - Return compressed public key

**Returns:**
- `Buffer` - Public key (33 bytes if compressed, 65 bytes if uncompressed)

#### `ECDSA.isCanonical(signature)`
Checks if a signature is canonical (s ≤ curve_order/2).

**Parameters:**
- `signature` (Object) - Signature to check

**Returns:**
- `boolean` - True if canonical, false otherwise

### Enhanced ECDSA Class

#### `new ECDSA.Enhanced(options = {})`
Creates an enhanced ECDSA instance with advanced features.

**Options:**
- `enforceCanonical` (boolean) - Enforce canonical signatures (default: true)
- `enableCache` (boolean) - Enable public key caching (default: false)
- `extraEntropy` (Buffer) - Default extra entropy
- `maxCacheSize` (number) - Maximum cache size (default: 100)

#### `enhanced.sign(privateKey, message, options = {})`
Enhanced signing with additional security features.

**Parameters:**
- `privateKey` (string|Buffer) - Private key
- `message` (string|Buffer) - Message to sign
- `options` (Object) - Enhanced signing options
  - `bitcoinMessage` (boolean) - Use Bitcoin message hash
  - `extraEntropy` (Buffer) - Per-message entropy
  - `deterministicNonce` (boolean) - Use deterministic nonce (RFC 6979)

**Returns:**
- Object with enhanced signature:
  - `signature` (Object) - Standard signature components
  - `metadata` (Object) - Additional signature metadata
  - `securityLevel` (string) - Security assessment
  - `canonicalized` (boolean) - Whether signature was canonicalized

#### `enhanced.verify(signature, message, publicKey, options = {})`
Enhanced verification with additional checks.

**Parameters:**
- `signature` (Object) - Signature to verify
- `message` (string|Buffer) - Original message
- `publicKey` (string|Buffer) - Public key
- `options` (Object) - Verification options

**Returns:**
- Object with verification result:
  - `valid` (boolean) - Whether signature is valid
  - `canonical` (boolean) - Whether signature is canonical
  - `securityChecks` (Object) - Additional security validations

### Validator Classes

#### `ECDSAValidator`
Static validation utilities for ECDSA operations.

**Methods:**
- `validatePrivateKey(privateKey)` - Validates private key format and range
- `validatePublicKey(publicKey)` - Validates public key format and curve point
- `validateSignature(signature)` - Validates signature components
- `validateMessage(message)` - Validates message format

#### `SignatureCanonicalizer`
Utilities for signature canonicalization.

**Methods:**
- `canonicalize(signature)` - Converts signature to canonical form
- `isCanonical(signature)` - Checks if signature is canonical

### Transaction Integration

#### `TransactionHasher`
Utilities for Bitcoin transaction message hashing.

**Methods:**
- `createMessageHash(message)` - Creates Bitcoin message hash
- `createTransactionHash(transaction, inputIndex, sighashType)` - Creates transaction signature hash

### Security Features

- **Canonical Signatures** - Enforces low-s signatures to prevent malleability
- **Nonce Reuse Prevention** - Secure nonce generation with entropy mixing
- **Timing Attack Protection** - Constant-time operations where possible
- **Input Validation** - Comprehensive validation of all inputs
- **Public Key Recovery** - Efficient public key recovery from signatures
- **Cache Security** - Optional secure caching of computed values
- **Side-Channel Protection** - Protection against side-channel attacks

### Signature Format

#### Standard ECDSA Signature
```javascript
{
  r: Buffer,           // 32-byte R component
  s: Buffer,           // 32-byte S component  
  recovery: number,    // Recovery ID (0-3)
  isCanonical: boolean // Whether signature is canonical
}
```

#### Enhanced Signature
```javascript
{
  signature: {         // Standard signature components
    r: Buffer,
    s: Buffer,
    recovery: number
  },
  metadata: {
    nonce: string,     // Nonce used (for debugging)
    entropy: string,   // Entropy source
    attempts: number   // Generation attempts
  },
  securityLevel: string, // 'high', 'medium', 'low'
  canonicalized: boolean
}
```

### Bitcoin Message Format

When `bitcoinMessage` option is true, messages are hashed using Bitcoin's standard:

```
SHA256(SHA256("Bitcoin Signed Message:\n" + message_length + message))
```

### Error Codes

- `INVALID_PRIVATE_KEY` - Private key format or value invalid
- `INVALID_PUBLIC_KEY` - Public key format or curve point invalid
- `INVALID_SIGNATURE` - Signature components invalid
- `SIGNING_FAILED` - ECDSA signing operation failed
- `VERIFICATION_FAILED` - Signature verification failed
- `RECOVERY_FAILED` - Public key recovery failed
- `NON_CANONICAL_SIGNATURE` - Signature is not canonical
- `NONCE_GENERATION_FAILED` - Nonce generation failed

### Best Practices

1. **Always use canonical signatures** for Bitcoin transactions
2. **Validate all inputs** before cryptographic operations
3. **Use extra entropy** for additional security
4. **Clear sensitive data** after use
5. **Verify signatures** before accepting transactions
6. **Use compressed public keys** to save space
7. **Handle errors gracefully** without information leakage
8. **Consider caching** for performance in high-throughput scenarios

### Performance Notes

- Signature generation: ~1-5ms depending on hardware
- Signature verification: ~1-3ms per signature
- Public key recovery: ~2-4ms per recovery
- Caching can improve performance by 50-80% for repeated operations