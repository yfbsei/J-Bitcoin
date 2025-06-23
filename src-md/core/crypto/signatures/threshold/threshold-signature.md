# Threshold Signatures

Comprehensive threshold signature implementation for distributed Bitcoin key management and multi-party signing.

## Description

This module provides a complete threshold signature scheme implementation allowing t-of-n multi-party control over Bitcoin private keys. It includes secure secret sharing, distributed key generation, threshold signing protocols, and comprehensive security features for enterprise-grade Bitcoin custody solutions.

## Example

```javascript
import ThresholdSignature from 'j-bitcoin';

// Generate threshold keys (2-of-3 scheme)
const threshold = 2;
const participants = 3;

const keyShares = ThresholdSignature.generateKeyShares(threshold, participants);
console.log('Generated', participants, 'key shares with threshold', threshold);

// Each participant gets their share
const [share1, share2, share3] = keyShares;
console.log('Participant 1 Share:', share1.shareValue.toString('hex'));

// Distributed signing (requires threshold participants)
const message = "Bitcoin transaction to sign";
const messageHash = Buffer.from(message);

// Phase 1: Generate individual signatures
const partialSig1 = ThresholdSignature.generatePartialSignature(share1, messageHash);
const partialSig2 = ThresholdSignature.generatePartialSignature(share2, messageHash);

// Phase 2: Combine signatures (threshold reached)
const partialSignatures = [partialSig1, partialSig2];
const combinedSignature = ThresholdSignature.combinePartialSignatures(
    partialSignatures, 
    messageHash,
    threshold
);

console.log('Combined Signature:', combinedSignature);
console.log('R:', combinedSignature.r.toString('hex'));
console.log('S:', combinedSignature.s.toString('hex'));

// Verify the threshold signature
const publicKey = ThresholdSignature.derivePublicKey(keyShares);
const isValid = ThresholdSignature.verify(combinedSignature, messageHash, publicKey);
console.log('Threshold signature valid:', isValid);

// Advanced: PDF-compliant threshold signature
const pdfSignature = await ThresholdSignature.generatePDFCompliantSignature(
    partialSignatures,
    message,
    { maxAttempts: 10 }
);
console.log('PDF-compliant signature:', pdfSignature);
```

## API Reference

### Static Methods

#### `ThresholdSignature.generateKeyShares(threshold, participants, options = {})`
Generates threshold key shares for distributed key management.

**Parameters:**
- `threshold` (number) - Minimum shares required for signing (t)
- `participants` (number) - Total number of participants (n)
- `options` (Object) - Generation options
  - `network` (string) - Bitcoin network ('main' or 'test')
  - `entropy` (Buffer) - Additional entropy source
  - `algorithm` (string) - Sharing algorithm ('shamir' or 'jvrss')

**Returns:**
- Array of key share objects:
  - `shareIndex` (number) - Share index (1 to n)
  - `shareValue` (Buffer) - Secret share value
  - `publicKey` (Buffer) - Corresponding public key
  - `threshold` (number) - Required threshold
  - `participants` (number) - Total participants
  - `metadata` (Object) - Additional share metadata

**Throws:**
- `Error` - If threshold parameters are invalid
- `Error` - If key generation fails

#### `ThresholdSignature.generatePartialSignature(keyShare, messageHash, options = {})`
Generates a partial signature from a threshold key share.

**Parameters:**
- `keyShare` (Object) - Threshold key share
- `messageHash` (Buffer) - 32-byte message hash to sign
- `options` (Object) - Signing options
  - `nonce` (Buffer) - Custom nonce (optional)
  - `deterministicNonce` (boolean) - Use deterministic nonce
  - `auxRand` (Buffer) - Auxiliary randomness

**Returns:**
- Object with partial signature:
  - `shareIndex` (number) - Signer's share index
  - `partialR` (Buffer) - Partial R component
  - `partialS` (Buffer) - Partial S component
  - `nonce` (Buffer) - Nonce used
  - `commitment` (Buffer) - Commitment to nonce

#### `ThresholdSignature.combinePartialSignatures(partialSignatures, messageHash, threshold)`
Combines partial signatures into a complete threshold signature.

**Parameters:**
- `partialSignatures` (Array) - Array of partial signatures (≥ threshold)
- `messageHash` (Buffer) - Original message hash
- `threshold` (number) - Required threshold

**Returns:**
- Object with combined signature:
  - `r` (Buffer) - R component (32 bytes)
  - `s` (Buffer) - S component (32 bytes)
  - `recovery` (number) - Recovery ID
  - `threshold` (number) - Threshold used
  - `participantsUsed` (Array) - Indices of participants used

**Throws:**
- `Error` - If insufficient partial signatures
- `Error` - If combination fails

#### `ThresholdSignature.verify(signature, messageHash, publicKey)`
Verifies a threshold signature.

**Parameters:**
- `signature` (Object) - Threshold signature to verify
- `messageHash` (Buffer) - Original message hash
- `publicKey` (Buffer) - Public key for verification

**Returns:**
- `boolean` - True if signature is valid, false otherwise

#### `ThresholdSignature.derivePublicKey(keyShares)`
Derives the combined public key from threshold key shares.

**Parameters:**
- `keyShares` (Array) - Array of key shares

**Returns:**
- `Buffer` - Combined public key (33 bytes compressed)

### Advanced Features

#### `ThresholdSignature.generatePDFCompliantSignature(partialSignatures, message, options = {})`
Generates PDF-compliant threshold signature with enhanced validation.

**Parameters:**
- `partialSignatures` (Array) - Partial signatures
- `message` (string|Buffer) - Original message
- `options` (Object) - Generation options
  - `maxAttempts` (number) - Maximum generation attempts
  - `canonicalize` (boolean) - Ensure canonical signature

**Returns:**
- Object with PDF-compliant signature:
  - `signature` (Object) - Standard signature components
  - `messageHash` (string) - Message hash used
  - `canonicalized` (boolean) - Whether signature was canonicalized
  - `participantsUsed` (number) - Number of participants
  - `attempts` (number) - Generation attempts

#### `ThresholdSignature.reconstructSecret(keyShares, threshold)`
Reconstructs the original secret from threshold shares (for emergency recovery).

**Parameters:**
- `keyShares` (Array) - Array of key shares (≥ threshold)
- `threshold` (number) - Required threshold

**Returns:**
- `Buffer` - Reconstructed secret (use with extreme caution)

**⚠️ Security Warning:** This function reconstructs the full private key and should only be used for emergency recovery.

### Polynomial Interpolation

#### `ThresholdSignature.Polynomial.interpolateAtZero(points)`
Performs Lagrange interpolation at zero for secret reconstruction.

**Parameters:**
- `points` (Array) - Array of polynomial points

**Returns:**
- Object with interpolation result:
  - `value` (BigNumber) - Interpolated value
  - `coefficients` (Array) - Lagrange coefficients used

### Security Classes

#### `ThresholdSecurityUtils`
Security utilities for threshold operations.

**Methods:**
- `validateThresholdParams(t, n)` - Validates threshold parameters
- `secureClear(data)` - Securely clears sensitive data
- `validatePartialSignature(partialSig)` - Validates partial signature
- `checkNonceReuse(nonces)` - Prevents nonce reuse attacks

#### `SignatureValidator`
Signature validation utilities.

**Methods:**
- `validateAndCanonicalize(signature)` - Validates and canonicalizes signature
- `isCanonical(signature)` - Checks if signature is canonical
- `validateComponents(r, s)` - Validates signature components

### Threshold Schemes

#### Shamir's Secret Sharing
- **Security:** Information-theoretic security
- **Threshold:** Any t-of-n configuration
- **Reconstruction:** Requires exactly t shares
- **Use Case:** Static key backup and recovery

#### Joint Verifiable Random Secret Sharing (JVRSS)
- **Security:** Cryptographic security with verification
- **Threshold:** Optimized for 2-of-3, 3-of-5 configurations
- **Reconstruction:** Distributed without reconstruction
- **Use Case:** Active signing without key reconstruction

### Security Features

- **Distributed Key Generation** - No single point of failure
- **Verifiable Secret Sharing** - Cryptographic verification of shares
- **Nonce Reuse Prevention** - Comprehensive nonce management
- **Canonical Signatures** - Enforces low-s signatures
- **Secure Memory Management** - Automatic cleanup of sensitive data
- **Share Validation** - Comprehensive validation of all shares
- **Attack Resistance** - Protection against common threshold attacks

### Threshold Configuration Examples

#### 2-of-3 Multi-Signature
```javascript
const keyShares = ThresholdSignature.generateKeyShares(2, 3);
// Requires any 2 of 3 participants to sign
```

#### 3-of-5 Enterprise Setup
```javascript
const keyShares = ThresholdSignature.generateKeyShares(3, 5);
// Requires any 3 of 5 board members to authorize
```

#### 5-of-7 High Security
```javascript
const keyShares = ThresholdSignature.generateKeyShares(5, 7);
// Requires majority (5 of 7) for critical operations
```

### Performance Considerations

| Operation | Time Complexity | Notes |
|-----------|----------------|--------|
| Key Generation | O(n²) | One-time setup |
| Partial Signature | O(1) | Per participant |
| Signature Combination | O(t²) | Threshold dependent |
| Verification | O(1) | Standard ECDSA |

### Error Codes

- `INVALID_THRESHOLD_PARAMS` - Threshold parameters invalid
- `INSUFFICIENT_SHARES` - Not enough shares for operation
- `INVALID_SHARE` - Share format or value invalid
- `SIGNING_FAILED` - Partial signature generation failed
- `COMBINATION_FAILED` - Signature combination failed
- `NONCE_REUSE_DETECTED` - Nonce reuse attack detected
- `INTERPOLATION_FAILED` - Polynomial interpolation failed
- `VERIFICATION_FAILED` - Threshold signature verification failed

### Best Practices

1. **Use JVRSS for active signing** scenarios
2. **Use Shamir's for backup/recovery** scenarios
3. **Never reconstruct the full key** unless absolutely necessary
4. **Validate all shares** before use
5. **Implement secure communication** between participants
6. **Use deterministic nonces** to prevent attacks
7. **Clear sensitive data** immediately after use
8. **Implement proper access controls** for shares
9. **Regular security audits** of threshold operations
10. **Backup shares securely** in separate locations