# BIP39 Mnemonic Implementation

Comprehensive BIP39 mnemonic phrase generation, validation, and seed derivation with enhanced security features.

## Description

This module provides a complete BIP39 implementation for generating and validating mnemonic phrases, converting them to seeds, and assessing entropy quality. It includes enhanced security features, proper Unicode normalization, comprehensive validation, and secure memory management for all sensitive operations.

## Example

```javascript
import { BIP39 } from 'j-bitcoin';

// Generate new mnemonic with default 128-bit entropy
const result = BIP39.generate();
console.log('Mnemonic:', result.mnemonic);
console.log('Quality Score:', result.entropyQuality.score);
console.log('Generation Time:', result.generationTime + 'ms');

// Generate with higher entropy
const strongResult = BIP39.generate(256);
console.log('24-word Mnemonic:', strongResult.mnemonic);

// Validate existing mnemonic
const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const isValid = BIP39.validate(testMnemonic);
console.log('Valid:', isValid);

// Convert to seed for key derivation
const seed = BIP39.toSeed(result.mnemonic, "optional-passphrase");
console.log('Seed (hex):', seed.toString('hex'));
console.log('Seed length:', seed.length, 'bytes');

// Extract original entropy
const entropy = BIP39.toEntropy(result.mnemonic);
console.log('Original Entropy:', entropy.toString('hex'));

// Create mnemonic from entropy
const customEntropy = new Uint8Array(16); // 128 bits
crypto.getRandomValues(customEntropy);
const mnemonicFromEntropy = BIP39.fromEntropy(customEntropy);
console.log('Mnemonic from custom entropy:', mnemonicFromEntropy);
```

## API Reference

### Static Methods

#### `BIP39.generate(entropyBits = 128)`
Generates a new BIP39 mnemonic phrase with cryptographic entropy.

**Parameters:**
- `entropyBits` (number) - Entropy in bits (128, 160, 192, 224, or 256)

**Returns:**
- Object with generation result:
  - `mnemonic` (string) - Generated mnemonic phrase
  - `entropyQuality` (Object) - Entropy quality assessment
    - `score` (number) - Quality score 0.0-1.0
    - `tests` (Object) - Individual test results
  - `generationTime` (number) - Generation time in milliseconds

**Throws:**
- `Error` - If entropy bits value is not supported

#### `BIP39.validate(mnemonic)`
Validates a BIP39 mnemonic phrase checksum and format.

**Parameters:**
- `mnemonic` (string) - Mnemonic phrase to validate

**Returns:**
- `boolean` - True if valid, false otherwise

**Features:**
- Validates word count (12, 15, 18, 21, or 24 words)
- Checks each word exists in BIP39 wordlist
- Verifies checksum integrity
- Handles Unicode normalization

#### `BIP39.toSeed(mnemonic, passphrase = '')`
Converts a mnemonic phrase to a seed using PBKDF2.

**Parameters:**
- `mnemonic` (string) - Valid BIP39 mnemonic phrase
- `passphrase` (string) - Optional passphrase for additional security

**Returns:**
- `Uint8Array` - 64-byte seed for key derivation

**Features:**
- PBKDF2 with 2048 iterations (BIP39 standard)
- Proper Unicode NFKD normalization
- Salt: "mnemonic" + passphrase
- Secure memory management

#### `BIP39.toEntropy(mnemonic)`
Converts a mnemonic phrase back to its original entropy.

**Parameters:**
- `mnemonic` (string) - Valid BIP39 mnemonic phrase

**Returns:**
- `Uint8Array` - Original entropy bytes (16-32 bytes)

**Throws:**
- `Error` - If mnemonic is invalid or checksum fails

#### `BIP39.fromEntropy(entropy)`
Creates a mnemonic phrase from entropy bytes.

**Parameters:**
- `entropy` (Buffer|Uint8Array) - Entropy bytes (16, 20, 24, 28, or 32 bytes)

**Returns:**
- `string` - BIP39 mnemonic phrase

**Throws:**
- `Error` - If entropy length is invalid

#### `BIP39.assessMnemonicQuality(mnemonic)`
Assesses the entropy quality of an existing mnemonic.

**Parameters:**
- `mnemonic` (string) - Mnemonic phrase to assess

**Returns:**
- Object with quality assessment:
  - `isValid` (boolean) - Whether mnemonic is valid
  - `quality` (Object) - Quality metrics
  - `assessment` (string) - Overall assessment ('excellent', 'good', 'fair', 'poor')

### Word Count Support

| Entropy Bits | Word Count | Checksum Bits | Use Case |
|--------------|------------|---------------|-----------|
| 128 | 12 | 4 | Standard wallets |
| 160 | 15 | 5 | Enhanced security |
| 192 | 18 | 6 | High security |
| 224 | 21 | 7 | Very high security |
| 256 | 24 | 8 | Maximum security |

### Security Features

- **Cryptographic Entropy** - Uses secure random number generation (Node.js crypto)
- **Unicode Normalization** - Proper NFKD normalization for international compatibility
- **Checksum Validation** - Comprehensive checksum verification with timing attack prevention
- **Quality Assessment** - Entropy quality analysis and scoring
- **Secure Memory Management** - Automatic cleanup of sensitive data
- **Rate Limiting** - DoS protection for computational operations
- **Timing Attack Prevention** - Constant-time comparison operations

### Error Codes

- `INVALID_ENTROPY_BITS` - Unsupported entropy size
- `INVALID_MNEMONIC_LENGTH` - Invalid word count
- `INVALID_WORD` - Word not in BIP39 wordlist
- `CHECKSUM_MISMATCH` - Mnemonic checksum validation failed
- `UNICODE_NORMALIZATION_FAILED` - Unicode processing error
- `PBKDF2_FAILED` - Seed derivation failed