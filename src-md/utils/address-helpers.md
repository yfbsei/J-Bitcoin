# Address Helper Utilities

Enhanced address utility functions with comprehensive security features for Bitcoin address operations.

## Description

This module provides essential address utility functions for Bitcoin operations including bit conversion, checksum validation, buffer operations, and security utilities. It includes comprehensive security improvements such as timing attack prevention, buffer overflow protection, and secure memory management.

## Example

```javascript
import { 
    convertBits,
    validateChecksumLegacy,
    secureBufferConcat,
    constantTimeEqual,
    AddressUtilError 
} from 'j-bitcoin';

// Convert between different bit encodings
const data = Buffer.from([1, 2, 3, 4, 5]);
const converted = convertBits(data, 8, 5, true);
console.log('Converted to 5-bit:', converted);

// Convert back to original encoding
const original = convertBits(converted, 5, 8, false);
console.log('Original data restored:', original);

// Validate legacy address checksum
const address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
const addressBytes = base58_to_binary(address);
const isValid = validateChecksumLegacy(addressBytes);
console.log('Checksum valid:', isValid);

// Secure buffer concatenation
const buffer1 = Buffer.from('hello');
const buffer2 = Buffer.from(' world');
const combined = secureBufferConcat([buffer1, buffer2]);
console.log('Combined:', combined.toString()); // "hello world"

// Constant-time comparison (prevents timing attacks)
const secret1 = Buffer.from('secret');
const secret2 = Buffer.from('secret');
const isEqual = constantTimeEqual(secret1, secret2);
console.log('Secrets equal:', isEqual); // true
```

## API Reference

### Classes

#### `AddressUtilError`
Enhanced error class for address utility operations.

**Constructor:**
- `AddressUtilError(message, code, details = {})`

**Properties:**
- `name` (string) - Always 'AddressUtilError'
- `message` (string) - Error message
- `code` (string) - Error code
- `details` (Object) - Additional error details
- `timestamp` (number) - Error creation timestamp

### Functions

#### `convertBits(data, fromBits, toBits, pad = true)`
Converts data between different bit encodings with comprehensive validation.

**Parameters:**
- `data` (Buffer|Uint8Array|Array) - Input data to convert
- `fromBits` (number) - Source bit encoding (1-8)
- `toBits` (number) - Target bit encoding (1-8)
- `pad` (boolean) - Whether to pad final incomplete group

**Returns:**
- `Array` - Converted data as array of integers

**Throws:**
- `AddressUtilError` - If parameters are invalid or conversion fails

**Security Features:**
- Input size validation (prevents DoS)
- Bit range validation
- Overflow protection
- Memory bounds checking

**Example:**
```javascript
// Convert 8-bit data to 5-bit (for Bech32)
const data = Buffer.from([0xff, 0x00, 0x80]);
const bech32Data = convertBits(data, 8, 5, true);
console.log('Bech32 encoding:', bech32Data);

// Convert back
const original = convertBits(bech32Data, 5, 8, false);
console.log('Restored:', Buffer.from(original));
```

#### `validateChecksumLegacy(addressBytes)`
Validates Base58Check checksum for legacy Bitcoin addresses.

**Parameters:**
- `addressBytes` (Buffer|Uint8Array) - Address bytes including checksum

**Returns:**
- `boolean` - True if checksum is valid, false otherwise

**Security Features:**
- Constant-time comparison
- Input validation
- Buffer bounds checking
- Timing attack prevention

**Example:**
```javascript
// Validate legacy address
const address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
const decoded = base58_to_binary(address);
const isValid = validateChecksumLegacy(decoded);
console.log('Legacy address valid:', isValid);
```

#### `secureBufferConcat(buffers, totalLength = null)`
Securely concatenates multiple buffers with bounds checking.

**Parameters:**
- `buffers` (Array<Buffer>) - Array of buffers to concatenate
- `totalLength` (number|null) - Expected total length (optional validation)

**Returns:**
- `Buffer` - Concatenated buffer

**Throws:**
- `AddressUtilError` - If concatenation fails or length mismatch

**Security Features:**
- Memory bounds checking
- Length validation
- Buffer overflow prevention
- Input sanitization

**Example:**
```javascript
const parts = [
    Buffer.from([0x01, 0x02]),
    Buffer.from([0x03, 0x04]),
    Buffer.from([0x05, 0x06])
];
const combined = secureBufferConcat(parts, 6);
console.log('Combined buffer:', combined); // <Buffer 01 02 03 04 05 06>
```

#### `constantTimeEqual(a, b)`
Performs constant-time buffer comparison to prevent timing attacks.

**Parameters:**
- `a` (Buffer|Uint8Array) - First buffer
- `b` (Buffer|Uint8Array) - Second buffer

**Returns:**
- `boolean` - True if buffers are equal, false otherwise

**Security Features:**
- Timing attack prevention
- Constant-time operation
- Length validation
- Side-channel protection

**Example:**
```javascript
const hash1 = Buffer.from('a'.repeat(32), 'hex');
const hash2 = Buffer.from('a'.repeat(32), 'hex');
const isEqual = constantTimeEqual(hash1, hash2);
console.log('Hashes equal:', isEqual); // true

// Timing attack safe comparison
const userHash = Buffer.from(userInput, 'hex');
const expectedHash = Buffer.from(expectedValue, 'hex');
const isValid = constantTimeEqual(userHash, expectedHash);
```

#### `validateBitConversionParams(fromBits, toBits, data)`
Validates parameters for bit conversion operations.

**Parameters:**
- `fromBits` (number) - Source bit encoding
- `toBits` (number) - Target bit encoding
- `data` (any) - Data to validate

**Returns:**
- `void` - Throws on validation failure

**Throws:**
- `AddressUtilError` - If parameters are invalid

**Validation Rules:**
- Bit values must be 1-8
- Data must be array-like
- Data length must be reasonable
- No null/undefined values

#### `secureMemoryClear(buffer)`
Securely clears sensitive data from memory.

**Parameters:**
- `buffer` (Buffer|Uint8Array) - Buffer to clear

**Returns:**
- `void`

**Security Features:**
- Multi-pass clearing
- Random data overwrite
- Final zero fill
- Memory safety

**Example:**
```javascript
const privateKey = Buffer.from('sensitive_key_data');
// ... use private key ...
secureMemoryClear(privateKey);
console.log('Key cleared:', privateKey); // All zeros
```

#### `generateSecureRandom(length)`
Generates cryptographically secure random bytes.

**Parameters:**
- `length` (number) - Number of bytes to generate

**Returns:**
- `Buffer` - Secure random bytes

**Throws:**
- `AddressUtilError` - If random generation fails

**Example:**
```javascript
const randomBytes = generateSecureRandom(32);
console.log('Random data:', randomBytes.toString('hex'));
```

#### `validateAddressFormat(address, expectedFormat)`
Validates address format against expected type.

**Parameters:**
- `address` (string) - Address to validate
- `expectedFormat` (string) - Expected format ('legacy', 'segwit', 'taproot')

**Returns:**
- `boolean` - True if format matches

**Example:**
```javascript
const isLegacy = validateAddressFormat('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', 'legacy');
const isSegWit = validateAddressFormat('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'segwit');
console.log('Legacy format:', isLegacy); // true
console.log('SegWit format:', isSegWit); // true
```

### Security Constants

#### `SECURITY_CONSTANTS`
Security-related constants for safe operations.

```javascript
{
  MAX_INPUT_SIZE: 512,                    // Maximum input size
  MAX_OUTPUT_SIZE: 1024,                  // Maximum output size
  MAX_CONVERSION_BITS: 8,                 // Maximum bit conversion
  MIN_CONVERSION_BITS: 1,                 // Minimum bit conversion
  MAX_VALIDATIONS_PER_SECOND: 100,        // Rate limiting
  MEMORY_CLEAR_PASSES: 3,                 // Memory clearing passes
  MAX_BUFFER_CONCAT_SIZE: 2048,           // Max concatenation size
  CHECKSUM_LENGTH: 4                      // Base58Check checksum length
}
```

### Security Features

- **Timing Attack Prevention** - Constant-time operations for sensitive comparisons
- **Buffer Overflow Protection** - Comprehensive bounds checking
- **Memory Safety** - Secure memory clearing and management
- **Rate Limiting** - DoS protection for computational operations
- **Input Validation** - Thorough validation of all inputs
- **Side-Channel Protection** - Protection against side-channel attacks
- **Secure Random Generation** - Cryptographically secure randomness

### Error Codes

- `INVALID_INPUT_SIZE` - Input exceeds size limits
- `INVALID_BIT_ENCODING` - Bit encoding parameters invalid
- `BUFFER_OVERFLOW` - Buffer operation would overflow
- `CONVERSION_FAILED` - Bit conversion failed
- `CHECKSUM_VALIDATION_FAILED` - Checksum validation failed
- `MEMORY_CLEAR_FAILED` - Memory clearing operation failed
- `RANDOM_GENERATION_FAILED` - Secure random generation failed
- `RATE_LIMIT_EXCEEDED` - Too many operations per second

### Best Practices

1. **Use constant-time comparisons** for sensitive data
2. **Validate all inputs** before processing
3. **Clear sensitive data** after use
4. **Check buffer bounds** before operations
5. **Use secure random generation** for cryptographic operations
6. **Implement rate limiting** for public-facing functions
7. **Handle errors gracefully** without information leakage