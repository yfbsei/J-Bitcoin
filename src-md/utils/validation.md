# Validation Utilities

Comprehensive validation utilities for Bitcoin operations with enhanced security features and input sanitization.

## Description

This module provides a complete set of validation functions for Bitcoin-related operations including network validation, threshold parameters, numerical ranges, buffer validation, and more. It includes enhanced security features, proper error handling, and comprehensive input sanitization to prevent common vulnerabilities.

## Example

```javascript
import { 
    validateNetwork,
    validateThresholdParams,
    validateNumberRange,
    validateBufferLength,
    assertValid,
    ValidationError
} from 'j-bitcoin';

// Validate network parameter
try {
    validateNetwork('main');
    console.log('Network validation passed');
} catch (error) {
    console.error('Invalid network:', error.message);
}

// Validate threshold signature parameters
try {
    validateThresholdParams(2, 3); // 2-of-3 threshold
    console.log('Threshold parameters valid');
} catch (error) {
    console.error('Invalid threshold:', error.message);
}

// Validate numerical ranges
try {
    validateNumberRange(5, 1, 10, 'account index');
    console.log('Number in valid range');
} catch (error) {
    console.error('Number out of range:', error.message);
}

// Validate buffer length
const buffer = Buffer.from('hello world', 'utf8');
try {
    validateBufferLength(buffer, 11, 'message buffer');
    console.log('Buffer length valid');
} catch (error) {
    console.error('Invalid buffer length:', error.message);
}

// Assert validation with custom message
try {
    assertValid(false, 'Custom validation failed', 'CUSTOM_ERROR');
} catch (error) {
    console.error('Assertion failed:', error.message);
    console.error('Error code:', error.code);
}
```

## API Reference

### Classes

#### `ValidationError`
Enhanced error class for validation failures.

**Constructor:**
- `ValidationError(message, code, details = {})`

**Properties:**
- `name` (string) - Always 'ValidationError'
- `message` (string) - Error message
- `code` (string) - Error code for programmatic handling
- `details` (Object) - Additional error details
- `timestamp` (number) - Error creation timestamp

### Functions

#### `validateNetwork(network, fieldName = 'network')`
Validates Bitcoin network parameter.

**Parameters:**
- `network` (string) - Network to validate ('main' or 'test')
- `fieldName` (string) - Field name for error messages

**Returns:**
- `string` - Validated network value

**Throws:**
- `ValidationError` - If network is invalid

**Example:**
```javascript
const network = validateNetwork('main');
console.log('Validated network:', network); // 'main'
```

#### `validateThresholdParams(threshold, participants, fieldPrefix = '')`
Validates threshold signature scheme parameters.

**Parameters:**
- `threshold` (number) - Required threshold (minimum signatures)
- `participants` (number) - Total participants
- `fieldPrefix` (string) - Prefix for error field names

**Returns:**
- `Object` - Validated parameters
  - `threshold` (number) - Validated threshold
  - `participants` (number) - Validated participants

**Throws:**
- `ValidationError` - If parameters are invalid

**Validation Rules:**
- Threshold must be ≥ 2
- Participants must be ≥ threshold
- Threshold cannot exceed participants
- Both must be finite integers

**Example:**
```javascript
const params = validateThresholdParams(2, 3);
console.log('Valid 2-of-3 threshold:', params);
```

#### `validateNumberRange(value, min, max, fieldName = 'value')`
Validates that a number is within a specified range.

**Parameters:**
- `value` (number) - Number to validate
- `min` (number) - Minimum allowed value (inclusive)
- `max` (number) - Maximum allowed value (inclusive)
- `fieldName` (string) - Field name for error messages

**Returns:**
- `number` - Validated number

**Throws:**
- `ValidationError` - If number is out of range or invalid

**Example:**
```javascript
const index = validateNumberRange(5, 0, 10, 'address index');
console.log('Valid index:', index); // 5
```

#### `validateBufferLength(buffer, expectedLength, fieldName = 'buffer')`
Validates buffer length with security checks.

**Parameters:**
- `buffer` (Buffer|Uint8Array) - Buffer to validate
- `expectedLength` (number) - Expected buffer length
- `fieldName` (string) - Field name for error messages

**Returns:**
- `Buffer` - Validated buffer

**Throws:**
- `ValidationError` - If buffer is invalid or wrong length

**Example:**
```javascript
const key = Buffer.from('a'.repeat(32), 'hex');
const validKey = validateBufferLength(key, 16, 'private key');
console.log('Valid key length:', validKey.length); // 16
```

#### `validateHexString(hexString, expectedLength = null, fieldName = 'hex string')`
Validates hexadecimal string format and optional length.

**Parameters:**
- `hexString` (string) - Hex string to validate
- `expectedLength` (number|null) - Expected byte length (optional)
- `fieldName` (string) - Field name for error messages

**Returns:**
- `string` - Validated hex string (lowercase)

**Throws:**
- `ValidationError` - If hex string is invalid

**Example:**
```javascript
const hex = validateHexString('deadbeef', 4, 'transaction id');
console.log('Valid hex:', hex); // 'deadbeef'
```

#### `validateDerivationPath(path, fieldName = 'derivation path')`
Validates BIP32 derivation path format.

**Parameters:**
- `path` (string) - Derivation path to validate
- `fieldName` (string) - Field name for error messages

**Returns:**
- `string` - Validated derivation path

**Throws:**
- `ValidationError` - If path format is invalid

**Path Format Rules:**
- Must start with 'm/'
- Components must be numbers or numbers with "'" for hardened
- Indices must be within 32-bit range
- Maximum depth validation

**Example:**
```javascript
const path = validateDerivationPath("m/44'/0'/0'/0/0");
console.log('Valid path:', path);
```

#### `validateMnemonic(mnemonic, fieldName = 'mnemonic')`
Validates BIP39 mnemonic phrase format.

**Parameters:**
- `mnemonic` (string) - Mnemonic phrase to validate
- `fieldName` (string) - Field name for error messages

**Returns:**
- `string` - Validated mnemonic (normalized)

**Throws:**
- `ValidationError` - If mnemonic is invalid

**Validation Rules:**
- Word count must be 12, 15, 18, 21, or 24
- All words must exist in BIP39 wordlist
- Checksum validation
- Unicode normalization

#### `validatePrivateKey(privateKey, fieldName = 'private key')`
Validates private key format and value.

**Parameters:**
- `privateKey` (string|Buffer) - Private key to validate
- `fieldName` (string) - Field name for error messages

**Returns:**
- `Buffer` - Validated private key as buffer

**Throws:**
- `ValidationError` - If private key is invalid

**Validation Rules:**
- Must be 32 bytes
- Cannot be zero
- Must be less than secp256k1 curve order
- Validates both hex strings and buffers

#### `validatePublicKey(publicKey, fieldName = 'public key')`
Validates public key format and point validity.

**Parameters:**
- `publicKey` (string|Buffer) - Public key to validate
- `fieldName` (string) - Field name for error messages

**Returns:**
- `Buffer` - Validated public key as buffer

**Throws:**
- `ValidationError` - If public key is invalid

**Validation Rules:**
- Must be 33 bytes (compressed) or 65 bytes (uncompressed)
- Must be valid secp256k1 point
- Validates point on curve

#### `assertValid(condition, message, code = 'VALIDATION_FAILED', details = {})`
Assertion function that throws ValidationError on failure.

**Parameters:**
- `condition` (boolean) - Condition to assert
- `message` (string) - Error message if condition fails
- `code` (string) - Error code
- `details` (Object) - Additional error details

**Throws:**
- `ValidationError` - If condition is false

**Example:**
```javascript
assertValid(
    user.age >= 18, 
    'User must be at least 18 years old',
    'AGE_VALIDATION_FAILED',
    { actualAge: user.age, minimumAge: 18 }
);
```

### Security Features

- **Input Sanitization** - All inputs are thoroughly validated and sanitized
- **Range Checking** - Numerical values are checked against valid ranges
- **Buffer Overflow Prevention** - Buffer lengths are validated
- **Format Validation** - String formats are validated with regex patterns
- **Type Checking** - Strict type validation for all parameters
- **Cryptographic Validation** - Private/public keys validated for cryptographic validity
- **Error Information Control** - Error messages don't leak sensitive information

### Error Codes

- `INVALID_NETWORK` - Network parameter is invalid
- `INVALID_THRESHOLD_PARAMS` - Threshold signature parameters invalid
- `NUMBER_OUT_OF_RANGE` - Number outside valid range
- `INVALID_BUFFER_LENGTH` - Buffer length incorrect
- `INVALID_HEX_STRING` - Hexadecimal string format invalid
- `INVALID_DERIVATION_PATH` - Derivation path format invalid
- `INVALID_MNEMONIC` - Mnemonic phrase invalid
- `INVALID_PRIVATE_KEY` - Private key invalid
- `INVALID_PUBLIC_KEY` - Public key invalid
- `VALIDATION_FAILED` - Generic validation failure

### Best Practices

1. **Always validate external inputs** before processing
2. **Use specific validation functions** rather than generic checks
3. **Handle ValidationError separately** from other errors
4. **Check error codes** for programmatic error handling
5. **Validate early** in function execution
6. **Use appropriate field names** for clear error messages