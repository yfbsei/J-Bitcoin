# Address Decoding

Comprehensive Bitcoin address decoding utilities with support for all address formats and enhanced security validation.

## Description

This module provides complete Bitcoin address decoding functionality for all address types including Legacy (P2PKH/P2SH), SegWit (Bech32), and Taproot addresses. It includes comprehensive validation, format detection, network identification, and security features with timing attack prevention and comprehensive error handling.

## Example

```javascript
import { 
    decodeAddress,
    validateAddress,
    getAddressInfo,
    decodeBase58Check,
    decodeBech32Address,
    AddressDecoder
} from 'j-bitcoin';

// Decode Legacy P2PKH address
const legacyAddress = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';
const legacyDecoded = decodeAddress(legacyAddress);
console.log('Address Type:', legacyDecoded.type); // 'p2pkh'
console.log('Network:', legacyDecoded.network); // 'main'
console.log('Hash:', legacyDecoded.hash.toString('hex'));
console.log('Script:', legacyDecoded.scriptPubKey.toString('hex'));

// Decode SegWit Bech32 address
const segwitAddress = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
const segwitDecoded = decodeAddress(segwitAddress);
console.log('Address Type:', segwitDecoded.type); // 'p2wpkh'
console.log('Witness Version:', segwitDecoded.witnessVersion); // 0
console.log('Witness Program:', segwitDecoded.witnessProgram.toString('hex'));

// Decode Taproot address
const taprootAddress = 'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297';
const taprootDecoded = decodeAddress(taprootAddress);
console.log('Address Type:', taprootDecoded.type); // 'p2tr'
console.log('Taproot Output:', taprootDecoded.taprootOutput.toString('hex'));

// Comprehensive address validation
const validation = validateAddress(legacyAddress);
console.log('Valid:', validation.isValid);
console.log('Details:', validation.details);
console.log('Warnings:', validation.warnings);

// Get comprehensive address information
const addressInfo = getAddressInfo(segwitAddress);
console.log('Address Info:', addressInfo);
console.log('Format:', addressInfo.format); // 'bech32'
console.log('Version:', addressInfo.version);
console.log('Estimated Fee Savings:', addressInfo.feeSavings);

// Batch address decoding
const addresses = [
    '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
    '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
    'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297'
];

const batchResults = addresses.map(addr => decodeAddress(addr));
batchResults.forEach((result, index) => {
    console.log(`Address ${index + 1}:`, result.type, result.network);
});

// Advanced decoding with custom options
const advancedDecoder = new AddressDecoder({
    strictValidation: true,
    supportTestnet: true,
    allowNonStandard: false,
    checksumValidation: true
});

const strictDecoded = advancedDecoder.decode(legacyAddress);
console.log('Strict Validation Result:', strictDecoded);

// Raw Base58Check decoding
const base58Decoded = decodeBase58Check(legacyAddress);
console.log('Version Byte:', base58Decoded.version);
console.log('Payload:', base58Decoded.payload.toString('hex'));
console.log('Checksum Valid:', base58Decoded.checksumValid);

// Raw Bech32 decoding
const bech32Decoded = decodeBech32Address(segwitAddress);
console.log('HRP:', bech32Decoded.hrp);
console.log('Witness Version:', bech32Decoded.witnessVersion);
console.log('Witness Program:', bech32Decoded.witnessProgram.toString('hex'));
console.log('Encoding:', bech32Decoded.encoding); // 'bech32' or 'bech32m'
```

## API Reference

### Functions

#### `decodeAddress(address, options = {})`
Decodes any Bitcoin address format with automatic type detection.

**Parameters:**
- `address` (string) - Bitcoin address to decode
- `options` (Object) - Decoding options
  - `network` (string) - Expected network ('main', 'test', or 'auto')
  - `strictValidation` (boolean) - Enable strict validation (default: true)
  - `allowNonStandard` (boolean) - Allow non-standard addresses (default: false)

**Returns:**
- Object with decoded address information:
  - `type` (string) - Address type ('p2pkh', 'p2sh', 'p2wpkh', 'p2wsh', 'p2tr')
  - `network` (string) - Network ('main' or 'test')
  - `format` (string) - Address format ('base58', 'bech32', 'bech32m')
  - `hash` (Buffer) - Hash160 for legacy addresses
  - `witnessVersion` (number) - Witness version for SegWit addresses
  - `witnessProgram` (Buffer) - Witness program for SegWit addresses
  - `taprootOutput` (Buffer) - Taproot output for P2TR addresses
  - `scriptPubKey` (Buffer) - Corresponding scriptPubKey
  - `isValid` (boolean) - Whether address is valid
  - `originalAddress` (string) - Original input address

**Throws:**
- `AddressDecodingError` - If address format is invalid or unsupported

#### `validateAddress(address, options = {})`
Validates a Bitcoin address with comprehensive checks.

**Parameters:**
- `address` (string) - Address to validate
- `options` (Object) - Validation options
  - `network` (string) - Expected network
  - `allowedTypes` (Array<string>) - Allowed address types
  - `strictChecksums` (boolean) - Strict checksum validation

**Returns:**
- Object with validation result:
  - `isValid` (boolean) - Overall validation result
  - `type` (string) - Detected address type
  - `network` (string) - Detected network
  - `details` (Object) - Detailed validation information
    - `formatValid` (boolean) - Format validation
    - `checksumValid` (boolean) - Checksum validation
    - `networkValid` (boolean) - Network validation
    - `typeValid` (boolean) - Type validation
  - `warnings` (Array<string>) - Validation warnings
  - `errors` (Array<string>) - Validation errors

#### `getAddressInfo(address)`
Gets comprehensive information about an address including metadata.

**Parameters:**
- `address` (string) - Bitcoin address

**Returns:**
- Object with comprehensive address information:
  - Basic decoding information (type, network, etc.)
  - `format` (string) - Address format details
  - `version` (number) - Address version information
  - `feeSavings` (number) - Estimated fee savings vs legacy (percentage)
  - `privacyLevel` (string) - Privacy level assessment
  - `adoptionRate` (number) - Network adoption rate for this type
  - `recommendations` (Array<string>) - Usage recommendations

#### `decodeBase58Check(address)`
Decodes Base58Check encoded data (Legacy addresses).

**Parameters:**
- `address` (string) - Base58Check encoded string

**Returns:**
- Object with Base58Check decoding:
  - `version` (number) - Version byte
  - `payload` (Buffer) - Decoded payload
  - `checksum` (Buffer) - Extracted checksum
  - `checksumValid` (boolean) - Whether checksum is valid
  - `originalData` (Buffer) - Complete original data

#### `decodeBech32Address(address)`
Decodes Bech32/Bech32m encoded addresses (SegWit/Taproot).

**Parameters:**
- `address` (string) - Bech32 encoded address

**Returns:**
- Object with Bech32 decoding:
  - `hrp` (string) - Human-readable prefix
  - `witnessVersion` (number) - Witness version (0-16)
  - `witnessProgram` (Buffer) - Witness program
  - `encoding` (string) - Encoding type ('bech32' or 'bech32m')
  - `checksumValid` (boolean) - Checksum validation result

### Classes

#### `AddressDecoder`
Advanced address decoder with configurable options.

**Constructor:**
```javascript
new AddressDecoder(options = {})
```

**Options:**
- `strictValidation` (boolean) - Enable strict validation mode
- `supportTestnet` (boolean) - Support testnet addresses
- `allowNonStandard` (boolean) - Allow non-standard address formats
- `checksumValidation` (boolean) - Enable checksum validation
- `networkDetection` (boolean) - Auto-detect network from address
- `cacheResults` (boolean) - Cache decoding results for performance

**Methods:**

##### `decoder.decode(address)`
Decodes address with configured options.

##### `decoder.validateFormat(address)`
Validates address format only (no checksum verification).

##### `decoder.getNetworkInfo(address)`
Gets network information from address.

##### `decoder.clearCache()`
Clears the decoding cache.

### Address Type Detection

#### Address Format Recognition
```javascript
const formats = {
  legacy: /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/,
  bech32: /^(bc|tb)1[ac-hj-np-z02-9]{11,87}$/,
  bech32m: /^(bc|tb)1p[ac-hj-np-z02-9]{6,87}$/
};
```

#### Version Byte Mapping
```javascript
const VERSION_BYTES = {
  // Mainnet
  0x00: 'p2pkh',        // 1...
  0x05: 'p2sh',         // 3...
  
  // Testnet
  0x6f: 'p2pkh_test',   // m... or n...
  0xc4: 'p2sh_test'     // 2...
};
```

#### Witness Version Mapping
```javascript
const WITNESS_VERSIONS = {
  0: { types: ['p2wpkh', 'p2wsh'], encoding: 'bech32' },
  1: { types: ['p2tr'], encoding: 'bech32m' }
  // Versions 2-16 reserved for future use
};
```

### ScriptPubKey Generation

#### Legacy ScriptPubKey (P2PKH)
```
OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
```

#### Legacy ScriptPubKey (P2SH)
```
OP_HASH160 <20-byte-hash> OP_EQUAL
```

#### SegWit ScriptPubKey (P2WPKH)
```
OP_0 <20-byte-hash>
```

#### SegWit ScriptPubKey (P2WSH)
```
OP_0 <32-byte-hash>
```

#### Taproot ScriptPubKey (P2TR)
```
OP_1 <32-byte-taproot-output>
```

### Security Features

- **Checksum Validation** - Comprehensive checksum verification for all formats
- **Format Validation** - Strict format validation with regex patterns
- **Network Validation** - Automatic network detection and validation
- **Timing Attack Prevention** - Constant-time comparison operations
- **Input Sanitization** - Thorough input validation and sanitization
- **Error Information Control** - Error messages don't leak sensitive information
- **Rate Limiting** - DoS protection for batch operations

### Error Handling

#### Error Types
- `INVALID_ADDRESS_FORMAT` - Address format not recognized
- `INVALID_CHECKSUM` - Checksum validation failed
- `UNSUPPORTED_ADDRESS_TYPE` - Address type not supported
- `NETWORK_MISMATCH` - Address network doesn't match expected
- `INVALID_WITNESS_VERSION` - Witness version not supported
- `INVALID_WITNESS_PROGRAM` - Witness program format invalid
- `DECODING_FAILED` - General decoding failure

#### Error Codes
```javascript
const ERROR_CODES = {
  INVALID_FORMAT: 'INVALID_ADDRESS_FORMAT',
  CHECKSUM_FAILED: 'INVALID_CHECKSUM',
  UNSUPPORTED_TYPE: 'UNSUPPORTED_ADDRESS_TYPE',
  NETWORK_MISMATCH: 'NETWORK_MISMATCH',
  WITNESS_ERROR: 'INVALID_WITNESS_PROGRAM'
};
```

### Performance Optimization

#### Decoding Performance
- **Format detection** - Fast regex-based format detection
- **Caching** - Optional result caching for repeated operations
- **Batch processing** - Optimized batch decoding
- **Early validation** - Fail fast on invalid formats

#### Memory Usage
- **Buffer pooling** - Reuse buffers for temporary operations
- **Lazy evaluation** - Only compute required fields
- **Memory cleanup** - Automatic cleanup of temporary data

### Integration Examples

#### With Address Validation
```javascript
const isValidBitcoinAddress = (address) => {
    try {
        const decoded = decodeAddress(address);
        return decoded.isValid;
    } catch (error) {
        return false;
    }
};
```

#### With Transaction Building
```javascript
const createOutputScript = (address) => {
    const decoded = decodeAddress(address);
    return decoded.scriptPubKey;
};
```

#### With Wallet Address Generation
```javascript
const validateReceiveAddress = (address, expectedNetwork) => {
    const validation = validateAddress(address, {
        network: expectedNetwork,
        allowedTypes: ['p2wpkh', 'p2tr'] // Only modern formats
    });
    return validation;
};
```

### Best Practices

1. **Always validate addresses** before using in transactions
2. **Check network compatibility** before processing
3. **Use strict validation** for production applications
4. **Handle all error cases** gracefully
5. **Cache decoding results** for performance when appropriate
6. **Validate checksums** for all address types
7. **Support all modern formats** (SegWit, Taproot)
8. **Provide clear error messages** for invalid addresses
9. **Use constant-time operations** for sensitive comparisons
10. **Keep up with new address formats** and Bitcoin improvements

### Compatibility Notes

- **Bitcoin Core compatibility** - Fully compatible with Bitcoin Core address validation
- **BIP compliance** - Follows all relevant BIPs (BIP173, BIP350, etc.)
- **Cross-platform** - Works across different JavaScript environments
- **Version support** - Supports all current and planned address versions