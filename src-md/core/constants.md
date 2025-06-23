# Bitcoin Core Constants

Comprehensive Bitcoin constants and network configuration for the J-Bitcoin library.

## Description

This module provides all the essential constants, network configurations, and utility functions needed for Bitcoin operations. It includes BIP44 derivation paths, network version bytes, cryptographic constants, address formats, and helper functions for Bitcoin development. The module serves as the central configuration hub for the entire library.

## Example

```javascript
import { 
    BIP44_CONSTANTS, 
    BITCOIN_NETWORKS, 
    CRYPTO_CONSTANTS,
    generateDerivationPath,
    parseDerivationPath,
    getNetworkByCoinType,
    validateAndGetNetwork 
} from 'j-bitcoin';

// Generate standard Bitcoin receiving address path
const receivingPath = generateDerivationPath({
    purpose: 44,
    coinType: BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET,
    account: 0,
    change: 0,
    addressIndex: 0
});
console.log('Receiving Path:', receivingPath); // "m/44'/0'/0'/0/0"

// Generate change address path
const changePath = generateDerivationPath({
    purpose: 44,
    coinType: BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET,
    account: 0,
    change: BIP44_CONSTANTS.CHANGE_TYPES.INTERNAL_CHAIN,
    addressIndex: 5
});
console.log('Change Path:', changePath); // "m/44'/0'/0'/1/5"

// Parse derivation path
const parsed = parseDerivationPath(receivingPath);
console.log('Parsed Components:', parsed);
// { purpose: 44, coinType: 0, account: 0, change: 0, addressIndex: 0 }

// Get network configuration
const mainnetConfig = getNetworkByCoinType(0);
console.log('Network:', mainnetConfig.name); // "Bitcoin"
console.log('Bech32 Prefix:', mainnetConfig.bech32Prefix); // "bc"

// Validate network
const networkConfig = validateAndGetNetwork('main');
console.log('Validated Network:', networkConfig);

// Access cryptographic constants
console.log('Private Key Length:', CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH); // 32
console.log('Secp256k1 Order:', CRYPTO_CONSTANTS.SECP256K1_ORDER);
```

## API Reference

### Constants

#### `BIP44_CONSTANTS`
Standard BIP44 constants for Bitcoin derivation paths.

```javascript
{
  COIN_TYPES: {
    BITCOIN_MAINNET: 0,
    BITCOIN_TESTNET: 1
  },
  DEFAULT_ACCOUNT: 0,
  CHANGE_TYPES: {
    EXTERNAL_CHAIN: 0,  // Receiving addresses
    INTERNAL_CHAIN: 1   // Change addresses
  }
}
```

#### `DERIVATION_PATHS`
Standard Bitcoin derivation path templates.

```javascript
{
  MAINNET_RECEIVING: "m/44'/0'/0'/0",
  MAINNET_CHANGE: "m/44'/0'/0'/1",
  TESTNET_RECEIVING: "m/44'/1'/0'/0",
  TESTNET_CHANGE: "m/44'/1'/0'/1"
}
```

#### `BITCOIN_NETWORKS`
Complete Bitcoin network configurations.

```javascript
{
  MAINNET: {
    name: 'Bitcoin',
    symbol: 'BTC',
    coinType: 0,
    bech32Prefix: 'bc',
    legacyPrefix: '1',
    p2shPrefix: '3',
    network: 'main',
    versions: { /* version bytes */ }
  },
  TESTNET: {
    name: 'Bitcoin Testnet',
    symbol: 'BTC',
    coinType: 1,
    bech32Prefix: 'tb',
    legacyPrefix: 'm',
    legacyPrefixAlt: 'n',
    p2shPrefix: '2',
    network: 'test',
    versions: { /* version bytes */ }
  }
}
```

#### `NETWORK_VERSIONS`
Network-specific version bytes for address and key encoding.

```javascript
{
  MAINNET: {
    P2PKH_ADDRESS: 0x00,
    P2SH_ADDRESS: 0x05,
    WIF_PRIVATE_KEY: 0x80,
    EXTENDED_PUBLIC_KEY: 0x0488b21e,
    EXTENDED_PRIVATE_KEY: 0x0488ade4
  },
  TESTNET: {
    P2PKH_ADDRESS: 0x6f,
    P2SH_ADDRESS: 0xc4,
    WIF_PRIVATE_KEY: 0xef,
    EXTENDED_PUBLIC_KEY: 0x043587cf,
    EXTENDED_PRIVATE_KEY: 0x04358394
  }
}
```

#### `CRYPTO_CONSTANTS`
Cryptographic constants for secp256k1 operations.

```javascript
{
  SECP256K1_ORDER: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
  PRIVATE_KEY_LENGTH: 32,
  PUBLIC_KEY_COMPRESSED_LENGTH: 33,
  PUBLIC_KEY_UNCOMPRESSED_LENGTH: 65,
  CHAIN_CODE_LENGTH: 32,
  CHECKSUM_LENGTH: 4,
  HARDENED_OFFSET: 0x80000000,
  HASH160_LENGTH: 20,
  SHA256_LENGTH: 32,
  HASH256_LENGTH: 32
}
```

#### `BIP32_CONSTANTS`
BIP32 hierarchical deterministic wallet constants.

```javascript
{
  MASTER_KEY_DEPTH: 0,
  ZERO_PARENT_FINGERPRINT: Buffer.alloc(4, 0),
  MASTER_CHILD_INDEX: 0,
  MASTER_KEY_HMAC_KEY: "Bitcoin seed",
  MAX_DERIVATION_DEPTH: 255,
  EXTENDED_KEY_LENGTH: 78,
  MIN_SEED_BYTES: 16,
  MAX_SEED_BYTES: 64
}
```

#### `BIP39_CONSTANTS`
BIP39 mnemonic phrase constants.

```javascript
{
  ENTROPY_BITS: 128,
  CHECKSUM_BITS: 4,
  WORD_COUNT: 12,
  BITS_PER_WORD: 11,
  PBKDF2_ITERATIONS: 2048,
  SEED_LENGTH_BYTES: 64,
  MNEMONIC_SALT_PREFIX: 'mnemonic'
}
```

#### `ADDRESS_FORMATS`
Address format identifiers.

```javascript
{
  LEGACY: 'legacy',      // P2PKH
  SEGWIT: 'segwit',      // P2WPKH
  P2SH: 'p2sh',          // P2SH
  TAPROOT: 'taproot'     // P2TR
}
```

#### `BIP_PURPOSES`
Standard BIP purposes for different address types.

```javascript
{
  LEGACY: 44,           // BIP44 - Legacy P2PKH addresses
  NESTED_SEGWIT: 49,    // BIP49 - P2WPKH-nested-in-P2SH addresses
  NATIVE_SEGWIT: 84,    // BIP84 - Native SegWit P2WPKH addresses
  TAPROOT: 86           // BIP86 - Taproot P2TR addresses
}
```

#### `ENCODING_CONSTANTS`
Base58 and Base32 encoding constants.

```javascript
{
  BASE58_ALPHABET: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
  BASE32_ALPHABET: 'qpzry9x8gf2tvdw0s3jn54khce6mua7l',
  BECH32_CONST: 1,
  BECH32M_CONST: 0x2bc830a3,
  BECH32_MAX_LENGTH: 90
}
```

#### `THRESHOLD_CONSTANTS`
Threshold signature scheme constants.

```javascript
{
  MIN_PARTICIPANTS: 2,
  MIN_THRESHOLD: 2,
  MAX_RECOMMENDED_PARTICIPANTS: 15,
  POLYNOMIAL_ORDER_OFFSET: 1
}
```

### Functions

#### `generateDerivationPath(options)`
Generates a BIP44 derivation path from options.

**Parameters:**
- `options` (Object) - Path generation options
  - `purpose` (number) - BIP purpose (default: 44)
  - `coinType` (number) - Coin type (default: 0)
  - `account` (number) - Account index (default: 0)
  - `change` (number) - Change chain (default: 0)
  - `addressIndex` (number) - Address index (default: 0)

**Returns:**
- `string` - Complete BIP44 derivation path

**Example:**
```javascript
const path = generateDerivationPath({
  purpose: BIP_PURPOSES.NATIVE_SEGWIT,
  coinType: BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET,
  account: 0,
  change: BIP44_CONSTANTS.CHANGE_TYPES.EXTERNAL_CHAIN,
  addressIndex: 10
});
// Returns: "m/84'/0'/0'/0/10"
```

#### `parseDerivationPath(path)`
Parses a derivation path into its components.

**Parameters:**
- `path` (string) - BIP44 derivation path

**Returns:**
- Object with parsed components:
  - `purpose` (number) - Purpose field
  - `coinType` (number) - Coin type field
  - `account` (number) - Account field
  - `change` (number) - Change field
  - `addressIndex` (number) - Address index field

**Throws:**
- `Error` - If path format is invalid

#### `isValidBitcoinPath(path)`
Validates if a derivation path is valid for Bitcoin.

**Parameters:**
- `path` (string) - Derivation path to validate

**Returns:**
- `boolean` - True if valid Bitcoin path, false otherwise

#### `getNetworkByCoinType(coinType)`
Gets network configuration by BIP44 coin type.

**Parameters:**
- `coinType` (number) - BIP44 coin type (0 for mainnet, 1 for testnet)

**Returns:**
- Object with network configuration

**Throws:**
- `Error` - If coin type is not supported

#### `validateAndGetNetwork(network)`
Validates and returns network configuration.

**Parameters:**
- `network` (string) - Network identifier ('main' or 'test')

**Returns:**
- Object with validated network configuration

**Throws:**
- `Error` - If network is not supported

#### `getNetworkConfiguration(network)`
Gets complete network configuration with all settings.

**Parameters:**
- `network` (string) - Network identifier ('main' or 'test')

**Returns:**
- Object with complete network configuration including:
  - Version bytes
  - Address prefixes
  - BIP44 coin type
  - Network metadata

### Network Configuration Structure

Each network configuration includes:

```javascript
{
  name: string,           // Human-readable name
  symbol: string,         // Currency symbol
  coinType: number,       // BIP44 coin type
  bech32Prefix: string,   // Bech32 address prefix
  legacyPrefix: string,   // Legacy address prefix
  p2shPrefix: string,     // P2SH address prefix
  network: string,        // Network identifier
  versions: {             // Version bytes object
    P2PKH_ADDRESS: number,
    P2SH_ADDRESS: number,
    WIF_PRIVATE_KEY: number,
    EXTENDED_PUBLIC_KEY: number,
    EXTENDED_PRIVATE_KEY: number
  }
}
```

### Usage Patterns

#### Standard Receiving Address
```javascript
const receivingPath = generateDerivationPath({
  purpose: BIP_PURPOSES.NATIVE_SEGWIT,
  coinType: BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET,
  account: 0,
  change: BIP44_CONSTANTS.CHANGE_TYPES.EXTERNAL_CHAIN,
  addressIndex: 0
});
// "m/84'/0'/0'/0/0"
```

#### Change Address
```javascript
const changePath = generateDerivationPath({
  purpose: BIP_PURPOSES.NATIVE_SEGWIT,
  coinType: BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET,
  account: 0,
  change: BIP44_CONSTANTS.CHANGE_TYPES.INTERNAL_CHAIN,
  addressIndex: 0
});
// "m/84'/0'/0'/1/0"
```

#### Testnet Address
```javascript
const testnetPath = generateDerivationPath({
  purpose: BIP_PURPOSES.NATIVE_SEGWIT,
  coinType: BIP44_CONSTANTS.COIN_TYPES.BITCOIN_TESTNET,
  account: 0,
  change: 0,
  addressIndex: 0
});
// "m/84'/1'/0'/0/0"
```

### Security Notes

- **Hardened Derivation** - Account, coin type, and purpose levels use hardened derivation for security
- **Network Validation** - All functions validate network parameters
- **Constant-Time Operations** - Where applicable, operations use constant-time algorithms
- **Input Sanitization** - All inputs are thoroughly validated

### Error Codes

- `INVALID_NETWORK` - Network parameter is invalid
- `INVALID_COIN_TYPE` - Coin type not supported
- `INVALID_DERIVATION_PATH` - Path format is incorrect
- `INVALID_PURPOSE` - BIP purpose not recognized
- `INDEX_OUT_OF_RANGE` - Index exceeds valid range