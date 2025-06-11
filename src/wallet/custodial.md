# Custodial Wallet

A comprehensive Bitcoin custodial wallet implementation with full support for Legacy, SegWit, and Taproot addresses, featuring enhanced security, proper signature algorithms, and advanced transaction management.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Address Types](#address-types)
- [Examples](#examples)
- [API Reference](#api-reference)
- [Security Features](#security-features)
- [Error Handling](#error-handling)
- [Contributing](#contributing)

## Features

### 🔐 **Multi-Address Type Support**
- **Legacy (P2PKH)** - BIP44 compatible with maximum compatibility
- **Nested SegWit (P2SH-P2WPKH)** - BIP49 for backward compatibility
- **Native SegWit (P2WPKH)** - BIP84 for optimal fees
- **Taproot (P2TR)** - BIP86 for maximum privacy and efficiency

### 🔏 **Advanced Signature Support**
- **ECDSA Signatures** for Legacy and SegWit inputs
- **Schnorr Signatures** for Taproot inputs (BIP340)
- **Mixed Transactions** with automatic algorithm detection
- **Script Path Spending** with merkle tree support

### 🛡️ **Security Features**
- Rate limiting and DoS protection
- Secure memory management
- Entropy validation
- Input sanitization
- Timing attack prevention

### ⚡ **Transaction Management**
- Integrated UTXO management
- Fee estimation and optimization
- Replace-by-Fee (RBF) support
- Batch transaction creation
- Transaction size estimation

## Installation

```bash
npm install custodial-wallet
```

## Quick Start

### Creating a New Wallet

```javascript
import { CustodialWalletFactory } from 'custodial-wallet';

// Generate a new random wallet
const { wallet, mnemonic } = CustodialWalletFactory.generateRandom('main', {
    wordCount: 12,
    storeMnemonic: true
});

console.log('Mnemonic:', mnemonic);
console.log('Wallet created for:', wallet.network);
```

### Restoring from Mnemonic

```javascript
// Restore wallet from existing mnemonic
const wallet = CustodialWalletFactory.fromMnemonic(
    'main', 
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    { passphrase: 'optional_passphrase' }
);
```

### Generating Addresses

```javascript
// Generate different address types
const addresses = {
    legacy: wallet.deriveChildKey(0, 0, 0, 'legacy'),
    segwit: wallet.deriveChildKey(0, 0, 1, 'segwit'),
    taproot: wallet.deriveChildKey(0, 0, 2, 'taproot')
};

console.log('Legacy:', addresses.legacy.address);   // 1...
console.log('SegWit:', addresses.segwit.address);   // bc1q...
console.log('Taproot:', addresses.taproot.address); // bc1p...
```

## Address Types

### Legacy (P2PKH) - BIP44
```javascript
const legacy = wallet.deriveChildKey(0, 0, 0, 'legacy');
// Address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
// Purpose: 44' (BIP44)
// Signature: ECDSA
// Fees: Highest
```

### Nested SegWit (P2SH-P2WPKH) - BIP49
```javascript
const nestedSegwit = wallet.deriveChildKey(0, 0, 0, 'nested-segwit');
// Address: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
// Purpose: 49' (BIP49)
// Signature: ECDSA
// Fees: Medium
```

### Native SegWit (P2WPKH) - BIP84
```javascript
const segwit = wallet.deriveChildKey(0, 0, 0, 'segwit');
// Address: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
// Purpose: 84' (BIP84)
// Signature: ECDSA
// Fees: Low
```

### Taproot (P2TR) - BIP86
```javascript
const taproot = wallet.deriveChildKey(0, 0, 0, 'taproot');
// Address: bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297
// Purpose: 86' (BIP86)
// Signature: Schnorr
// Fees: Lowest
```

## Examples

### Basic Transaction to Taproot Address

```javascript
import { CustodialWalletFactory, TransactionManager } from 'custodial-wallet';

async function sendToTaproot() {
    // Create wallet
    const { wallet } = CustodialWalletFactory.generateRandom('main');
    
    // Generate addresses
    const sender = wallet.deriveChildKey(0, 0, 0, 'segwit');
    const recipient = 'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297';
    
    // Create UTXO (normally from blockchain)
    const utxos = [{
        txid: 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890',
        vout: 0,
        value: 100000000, // 1 BTC
        address: sender.address,
        derivationPath: sender.path,
        type: 'p2wpkh',
        scriptPubKey: Buffer.from('0014' + sender.publicKey.toString('hex').slice(2), 'hex')
    }];
    
    // Build transaction
    const txBuilder = wallet.createTransaction({
        version: 2,
        feeRate: 15,
        rbf: true
    });
    
    // Add input
    txBuilder.addInput({
        txid: utxos[0].txid,
        vout: utxos[0].vout,
        value: utxos[0].value,
        scriptPubKey: utxos[0].scriptPubKey,
        type: utxos[0].type
    });
    
    // Add outputs
    const sendAmount = 50000000; // 0.5 BTC
    const fee = 5000;
    const changeAmount = utxos[0].value - sendAmount - fee;
    
    txBuilder.addOutput({
        address: recipient,
        value: sendAmount
    });
    
    txBuilder.addOutput({
        address: sender.address,
        value: changeAmount
    });
    
    // Build and sign
    const unsignedTx = txBuilder.build();
    const signedTx = await wallet.signTransaction(unsignedTx, utxos);
    
    console.log('Transaction signed successfully!');
    console.log('Signature algorithms used:', signedTx.signingDetails.map(d => d.algorithm));
    
    return signedTx;
}
```

### Advanced Taproot with Script Paths

```javascript
async function taprootWithScripts() {
    const { wallet } = CustodialWalletFactory.generateRandom('main');
    
    // Create script leaves
    const scripts = [
        // Time-lock script
        Buffer.from([
            0x04, 0x80, 0x51, 0x03, 0x00, // 6 months
            0xb1, 0x75, // OP_CHECKLOCKTIMEVERIFY OP_DROP
            0x21, ...Buffer.from(wallet.deriveChildKey(0, 0, 0).publicKey),
            0xac // OP_CHECKSIG
        ]),
        
        // Multi-sig script
        Buffer.from([
            0x52, // OP_2
            0x21, ...Buffer.from(wallet.deriveChildKey(0, 0, 1).publicKey),
            0x21, ...Buffer.from(wallet.deriveChildKey(0, 0, 2).publicKey),
            0x21, ...Buffer.from(wallet.deriveChildKey(0, 0, 3).publicKey),
            0x53, 0xae // OP_3 OP_CHECKMULTISIG
        ])
    ];
    
    // Generate Taproot address with script commitment
    const taprootWithScripts = wallet.generateTaprootAddress(0, 0, 0, scripts);
    
    console.log('Taproot address with scripts:', taprootWithScripts.address);
    console.log('Merkle root:', taprootWithScripts.merkleRoot.toString('hex'));
    console.log('Available spending paths:');
    console.log('- Key path (single signature)');
    console.log('- Script path 1: Time-locked spend');
    console.log('- Script path 2: Multi-signature spend');
    
    return taprootWithScripts;
}
```

### Batch Transaction to Multiple Addresses

```javascript
async function batchTransaction() {
    const { wallet } = CustodialWalletFactory.generateRandom('main');
    
    // Generate multiple recipients
    const recipients = [
        { address: 'bc1p...', amount: 10000000, label: 'Recipient 1' },
        { address: 'bc1q...', amount: 20000000, label: 'Recipient 2' },
        { address: '3...', amount: 15000000, label: 'Recipient 3' }
    ];
    
    // Create source UTXO
    const sourceUtxo = {
        txid: 'batch123456789012345678901234567890123456789012345678901234567890',
        vout: 0,
        value: 200000000, // 2 BTC
        address: wallet.deriveChildKey(0, 0, 0, 'segwit').address,
        derivationPath: wallet.deriveChildKey(0, 0, 0, 'segwit').path,
        type: 'p2wpkh'
    };
    
    // Build batch transaction
    const txBuilder = wallet.createTransaction({ feeRate: 20 });
    
    // Add input
    txBuilder.addInput({
        txid: sourceUtxo.txid,
        vout: sourceUtxo.vout,
        value: sourceUtxo.value,
        type: sourceUtxo.type
    });
    
    // Add all recipient outputs
    let totalSent = 0;
    recipients.forEach(recipient => {
        txBuilder.addOutput({
            address: recipient.address,
            value: recipient.amount
        });
        totalSent += recipient.amount;
    });
    
    // Add change output
    const estimatedFee = 25000;
    const changeAmount = sourceUtxo.value - totalSent - estimatedFee;
    
    if (changeAmount > 1000) {
        const changeAddress = wallet.deriveChildKey(0, 1, 0, 'segwit');
        txBuilder.addOutput({
            address: changeAddress.address,
            value: changeAmount
        });
    }
    
    // Build and sign
    const unsignedTx = txBuilder.build();
    const signedTx = await wallet.signTransaction(unsignedTx, [sourceUtxo]);
    
    console.log(`Batch transaction created for ${recipients.length} recipients`);
    console.log(`Total sent: ${totalSent / 100000000} BTC`);
    
    return signedTx;
}
```

### Fee Optimization Comparison

```javascript
async function feeComparison() {
    const { wallet } = CustodialWalletFactory.generateRandom('main');
    
    const addressTypes = ['legacy', 'segwit', 'taproot'];
    const feeComparisons = [];
    
    for (const addressType of addressTypes) {
        // Estimate transaction size
        const sizeEstimate = TransactionManager.estimateTransactionSize(
            2, // inputs
            2, // outputs
            addressType === 'legacy' ? 'p2pkh' : 
            addressType === 'segwit' ? 'p2wpkh' : 'p2tr'
        );
        
        const feeEstimate = TransactionManager.calculateFee(
            sizeEstimate.vsize,
            15, // sat/vbyte
            'normal'
        );
        
        feeComparisons.push({
            type: addressType,
            vsize: sizeEstimate.vsize,
            fee: feeEstimate.totalFee,
            address: wallet.deriveChildKey(0, 0, 0, addressType).address
        });
    }
    
    console.log('Fee Comparison:');
    feeComparisons.forEach(comparison => {
        console.log(`${comparison.type.toUpperCase()}: ${comparison.fee} sats (${comparison.vsize} vbytes)`);
    });
    
    const legacyFee = feeComparisons.find(c => c.type === 'legacy').fee;
    const taprootFee = feeComparisons.find(c => c.type === 'taproot').fee;
    const savings = legacyFee - taprootFee;
    const savingsPercent = ((savings / legacyFee) * 100).toFixed(1);
    
    console.log(`Taproot saves ${savings} sats (${savingsPercent}%) compared to Legacy`);
    
    return feeComparisons;
}
```

## API Reference

### CustodialWallet Class

#### Constructor

```javascript
new CustodialWallet(network, masterKeys, serializationFormat)
```

**Parameters:**
- `network` (string): Network type ('main' or 'test')
- `masterKeys` (Object): Master key information containing hdKey, keypair, and address
- `serializationFormat` (Object): Optional serialization format configuration

#### Methods

##### `deriveChildKey(account, change, index, addressType)`

Derives a child key using BIP44 hierarchical deterministic derivation.

**Parameters:**
- `account` (number|string): Account index (default: 0)
- `change` (number): Change index - 0 for receiving, 1 for change (default: 0)
- `index` (number): Address index (default: 0)
- `addressType` (string): Address type - 'legacy', 'nested-segwit', 'segwit', 'taproot' (default: 'segwit')

**Returns:** Object containing:
- `path` (string): BIP44 derivation path
- `privateKey` (Buffer): Private key
- `publicKey` (Buffer): Public key
- `address` (string): Bitcoin address
- `extendedKeys` (Object): Extended key information

**Example:**
```javascript
const key = wallet.deriveChildKey(0, 0, 5, 'taproot');
console.log('Address:', key.address);
console.log('Path:', key.path); // m/86'/0'/0'/0/5
```

##### `generateReceiveAddress(account, index)`

Generates a new receiving address (change = 0).

**Parameters:**
- `account` (number|string): Account index (default: 0)
- `index` (number): Address index (default: 0)

**Returns:** Object with address information

##### `generateChangeAddress(account, index)`

Generates a new change address (change = 1).

**Parameters:**
- `account` (number|string): Account index (default: 0)  
- `index` (number): Address index (default: 0)

**Returns:** Object with address information

##### `createTransaction(options)`

Creates a new transaction builder instance.

**Parameters:**
- `options` (Object): Transaction options
  - `version` (number): Transaction version (default: 2)
  - `feeRate` (number): Fee rate in sat/vbyte (default: 10)
  - `rbf` (boolean): Enable Replace-by-Fee (default: true)
  - `priority` (string): Priority level - 'low', 'normal', 'high' (default: 'normal')

**Returns:** TransactionBuilder instance

##### `signTransaction(transaction, utxos)`

Signs a transaction with appropriate signature algorithms.

**Parameters:**
- `transaction` (Object): Unsigned transaction object
- `utxos` (Array): Array of UTXO objects with metadata

**Returns:** Promise resolving to signed transaction object

**UTXO Object Structure:**
```javascript
{
    txid: 'string',           // Transaction ID
    vout: 'number',           // Output index
    value: 'number',          // Value in satoshis
    address: 'string',        // Address
    derivationPath: 'string', // BIP44 path
    type: 'string',           // 'p2pkh', 'p2wpkh', 'p2tr', etc.
    scriptPubKey: 'Buffer',   // Script public key
    sighashType: 'number'     // Optional sighash type for Taproot
}
```

##### `generateTaprootAddress(account, change, index, scripts)`

Generates a Taproot address with optional script tree commitment.

**Parameters:**
- `account` (number): Account index
- `change` (number): Change index
- `index` (number): Address index  
- `scripts` (Array): Optional array of script Buffers for merkle tree

**Returns:** Object with Taproot address and script commitment information

##### `createTaprootMerkleTree(scriptLeaves)`

Creates a Taproot merkle tree for script path spending.

**Parameters:**
- `scriptLeaves` (Array): Array of script Buffers

**Returns:** TaprootMerkleTree instance

##### `getSummary()`

Returns comprehensive wallet summary and statistics.

**Returns:** Object containing:
- `network` (string): Network type
- `masterAddress` (string): Master address
- `derivedKeys` (number): Number of derived keys
- `utxos` (Object): UTXO statistics
- `features` (Array): Supported features
- `version` (string): Wallet version

##### `cleanup()`

Securely clears sensitive data from memory.

### CustodialWalletFactory Class

Factory methods for creating wallet instances from various sources.

#### `generateRandom(network, options)`

Generates a new random wallet with mnemonic.

**Parameters:**
- `network` (string): 'main' or 'test'
- `options` (Object):
  - `wordCount` (number): 12, 15, 18, 21, or 24 (default: 12)
  - `storeMnemonic` (boolean): Store mnemonic in wallet (default: false)
  - `storeSeed` (boolean): Store seed in wallet (default: false)

**Returns:** Object with wallet instance and mnemonic

#### `fromMnemonic(network, mnemonic, options)`

Creates wallet from BIP39 mnemonic phrase.

**Parameters:**
- `network` (string): 'main' or 'test'
- `mnemonic` (string): BIP39 mnemonic phrase
- `options` (Object):
  - `passphrase` (string): Optional BIP39 passphrase
  - `storeMnemonic` (boolean): Store mnemonic in wallet
  - `storeSeed` (boolean): Store seed in wallet

**Returns:** CustodialWallet instance

#### `fromPrivateKey(network, privateKey, options)`

Creates wallet from master private key.

**Parameters:**
- `network` (string): 'main' or 'test'
- `privateKey` (Buffer|string): Master private key
- `options` (Object): Additional options

**Returns:** CustodialWallet instance

#### `fromBackup(backupData, options)`

Restores wallet from backup data.

**Parameters:**
- `backupData` (Object): Backup data containing mnemonic, privateKey, or extendedKey
- `options` (Object): Restoration options

**Returns:** CustodialWallet instance

### SignatureManager Class

Handles signature operations for different address types.

#### `signTransactionInput(messageHash, privateKey, inputType, options)`

Signs a transaction input with appropriate algorithm.

**Parameters:**
- `messageHash` (Buffer): 32-byte message hash
- `privateKey` (Buffer): 32-byte private key
- `inputType` (string): Input type ('p2pkh', 'p2wpkh', 'p2tr', etc.)
- `options` (Object): Additional options for Taproot

**Returns:** Promise resolving to signature object

#### `signECDSA(messageHash, privateKey)`

Signs with ECDSA (Legacy/SegWit inputs).

#### `signSchnorr(messageHash, privateKey, options)`

Signs with Schnorr (Taproot inputs).

#### `signTaprootTransaction(transaction, inputIndex, privateKey, options)`

Signs a complete Taproot transaction with proper BIP341 signature hash.

#### `verifySignature(messageHash, signature, publicKey, signatureType)`

Verifies a signature with appropriate algorithm.

### TransactionManager Class

Utilities for transaction management and fee estimation.

#### `createBuilder(network, options)`

Creates a configured TransactionBuilder instance.

#### `estimateTransactionSize(inputCount, outputCount, inputType)`

Estimates transaction size for fee calculation.

**Parameters:**
- `inputCount` (number): Number of inputs
- `outputCount` (number): Number of outputs
- `inputType` (string): Input type for size calculation

**Returns:** Object with size estimation details

#### `calculateFee(vsize, feeRate, priority)`

Calculates transaction fee.

**Parameters:**
- `vsize` (number): Virtual transaction size
- `feeRate` (number): Fee rate in sat/vbyte
- `priority` (string): Priority level

**Returns:** Object with fee calculation details

## Security Features

### 🛡️ Rate Limiting
Prevents DoS attacks with configurable rate limits:
- Maximum 500 validations per second
- Automatic cleanup of old entries
- Operation-specific limits

### 🔒 Memory Security
Secure handling of sensitive data:
- Multi-pass memory clearing (3 passes)
- Secure buffer overwriting
- Automatic cleanup on wallet destruction

### 🎲 Entropy Validation
Ensures cryptographic quality:
- Shannon entropy calculation
- Minimum entropy threshold (0.7)
- Validation of random data sources

### ⏱️ Timing Attack Prevention
Constant-time operations where applicable:
- Safe comparison functions
- Timing-safe validation
- DoS protection timeouts

### 🔍 Input Validation
Comprehensive input sanitization:
- Network parameter validation
- Address format verification
- Private key validation
- Derivation path checking

## Error Handling

### Error Codes

The library uses standardized error codes for different failure types:

```javascript
const ERROR_CODES = {
    INVALID_NETWORK: 'INVALID_NETWORK',
    INVALID_MASTER_KEYS: 'INVALID_MASTER_KEYS',
    VALIDATION_FAILED: 'VALIDATION_FAILED',
    RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
    OPERATION_TIMEOUT: 'OPERATION_TIMEOUT',
    INSUFFICIENT_ENTROPY: 'INSUFFICIENT_ENTROPY',
    MEMORY_CLEAR_FAILED: 'MEMORY_CLEAR_FAILED',
    DERIVATION_ERROR: 'DERIVATION_ERROR',
    SIGNATURE_ERROR: 'SIGNATURE_ERROR',
    TRANSACTION_ERROR: 'TRANSACTION_ERROR',
    TAPROOT_SIGNING_ERROR: 'TAPROOT_SIGNING_ERROR'
};
```

### CustodialWalletError

All library errors inherit from `CustodialWalletError`:

```javascript
try {
    const wallet = CustodialWalletFactory.fromMnemonic('main', 'invalid mnemonic');
} catch (error) {
    if (error instanceof CustodialWalletError) {
        console.log('Error code:', error.code);
        console.log('Error message:', error.message);
        console.log('Error details:', error.details);
        console.log('Timestamp:', error.timestamp);
    }
}
```

### Common Error Handling Patterns

```javascript
// Rate limit handling
try {
    const key = wallet.deriveChildKey(0, 0, 100, 'taproot');
} catch (error) {
    if (error.code === 'RATE_LIMIT_EXCEEDED') {
        console.log('Too many requests, waiting...');
        await new Promise(resolve => setTimeout(resolve, 1000));
        // Retry operation
    }
}

// Signature error handling
try {
    const signedTx = await wallet.signTransaction(tx, utxos);
} catch (error) {
    if (error.code === 'TAPROOT_SIGNING_ERROR') {
        console.log('Taproot signing failed:', error.details);
        // Handle Taproot-specific error
    } else if (error.code === 'SIGNATURE_ERROR') {
        console.log('General signing error:', error.message);
        // Handle general signature error
    }
}
```

## Configuration

### Security Configuration

```javascript
const SECURITY_CONFIG = {
    MAX_VALIDATIONS_PER_SECOND: 500,
    MAX_CHILD_KEYS: 1000,
    MAX_DERIVATION_DEPTH: 10,
    VALIDATION_TIMEOUT_MS: 5000,
    MEMORY_CLEAR_PASSES: 3,
    MIN_ENTROPY_THRESHOLD: 0.7,
    MIN_CHANGE_AMOUNT: 546,
    RATE_LIMIT_CLEANUP_INTERVAL: 60000
};
```

### Network Configuration

The wallet automatically configures network-specific parameters:

**Mainnet:**
- Legacy addresses start with '1'
- P2SH addresses start with '3'
- SegWit addresses start with 'bc1q'
- Taproot addresses start with 'bc1p'

**Testnet:**
- Legacy addresses start with 'm' or 'n'
- P2SH addresses start with '2'
- SegWit addresses start with 'tb1q'
- Taproot addresses start with 'tb1p'

## Performance Considerations

### Memory Usage
- Derived keys are cached for performance
- Automatic cleanup prevents memory leaks
- Configurable cache limits

### Transaction Signing
- ECDSA signing: ~1-5ms per input
- Schnorr signing: ~2-8ms per input
- Batch operations are optimized

### Fee Optimization
- Taproot provides ~11% size reduction
- SegWit provides ~40% reduction vs Legacy
- Batch transactions optimize per-output costs

## Best Practices

### 1. Mnemonic Storage
```javascript
// ❌ Don't store mnemonics in plain text
const wallet = CustodialWalletFactory.fromMnemonic('main', mnemonic, {
    storeMnemonic: true // Dangerous in production
});

// ✅ Use secure storage or don't store at all
const wallet = CustodialWalletFactory.fromMnemonic('main', mnemonic, {
    storeMnemonic: false // Secure approach
});
```

### 2. Address Type Selection
```javascript
// ✅ Use Taproot for new applications
const addr = wallet.deriveChildKey(0, 0, 0, 'taproot');

// ✅ Use SegWit for compatibility
const addr = wallet.deriveChildKey(0, 0, 0, 'segwit');

// ⚠️ Only use Legacy if absolutely necessary
const addr = wallet.deriveChildKey(0, 0, 0, 'legacy');
```

### 3. Fee Management
```javascript
// ✅ Use appropriate fee rates
const feeRates = {
    urgent: 50,   // High priority
    normal: 15,   // Standard
    economy: 5    // Low priority
};

const txBuilder = wallet.createTransaction({
    feeRate: feeRates.normal
});
```

### 4. Error Handling
```javascript
// ✅ Always handle specific errors
try {
    const signedTx = await wallet.signTransaction(tx, utxos);
} catch (error) {
    switch (error.code) {
        case 'RATE_LIMIT_EXCEEDED':
            // Handle rate limiting
            break;
        case 'TAPROOT_SIGNING_ERROR':
            // Handle Taproot issues
            break;
        default:
            // Handle other errors
            break;
    }
}
```

### 5. Resource Cleanup
```javascript
// ✅ Always cleanup when done
try {
    // Use wallet...
} finally {
    wallet.cleanup(); // Secure memory cleanup
}
```

## Compatibility

### BIP Standards
- **BIP32**: Hierarchical Deterministic Wallets
- **BIP39**: Mnemonic code for generating deterministic keys
- **BIP44**: Multi-Account Hierarchy for Deterministic Wallets
- **BIP49**: Derivation scheme for P2WPKH-nested-in-P2SH
- **BIP84**: Derivation scheme for P2WPKH
- **BIP86**: Key Derivation for Single Key P2TR Outputs
- **BIP141**: Segregated Witness (Consensus layer)
- **BIP143**: Transaction Signature Verification for Version 0 Witness Program
- **BIP340**: Schnorr Signatures for secp256k1
- **BIP341**: Taproot: SegWit version 1 spending rules
- **BIP342**: Validation of Taproot Scripts

### Node.js Compatibility
- Node.js 16.0.0 or higher
- ES modules support required
- Native crypto module usage

### Browser Compatibility
- Modern browsers with WebCrypto API
- ES2020 support required
- No Node.js-specific dependencies in browser build

## Testing

### Running Tests
```bash
npm test                 # Run all tests
npm run test:unit        # Unit tests only
npm run test:integration # Integration tests
npm run test:security    # Security tests
```

### Test Coverage
The library maintains >95% test coverage across:
- Address generation
- Transaction signing
- Error handling
- Security features
- BIP compliance

## Contributing

### Development Setup
```bash
git clone https://github.com/your-org/custodial-wallet.git
cd custodial-wallet
npm install
npm run build
npm test
```

### Code Style
- ESLint configuration provided
- Prettier for formatting
- JSDoc for documentation
- TypeScript definitions included

### Security Review
All contributions undergo security review:
- Static analysis with CodeQL
- Dependency vulnerability scanning
- Manual security review for crypto operations
- Test vector validation

## License

MIT License - see LICENSE file for details.

## Support

<!-- ### Documentation
- API Documentation: [docs/api.md](docs/api.md)
- Examples: [examples/](examples/)
- Security Guide: [docs/security.md](docs/security.md) -->

### Community
- GitHub Issues: Bug reports and feature requests
- Discussions: Design and implementation questions
- Security Issues: security@your-domain.com

### Professional Support
Enterprise support available for:
- Custom integration assistance
- Security auditing
- Performance optimization
- Training and consultation

---

**⚠️ Security Notice:** This is cryptographic software handling financial keys. Always review the code, use in testnet first, and follow security best practices. The authors are not responsible for any financial losses.