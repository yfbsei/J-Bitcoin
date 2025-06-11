# Custodial Wallet

A modern, secure Bitcoin custodial wallet implementation with hierarchical deterministic (HD) key derivation, comprehensive transaction support, and advanced cryptographic features. Built for modern Bitcoin standards with SegWit and Taproot support only.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Modern Bitcoin Standards](#modern-bitcoin-standards)
- [Address Types](#address-types)
- [Transaction Support](#transaction-support)
- [Examples](#examples)
- [API Reference](#api-reference)
- [Security Features](#security-features)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## Features

### 🔐 **Hierarchical Deterministic (HD) Wallets**
- **BIP32/BIP39/BIP44** - Full HD wallet implementation with mnemonic support
- **Deterministic Address Generation** - Reproducible addresses from seed phrases
- **Multi-Account Support** - Organize funds across multiple accounts
- **Change Address Management** - Automatic change address generation

### 🏛️ **Modern Address Types**
- **Native SegWit (P2WPKH)** - BIP84 compliant with reduced fees
- **Taproot (P2TR)** - BIP86 with enhanced privacy and efficiency
- **No Legacy Support** - Clean, modern implementation without legacy bloat

### 🔏 **Advanced Signature Support**
- **ECDSA Signatures** - Standard Bitcoin signatures for SegWit inputs
- **Schnorr Signatures** - BIP340 compliant for Taproot inputs (64-byte efficiency)
- **Algorithm Detection** - Automatic selection based on address type
- **Mixed Transactions** - Support for both signature types in same transaction

### ⚡ **Comprehensive Transaction Support**
- **Transaction Builder** - Fluent API for building complex transactions
- **Taproot Transactions** - Full BIP341 support with script path spending
- **Batch Payments** - Efficient multi-recipient transactions
- **Fee Estimation** - Smart fee calculation with Taproot optimizations
- **UTXO Management** - Integrated UTXO tracking and validation

### 🛡️ **Security Features**
- **Secure Memory Management** - Automatic cleanup of sensitive data
- **Input Validation** - Comprehensive validation throughout
- **Error Handling** - Standardized error codes and detailed context
- **Production Warnings** - Security alerts for sensitive operations

## Installation

```bash
npm install j-bitcoin
```

**Requirements:**
- Node.js 16.0.0 or higher
- ES modules support

## Quick Start

### Creating a New Wallet

```javascript
import { CustodialWalletFactory } from 'j-bitcoin/wallet/custodial';

// Generate new wallet with mnemonic
const [mnemonic, wallet] = CustodialWalletFactory.generateRandom('main');
console.log('Mnemonic:', mnemonic);
console.log('Master Address:', wallet.masterKeys.address);

// Derive addresses
const segwitAddr = wallet.deriveReceivingAddress(0, 'segwit');
const taprootAddr = wallet.deriveReceivingAddress(0, 'taproot');

console.log('SegWit Address:', segwitAddr.address);
console.log('Taproot Address:', taprootAddr.address);
```

### Restoring from Mnemonic

```javascript
// Restore wallet from existing mnemonic
const wallet = CustodialWalletFactory.fromMnemonic(
    'main',
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    { passphrase: '' }
);

console.log('Wallet restored successfully');
console.log('Network:', wallet.network);
console.log('Features:', wallet.features);
```

## Modern Bitcoin Standards

### Supported BIP Standards

| BIP | Description | Status |
|-----|-------------|--------|
| **BIP32** | Hierarchical Deterministic Wallets | ✅ Full Support |
| **BIP39** | Mnemonic Seed Phrases | ✅ Full Support |
| **BIP44** | Multi-Account HD Wallets | ✅ Full Support |
| **BIP84** | Native SegWit Derivation | ✅ Full Support |
| **BIP86** | Taproot Derivation | ✅ Full Support |
| **BIP141** | Segregated Witness | ✅ Full Support |
| **BIP340** | Schnorr Signatures | ✅ Full Support |
| **BIP341** | Taproot Script Spending | ✅ Full Support |

### Address Type Comparison

```javascript
// Fee efficiency comparison
const feeComparison = wallet.transactionManager.estimateTransaction(2, 2, 'taproot');
console.log('Taproot Input Size:', feeComparison.inputSize, 'bytes'); // 57 bytes
console.log('SegWit Input Size:', 68, 'bytes'); // 11 bytes savings per input

// Address generation
const addresses = {
    segwit: wallet.deriveChildKey(0, 0, 0, 'segwit'),   // bc1q...
    taproot: wallet.deriveChildKey(0, 0, 0, 'taproot')  // bc1p...
};
```

## Address Types

### SegWit (P2WPKH) - Default

```javascript
// Generate SegWit address
const segwitAddr = wallet.deriveReceivingAddress(0, 'segwit');
console.log({
    address: segwitAddr.address,     // bc1q...
    type: segwitAddr.type,           // 'p2wpkh'
    path: segwitAddr.path,           // m/44'/0'/0'/0/0
    witnessProgram: segwitAddr.witnessProgram
});
```

### Taproot (P2TR) - Most Efficient

```javascript
// Generate Taproot address
const taprootAddr = wallet.deriveReceivingAddress(0, 'taproot');
console.log({
    address: taprootAddr.address,         // bc1p...
    type: taprootAddr.type,               // 'p2tr'
    tweakedPublicKey: taprootAddr.tweakedPublicKey
});

// Generate Taproot with script path
const scriptAddr = wallet.deriveTaprootAddress(0, 0, 1, [
    Buffer.from('multisig script'),
    Buffer.from('timelock script')
]);
console.log('Script Commitment:', scriptAddr.scriptCommitment.toString('hex'));
```

## Transaction Support

### Simple Payment Transaction

```javascript
async function createPayment() {
    // Create transaction builder
    const tx = wallet.createTransaction({ feeRate: 15 });
    
    // Add inputs
    tx.addInput({
        txid: 'abc123...',
        vout: 0,
        value: 100000,
        addressType: 'segwit'
    });
    
    // Add outputs
    tx.addOutput('bc1q...recipient...', 50000);
    
    // Build and sign
    const unsignedTx = tx.build();
    const signedTx = await wallet.signTransaction(unsignedTx, [utxo]);
    
    console.log('Transaction signed successfully');
    return signedTx;
}
```

### Taproot Transaction with Schnorr

```javascript
async function createTaprootTransaction() {
    // Build Taproot transaction
    const tx = wallet.createTransaction();
    
    tx.addInput({
        txid: 'def456...',
        vout: 0,
        value: 200000,
        addressType: 'taproot'
    });
    
    tx.addOutput('bc1p...recipient...', 180000);
    
    const unsignedTx = tx.build();
    
    // Sign with Schnorr signatures (BIP340/341)
    const signedTx = await wallet.signTaprootTransaction(unsignedTx, [taprootUtxo], {
        sighashType: 0x00, // SIGHASH_DEFAULT for Taproot
    });
    
    console.log('Taproot transaction signed with Schnorr signatures');
    return signedTx;
}
```

### Batch Payment Transaction

```javascript
async function createBatchPayment() {
    const recipients = [
        { address: 'bc1q...alice...', amount: 25000 },
        { address: 'bc1p...bob...', amount: 30000 },
        { address: 'bc1q...charlie...', amount: 20000 }
    ];
    
    const batchTx = wallet.transactionManager.buildBatchTransaction(
        utxos,
        recipients,
        { 
            feeRate: 20,
            changeAddressType: 'taproot' 
        }
    );
    
    const signedTx = await wallet.signTransaction(batchTx, utxos);
    
    console.log(`Batch payment to ${recipients.length} recipients`);
    console.log(`Total sent: ${recipients.reduce((sum, r) => sum + r.amount, 0)} sats`);
    
    return signedTx;
}
```

### Advanced Taproot Script Path

```javascript
async function createScriptPathSpending() {
    // Create script leaves
    const scripts = [
        Buffer.from('OP_CHECKSIG script'),
        Buffer.from('2-of-2 multisig script'),
        Buffer.from('timelock script')
    ];
    
    // Generate script commitment address
    const scriptAddr = wallet.deriveTaprootAddress(0, 0, 1, scripts);
    
    // Create merkle tree
    const merkleTree = wallet.createTaprootMerkleTree(scripts);
    
    console.log('Script Address:', scriptAddr.address);
    console.log('Merkle Root:', merkleTree.getRoot().toString('hex'));
    
    // Later: spend using script path
    const scriptSpendTx = await wallet.signTaprootTransaction(tx, [scriptUtxo], {
        scriptPath: scripts[0],
        leafHash: merkleTree.getLeafHash(0)
    });
    
    return scriptSpendTx;
}
```

## API Reference

### CustodialWallet Class

#### Constructor

```javascript
new CustodialWallet(network, masterKeys, options)
```

**Parameters:**
- `network` (string): Network type ('main' or 'test')
- `masterKeys` (Object): Master key information containing hdKey, keypair, and address
- `options` (Object): Optional configuration

#### Core Methods

##### `deriveChildKey(account, change, index, addressType)`

Derives a child key using BIP44 hierarchical deterministic derivation.

**Parameters:**
- `account` (number): Account index (typically 0)
- `change` (number): Change index (0=external, 1=internal)
- `index` (number): Address index
- `addressType` (string): 'segwit' or 'taproot'

**Returns:** Object with derived key information

**Example:**
```javascript
const key = wallet.deriveChildKey(0, 0, 5, 'taproot');
console.log(key.path);      // m/44'/0'/0'/0/5
console.log(key.address);   // bc1p...
console.log(key.type);      // p2tr
```

##### `deriveReceivingAddress(index, addressType)`

Convenience method to derive receiving addresses (change=0).

**Parameters:**
- `index` (number): Address index (default: 0)
- `addressType` (string): 'segwit' or 'taproot' (default: 'segwit')

**Returns:** Derived address object

##### `deriveChangeAddress(index, addressType)`

Convenience method to derive change addresses (change=1).

**Parameters:**
- `index` (number): Address index (default: 0)
- `addressType` (string): 'segwit' or 'taproot' (default: 'segwit')

**Returns:** Derived address object

##### `createTransaction(options)`

Creates a transaction builder configured for this wallet.

**Parameters:**
- `options` (Object): Transaction builder options
  - `feeRate` (number): Fee rate in sat/vbyte
  - `rbfEnabled` (boolean): Enable Replace-by-Fee

**Returns:** TransactionBuilder instance

##### `signTransaction(transaction, utxos, options)`

Signs a complete transaction with all its inputs.

**Parameters:**
- `transaction` (Object): Transaction to sign
- `utxos` (Array): UTXOs being spent
- `options` (Object): Signing options

**Returns:** Promise resolving to signed transaction

##### `signTaprootTransaction(transaction, utxos, options)`

Signs a Taproot transaction with Schnorr signatures (BIP340/341).

**Parameters:**
- `transaction` (Object): Taproot transaction to sign
- `utxos` (Array): Taproot UTXOs being spent
- `options` (Object): Taproot signing options
  - `sighashType` (number): Signature hash type (default: 0x00)
  - `scriptPath` (Buffer): Script path for spending (optional)
  - `leafHash` (Buffer): Leaf hash for script validation (optional)

**Returns:** Promise resolving to signed Taproot transaction

##### `deriveTaprootAddress(account, change, index, scripts)`

Creates a Taproot address with optional script path for complex spending.

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
  - `passphrase` (string): Optional BIP39 passphrase

**Returns:** Array with [mnemonic, wallet]

**Example:**
```javascript
const [mnemonic, wallet] = CustodialWalletFactory.generateRandom('main', {
    wordCount: 12,
    passphrase: 'my-secure-passphrase'
});
```

#### `fromMnemonic(network, mnemonic, options)`

Creates wallet from BIP39 mnemonic phrase.

**Parameters:**
- `network` (string): 'main' or 'test'
- `mnemonic` (string): BIP39 mnemonic phrase
- `options` (Object):
  - `passphrase` (string): Optional BIP39 passphrase

**Returns:** CustodialWallet instance

#### `fromPrivateKey(network, privateKey, options)`

Creates wallet from master private key.

**Parameters:**
- `network` (string): 'main' or 'test'
- `privateKey` (Buffer|string): Master private key
- `options` (Object): Additional options

**Returns:** CustodialWallet instance

### TransactionManager Class

Handles transaction building and fee estimation.

#### `estimateTransaction(inputCount, outputCount, inputType)`

Estimates transaction size and fees for different address types.

**Parameters:**
- `inputCount` (number): Number of inputs
- `outputCount` (number): Number of outputs
- `inputType` (string): 'segwit' or 'taproot'

**Returns:** Object with size estimation details

**Example:**
```javascript
const estimate = wallet.transactionManager.estimateTransaction(2, 2, 'taproot');
console.log('Virtual Size:', estimate.vsize);
console.log('Taproot Savings:', 68 - estimate.inputSize, 'bytes per input');
```

#### `calculateFee(vsize, feeRate)`

Calculates transaction fee based on virtual size.

**Parameters:**
- `vsize` (number): Virtual size in bytes
- `feeRate` (number): Fee rate in sat/vbyte

**Returns:** Object with fee calculation details

#### `buildPaymentTransaction(utxos, outputs, options)`

Builds a simple payment transaction with automatic change handling.

**Parameters:**
- `utxos` (Array): Input UTXOs
- `outputs` (Array): Output destinations
- `options` (Object): Transaction options

**Returns:** Built transaction object

#### `buildBatchTransaction(utxos, recipients, options)`

Builds a batch payment transaction for multiple recipients.

**Parameters:**
- `utxos` (Array): Input UTXOs
- `recipients` (Array): Array of {address, amount} objects
- `options` (Object): Transaction options

**Returns:** Built batch transaction object

### SignatureManager Class

Handles signature operations for different address types.

#### `signTransactionInput(messageHash, privateKey, inputType, options)`

Signs a transaction input with appropriate algorithm.

**Parameters:**
- `messageHash` (Buffer): 32-byte message hash
- `privateKey` (Buffer): 32-byte private key
- `inputType` (string): Input type ('segwit', 'taproot')
- `options` (Object): Additional options for Taproot

**Returns:** Promise resolving to signature object

#### `signECDSA(messageHash, privateKey)`

Signs with ECDSA (SegWit inputs).

#### `signSchnorr(messageHash, privateKey, options)`

Signs with Schnorr (Taproot inputs).

#### `verify(signature, messageHash, publicKey, signatureType)`

Verifies a signature with appropriate algorithm.

## Security Features

### Memory Management

```javascript
// Automatic cleanup when done
try {
    const wallet = CustodialWalletFactory.generateRandom('main');
    // Use wallet...
} finally {
    wallet.cleanup(); // Secure memory cleanup
}
```

### Error Handling

```javascript
// Comprehensive error handling
try {
    const key = wallet.deriveChildKey(0, 0, 1, 'taproot');
} catch (error) {
    switch (error.code) {
        case 'DERIVATION_FAILED':
            // Handle derivation errors
            break;
        case 'UNSUPPORTED_ADDRESS_TYPE':
            // Handle unsupported address type
            break;
        default:
            // Handle other errors
            break;
    }
}
```

### Production Warnings

```javascript
// Security warnings in development
if (process.env.NODE_ENV !== 'production') {
    console.warn('⚠️  Custodial wallet created - ensure proper key management');
}
```

## Error Handling

### Error Codes

The library uses standardized error codes for different failure types:

```javascript
export const ERROR_CODES = {
    INVALID_NETWORK: 'INVALID_NETWORK',
    INVALID_MNEMONIC: 'INVALID_MNEMONIC',
    DERIVATION_FAILED: 'DERIVATION_FAILED',
    SIGNING_FAILED: 'SIGNING_FAILED',
    TRANSACTION_BUILD_FAILED: 'TRANSACTION_BUILD_FAILED',
    TRANSACTION_SIGNING_FAILED: 'TRANSACTION_SIGNING_FAILED',
    UTXO_VALIDATION_FAILED: 'UTXO_VALIDATION_FAILED',
    TAPROOT_SIGNING_ERROR: 'TAPROOT_SIGNING_ERROR',
    UNSUPPORTED_ADDRESS_TYPE: 'UNSUPPORTED_ADDRESS_TYPE'
};
```

### CustodialWalletError

All library errors inherit from `CustodialWalletError`:

```javascript
try {
    const wallet = CustodialWalletFactory.generateRandom('invalid-network');
} catch (error) {
    if (error instanceof CustodialWalletError) {
        console.log('Error code:', error.code);
        console.log('Error message:', error.message);
        console.log('Error details:', error.details);
        console.log('Timestamp:', error.timestamp);
    }
}
```

## Best Practices

### Address Generation

```javascript
// ✅ Use Taproot for new transactions (most efficient)
const taprootAddr = wallet.deriveReceivingAddress(0, 'taproot');

// ✅ Use SegWit for compatibility
const segwitAddr = wallet.deriveReceivingAddress(0, 'segwit');

// ✅ Organize addresses by purpose
const addresses = {
    receiving: wallet.deriveReceivingAddress(index, 'taproot'),
    change: wallet.deriveChangeAddress(index, 'taproot')
};
```

### Transaction Building

```javascript
// ✅ Use appropriate fee rates
const feeRates = {
    low: 5,      // Low priority (1-6 hours)
    normal: 15,  // Normal priority (30-60 minutes)
    high: 50     // High priority (next block)
};

// ✅ Estimate fees before building
const estimate = wallet.transactionManager.estimateTransaction(2, 2, 'taproot');
const fee = wallet.transactionManager.calculateFee(estimate.vsize, feeRates.normal);

// ✅ Handle change addresses properly
const changeAddr = wallet.deriveChangeAddress(0, 'taproot');
```

### Security

```javascript
// ✅ Always cleanup sensitive data
function handleWallet() {
    const [mnemonic, wallet] = CustodialWalletFactory.generateRandom('main');
    
    try {
        // Use wallet operations...
        return results;
    } finally {
        wallet.cleanup(); // Always cleanup
    }
}

// ✅ Validate inputs
try {
    const key = wallet.deriveChildKey(account, change, index, type);
} catch (error) {
    if (error.code === 'VALIDATION_FAILED') {
        console.error('Invalid parameters:', error.details);
    }
}

// ✅ Use proper error handling
async function signTransaction(tx, utxos) {
    try {
        return await wallet.signTransaction(tx, utxos);
    } catch (error) {
        switch (error.code) {
            case 'UTXO_VALIDATION_FAILED':
                console.error('Invalid UTXO data');
                break;
            case 'TRANSACTION_SIGNING_FAILED':
                console.error('Signing failed:', error.message);
                break;
            default:
                console.error('Unexpected error:', error);
        }
        throw error;
    }
}
```

### Performance

```javascript
// ✅ Cache derived addresses
const addressCache = new Map();
function getCachedAddress(account, change, index, type) {
    const key = `${account}-${change}-${index}-${type}`;
    if (!addressCache.has(key)) {
        addressCache.set(key, wallet.deriveChildKey(account, change, index, type));
    }
    return addressCache.get(key);
}

// ✅ Use batch operations for multiple recipients
const batchTx = wallet.transactionManager.buildBatchTransaction(utxos, recipients);

// ✅ Prefer Taproot for efficiency
const taprootEstimate = wallet.transactionManager.estimateTransaction(2, 2, 'taproot');
const segwitEstimate = wallet.transactionManager.estimateTransaction(2, 2, 'segwit');
const savings = segwitEstimate.inputSize - taprootEstimate.inputSize;
console.log(`Taproot saves ${savings} bytes per input`);
```

## Compatibility

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

## License

ISC License - see LICENSE file for details.