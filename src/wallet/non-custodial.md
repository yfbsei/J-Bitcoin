# Non-Custodial Wallet

A comprehensive Bitcoin non-custodial wallet implementation using Threshold Signature Scheme (TSS) for distributed key management, featuring full support for Legacy, SegWit, and Taproot addresses with advanced security and proper signature algorithms.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Threshold Cryptography](#threshold-cryptography)
- [Address Types](#address-types)
- [Examples](#examples)
- [API Reference](#api-reference)
- [Security Features](#security-features)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)
- [Contributing](#contributing)

## Features

### 🔐 **Threshold Signature Scheme (TSS)**
- **Distributed Key Generation** - No single point of failure with Joint Verifiable Random Secret Sharing (JVRSS)
- **t-of-n Threshold Schemes** - Configurable schemes like 2-of-3, 3-of-5, 5-of-7 up to 50 participants
- **No Trusted Dealer** - Completely trustless setup without central key generation
- **Share Distribution** - Secure distribution of secret shares across multiple entities or devices

### 🏛️ **Multi-Address Type Support**
- **Legacy (P2PKH)** - BIP44 compatible with maximum compatibility
- **Nested SegWit (P2SH-P2WPKH)** - BIP49 for backward compatibility
- **Native SegWit (P2WPKH)** - BIP84 for optimal fees
- **Taproot (P2TR)** - BIP86 with key path and script path spending

### 🔏 **Advanced Signature Support**
- **Threshold ECDSA** for Legacy and SegWit inputs with distributed signing
- **Threshold Schnorr Signatures** for Taproot inputs (BIP340) with distributed keys
- **Mixed Transactions** with automatic algorithm detection
- **Script Path Spending** with threshold merkle tree support
- **BIP341 Compliance** for proper Taproot signature hash computation

### 🛡️ **Enhanced Security Features**
- **Rate Limiting** and DoS protection with configurable thresholds
- **Secure Memory Management** with multi-pass clearing
- **Timing Attack Prevention** with constant-time operations
- **Entropy Validation** for cryptographic quality assurance
- **Nonce Reuse Prevention** with comprehensive history tracking
- **Signature Canonicalization** for malleability protection

### ⚡ **Transaction Management**
- **Threshold Transaction Building** with integrated UTXO management
- **Fee Estimation** optimized for threshold signatures
- **Replace-by-Fee (RBF)** support with threshold approval
- **Batch Operations** for efficient multi-party transactions
- **Script Path Execution** for complex spending conditions

## Installation

```bash
npm install non-custodial-wallet
```

## Quick Start

### Creating a New Threshold Wallet

```javascript
import { NonCustodialWalletFactory } from 'non-custodial-wallet';

// Generate a new 2-of-3 threshold wallet
const { wallet, thresholdInfo } = NonCustodialWalletFactory.generateRandom(
    'main',    // network
    3,         // total participants
    2          // required signers
);

console.log('Threshold Info:', thresholdInfo);
console.log('Participant IDs:', thresholdInfo.participantIds);
console.log('Share Distribution:', thresholdInfo.shareDistribution);
```

### Restoring from Threshold Shares

```javascript
// Restore wallet from distributed shares
const shares = [
    '5f4a8b2c...', // Share from participant 1
    '9e7d3f1a...', // Share from participant 2
    'a3c8e5b9...'  // Share from participant 3
];

const wallet = NonCustodialWalletFactory.fromThresholdShares(
    'main',
    shares,
    { groupSize: 3, threshold: 2 }
);

console.log('Wallet restored from threshold shares');
```

### Generating Addresses

```javascript
// Generate different address types
const addresses = {
    legacy: wallet.deriveChildKey(0, 0, 0, 'legacy'),
    segwit: wallet.deriveChildKey(0, 0, 1, 'segwit'),
    taproot: wallet.deriveChildKey(0, 0, 2, 'taproot')
};

console.log('Legacy Address:', addresses.legacy.address);
console.log('SegWit Address:', addresses.segwit.address);
console.log('Taproot Address:', addresses.taproot.address);
```

## Threshold Cryptography

### How Threshold Signatures Work

The non-custodial wallet uses threshold cryptography to distribute control over Bitcoin private keys across multiple participants. This provides several key advantages:

- **No Single Point of Failure**: No single entity can spend funds alone
- **Distributed Trust**: Requires cooperation of multiple parties
- **Enhanced Security**: Even if some shares are compromised, funds remain secure
- **Flexible Schemes**: Supports various t-of-n configurations

### Threshold Scheme Examples

```javascript
// 2-of-3 scheme: Any 2 of 3 participants can sign
const wallet_2_3 = NonCustodialWalletFactory.generateRandom('main', 3, 2);

// 3-of-5 scheme: Any 3 of 5 participants can sign  
const wallet_3_5 = NonCustodialWalletFactory.generateRandom('main', 5, 3);

// 5-of-7 scheme: Any 5 of 7 participants can sign
const wallet_5_7 = NonCustodialWalletFactory.generateRandom('main', 7, 5);
```

### Security Considerations

The security level depends on your threshold ratio:

- **High Security (≥75% ratio)**: 3-of-4, 4-of-5, 6-of-8
- **Medium Security (≥50% ratio)**: 2-of-3, 3-of-5, 5-of-9
- **Lower Security (<50% ratio)**: 2-of-5, 3-of-7 (not recommended)

## Address Types

### Legacy Addresses (P2PKH)

```javascript
const legacyAddr = wallet.deriveChildKey(0, 0, 0, 'legacy');
console.log('Legacy:', legacyAddr.address); // Starts with '1'
```

**Features:**
- Maximum compatibility with all Bitcoin software
- Higher transaction fees due to larger size
- Uses threshold ECDSA signatures

### SegWit Addresses (P2WPKH)

```javascript
const segwitAddr = wallet.deriveChildKey(0, 0, 0, 'segwit');
console.log('SegWit:', segwitAddr.address); // Starts with 'bc1q'
```

**Features:**
- ~40% lower fees compared to Legacy
- Better transaction malleability protection
- Uses threshold ECDSA signatures

### Taproot Addresses (P2TR)

```javascript
const taprootAddr = wallet.deriveChildKey(0, 0, 0, 'taproot');
console.log('Taproot:', taprootAddr.address); // Starts with 'bc1p'
```

**Features:**
- Lowest transaction fees and best privacy
- Uses threshold Schnorr signatures (BIP340)
- Supports complex script conditions
- Enhanced privacy through key and script indistinguishability

## Examples

### Basic Threshold Transaction

```javascript
async function createThresholdTransaction() {
    // Create a 2-of-3 threshold wallet
    const { wallet } = NonCustodialWalletFactory.generateRandom('main', 3, 2);
    
    // Create transaction builder
    const txBuilder = wallet.createTransaction({
        feeRate: 15 // sat/vbyte
    });
    
    // Add inputs (UTXOs)
    txBuilder.addInput({
        txid: 'a1b2c3d4e5f6...',
        vout: 0,
        value: 100000, // satoshis
        address: 'bc1q...',
        addressType: 'segwit'
    });
    
    // Add outputs
    txBuilder.addOutput({
        address: 'bc1p...', // Recipient address
        value: 50000
    });
    
    // Add change output
    txBuilder.addOutput({
        address: 'bc1q...', // Change address
        value: 45000 // 100000 - 50000 - 5000 (fee)
    });
    
    // Build unsigned transaction
    const unsignedTx = txBuilder.build();
    
    // Sign with threshold signatures (requires 2 of 3 participants)
    const signedTx = await wallet.signTransaction(unsignedTx, [{
        txid: 'a1b2c3d4e5f6...',
        vout: 0,
        value: 100000,
        addressType: 'segwit'
    }]);
    
    console.log('Transaction signed with threshold signatures');
    return signedTx;
}
```

### Taproot Transaction with Schnorr Signatures

```javascript
async function createTaprootTransaction() {
    const { wallet } = NonCustodialWalletFactory.generateRandom('main', 3, 2);
    
    // Create Taproot UTXOs
    const taprootUtxos = [
        {
            txid: 'f7e8d9c0b1a2...',
            vout: 0,
            value: 200000,
            address: 'bc1p...', // Taproot address
            addressType: 'taproot'
        }
    ];
    
    // Create transaction for Taproot inputs
    const txBuilder = wallet.createTransaction();
    
    txBuilder.addInput(taprootUtxos[0]);
    txBuilder.addOutput({
        address: 'bc1p...', // Taproot recipient
        value: 180000
    });
    
    const unsignedTx = txBuilder.build();
    
    // Sign with threshold Schnorr signatures (BIP340/341)
    const signedTx = await wallet.signTaprootTransaction(unsignedTx, taprootUtxos, {
        sighashType: 0x00, // SIGHASH_DEFAULT for Taproot
        scriptPath: null   // Key path spending
    });
    
    console.log('Taproot transaction signed with threshold Schnorr signatures');
    console.log('BIP341 Compliant:', signedTx.bip341Compliant);
    
    return signedTx;
}
```

### Script Path Spending

```javascript
async function createScriptPathSpending() {
    const { wallet } = NonCustodialWalletFactory.generateRandom('main', 3, 2);
    
    // Create scripts for merkle tree
    const scripts = [
        Buffer.from('OP_CHECKSIG'), // Simple signature check
        Buffer.from('OP_CHECKSIGVERIFY OP_CHECKLOCKTIMEVERIFY'), // Time-locked
        Buffer.from('OP_HASH160 <hash> OP_EQUAL') // Hash preimage
    ];
    
    // Create Taproot address with script path
    const scriptAddress = wallet.deriveTaprootAddress(0, 0, 0, scripts);
    
    console.log('Script Path Address:', scriptAddress.address);
    console.log('Merkle Root:', scriptAddress.merkleRoot);
    console.log('Can Use Script Path:', scriptAddress.canUseScriptPath);
    
    // Create merkle tree for script execution
    const merkleTree = wallet.createTaprootMerkleTree(scripts);
    console.log('Merkle tree created with', scripts.length, 'leaves');
    
    return { scriptAddress, merkleTree };
}
```

### Mixed Transaction (ECDSA + Schnorr)

```javascript
async function createMixedTransaction() {
    const { wallet } = NonCustodialWalletFactory.generateRandom('main', 3, 2);
    
    // UTXOs with different address types
    const mixedUtxos = [
        {
            txid: 'legacy123...',
            vout: 0,
            value: 50000,
            addressType: 'legacy' // Will use threshold ECDSA
        },
        {
            txid: 'segwit456...',
            vout: 1,
            value: 75000,
            addressType: 'segwit' // Will use threshold ECDSA
        },
        {
            txid: 'taproot789...',
            vout: 0,
            value: 100000,
            addressType: 'taproot' // Will use threshold Schnorr
        }
    ];
    
    const txBuilder = wallet.createTransaction();
    
    // Add all inputs
    mixedUtxos.forEach(utxo => txBuilder.addInput(utxo));
    
    // Add output
    txBuilder.addOutput({
        address: 'bc1p...',
        value: 200000 // Total: 225000 - 25000 fee
    });
    
    const unsignedTx = txBuilder.build();
    
    // Sign with mixed algorithms (automatic detection)
    const signedTx = await wallet.signTransaction(unsignedTx, mixedUtxos);
    
    console.log('Mixed transaction signed:');
    console.log('- Legacy input: threshold ECDSA signature');
    console.log('- SegWit input: threshold ECDSA signature');
    console.log('- Taproot input: threshold Schnorr signature');
    
    return signedTx;
}
```

### Batch Operations

```javascript
async function batchThresholdOperations() {
    const { wallet } = NonCustodialWalletFactory.generateRandom('main', 5, 3);
    
    // Generate multiple addresses efficiently
    const addresses = [];
    for (let i = 0; i < 10; i++) {
        addresses.push(wallet.deriveChildKey(0, 0, i, 'taproot'));
    }
    
    console.log(`Generated ${addresses.length} Taproot addresses`);
    
    // Batch transaction creation
    const recipients = [
        { address: 'bc1p...recipient1', amount: 10000 },
        { address: 'bc1p...recipient2', amount: 15000 },
        { address: 'bc1p...recipient3', amount: 20000 }
    ];
    
    const sourceUtxo = {
        txid: 'source123...',
        vout: 0,
        value: 100000,
        addressType: 'taproot'
    };
    
    const txBuilder = wallet.createTransaction();
    txBuilder.addInput(sourceUtxo);
    
    let totalSent = 0;
    recipients.forEach(recipient => {
        txBuilder.addOutput({
            address: recipient.address,
            value: recipient.amount
        });
        totalSent += recipient.amount;
    });
    
    // Add change
    const estimatedFee = 15000;
    const changeAmount = sourceUtxo.value - totalSent - estimatedFee;
    
    if (changeAmount > 1000) {
        const changeAddress = wallet.deriveChildKey(0, 1, 0, 'taproot');
        txBuilder.addOutput({
            address: changeAddress.address,
            value: changeAmount
        });
    }
    
    const unsignedTx = txBuilder.build();
    const signedTx = await wallet.signTaprootTransaction(unsignedTx, [sourceUtxo]);
    
    console.log(`Batch transaction created for ${recipients.length} recipients`);
    console.log(`Total sent: ${totalSent / 100000000} BTC`);
    
    return signedTx;
}
```

### Backup and Recovery

```javascript
async function backupAndRecovery() {
    // Create original wallet
    const { wallet, thresholdInfo } = NonCustodialWalletFactory.generateRandom('main', 3, 2);
    
    // Create backup data
    const backupData = {
        network: wallet.network,
        version: wallet.version,
        thresholdInfo: wallet.thresholdInfo,
        shares: wallet.shares, // Threshold shares
        created: Date.now()
    };
    
    console.log('Backup created');
    console.log('Store these shares securely across different locations:');
    backupData.shares.forEach((share, index) => {
        console.log(`Participant ${index + 1}: ${share}`);
    });
    
    // Simulate wallet loss and recovery
    wallet.cleanup(); // Destroy original wallet
    
    // Restore from backup
    const restoredWallet = NonCustodialWalletFactory.fromBackup(backupData);
    
    // Verify restoration
    const originalAddress = wallet.deriveChildKey(0, 0, 0, 'taproot').address;
    const restoredAddress = restoredWallet.deriveChildKey(0, 0, 0, 'taproot').address;
    
    console.log('Recovery successful:', originalAddress === restoredAddress);
    
    return { backupData, restoredWallet };
}
```

## API Reference

### NonCustodialWallet Class

#### Constructor

```javascript
new NonCustodialWallet(network, groupSize, threshold, options)
```

**Parameters:**
- `network` (string): Network type ('main' or 'test')
- `groupSize` (number): Total number of participants in threshold scheme
- `threshold` (number): Minimum number of participants required for operations
- `options` (Object): Additional configuration options

#### Methods

##### `deriveChildKey(account, change, index, addressType)`

Derives a child key for different address types using threshold cryptography.

**Parameters:**
- `account` (number): Account index (default: 0)
- `change` (number): Change index (0 for receiving, 1 for change)
- `index` (number): Address index
- `addressType` (string): Address type ('legacy', 'segwit', 'taproot')

**Returns:** Object with threshold key information

```javascript
const childKey = wallet.deriveChildKey(0, 0, 5, 'taproot');
console.log(childKey.address);      // Taproot address
console.log(childKey.shares);       // Threshold shares for this key
console.log(childKey.thresholdInfo); // Threshold configuration
```

##### `signTransaction(transaction, utxos, options)`

Signs a transaction using threshold signatures with automatic algorithm detection.

**Parameters:**
- `transaction` (Object): Transaction to sign
- `utxos` (Array): UTXOs being spent
- `options` (Object): Signing options

**Returns:** Promise resolving to signed transaction

##### `signTaprootTransaction(transaction, utxos, options)`

Signs a Taproot transaction with threshold Schnorr signatures (BIP340/341).

**Parameters:**
- `transaction` (Object): Taproot transaction to sign
- `utxos` (Array): Taproot UTXOs being spent
- `options` (Object): Taproot signing options
  - `sighashType` (number): Signature hash type (default: 0x00)
  - `scriptPath` (Buffer): Script path for spending (optional)
  - `leafHash` (Buffer): Leaf hash for script validation (optional)

**Returns:** Promise resolving to signed Taproot transaction

##### `createTransaction(options)`

Creates a transaction builder configured for threshold signatures.

**Parameters:**
- `options` (Object): Transaction builder options

**Returns:** TransactionBuilder instance

##### `deriveTaprootAddress(account, change, index, scripts)`

Creates a Taproot address with optional script path for threshold spending.

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
- `version` (string): Wallet version
- `thresholdInfo` (Object): Threshold configuration
- `securityMetrics` (Object): Security statistics
- `features` (Array): Supported features
- `type` (string): Wallet type

##### `cleanup()`

Securely clears sensitive data from memory.

### NonCustodialWalletFactory Class

Factory methods for creating wallet instances from various sources.

#### `generateRandom(network, groupSize, threshold, options)`

Generates a new random threshold wallet with distributed key generation.

**Parameters:**
- `network` (string): 'main' or 'test'
- `groupSize` (number): Total number of participants
- `threshold` (number): Minimum number of participants required
- `options` (Object): Additional options

**Returns:** Object with wallet instance and threshold information

#### `fromThresholdShares(network, shares, thresholdConfig, options)`

Creates wallet from existing threshold shares.

**Parameters:**
- `network` (string): 'main' or 'test'
- `shares` (Array): Array of threshold shares
- `thresholdConfig` (Object): Threshold configuration
- `options` (Object): Additional options

**Returns:** NonCustodialWallet instance

#### `fromBackup(backupData, options)`

Restores wallet from backup data.

**Parameters:**
- `backupData` (Object): Backup data containing threshold information
- `options` (Object): Restoration options

**Returns:** NonCustodialWallet instance

### ThresholdSignatureManager Class

Handles threshold signature operations for different address types.

#### `signTransactionInput(messageHash, thresholdShares, inputType, options)`

Signs a transaction input with threshold signature appropriate for the input type.

**Parameters:**
- `messageHash` (Buffer): 32-byte message hash
- `thresholdShares` (Array): Threshold shares for signing
- `inputType` (string): Input type ('p2pkh', 'p2wpkh', 'p2tr', etc.)
- `options` (Object): Additional options for Taproot

**Returns:** Promise resolving to signature object

#### `signThresholdECDSA(messageHash, thresholdShares)`

Signs with threshold ECDSA (Legacy/SegWit inputs).

#### `signThresholdSchnorr(messageHash, thresholdShares, options)`

Signs with threshold Schnorr (Taproot inputs).

#### `signTaprootInput(transaction, inputIndex, thresholdShares, options)`

Signs a complete Taproot transaction input with proper BIP341 signature hash.

#### `verifyThresholdSignature(messageHash, signature, publicKey, signatureType)`

Verifies a threshold signature with appropriate algorithm.

### ThresholdTransactionManager Class

Utilities for threshold transaction management and fee estimation.

#### `createBuilder(network, options)`

Creates a configured TransactionBuilder instance for threshold operations.

#### `estimateTransactionSize(inputCount, outputCount, inputType, thresholdInfo)`

Estimates transaction size for threshold signatures including overhead.

**Parameters:**
- `inputCount` (number): Number of inputs
- `outputCount` (number): Number of outputs
- `inputType` (string): Input type for size calculation
- `thresholdInfo` (Object): Threshold configuration for overhead calculation

**Returns:** Object with size estimation details including threshold overhead

#### `calculateFee(vsize, feeRate, priority)`

Calculates transaction fee for threshold transactions.

**Parameters:**
- `vsize` (number): Virtual transaction size
- `feeRate` (number): Fee rate in sat/vbyte
- `priority` (string): Priority level

**Returns:** Object with fee calculation details

## Security Features

### 🛡️ Threshold Security
- **Distributed Trust**: No single point of failure
- **Configurable Schemes**: Support for various t-of-n configurations
- **Share Validation**: Entropy validation for cryptographic quality
- **Secure Distribution**: Safe share distribution mechanisms

### 🔒 Advanced Protection
- **Rate Limiting**: Prevents DoS attacks with configurable limits
- **Memory Security**: Multi-pass secure memory clearing
- **Timing Attack Prevention**: Constant-time operations where applicable
- **Nonce Management**: Comprehensive nonce reuse prevention
- **Signature Canonicalization**: Protection against malleability attacks

### 🎲 Cryptographic Quality
- **Entropy Validation**: Shannon entropy calculation with minimum thresholds
- **Random Source Validation**: Validation of cryptographic randomness
- **Share Quality Checks**: Detection of weak or predictable shares
- **Cross-Implementation Compatibility**: Validation against test vectors

### ⏱️ DoS Protection
- **Execution Timeouts**: Maximum operation time limits
- **Complexity Limits**: Protection against computationally expensive attacks
- **Resource Monitoring**: Tracking of computational resources
- **Automatic Cleanup**: Prevention of resource leaks

### 🔍 Comprehensive Validation
- **Input Sanitization**: Thorough validation of all inputs
- **Network Parameter Verification**: Validation of network-specific parameters
- **Address Format Checking**: Proper address format validation
- **Derivation Path Validation**: BIP44 compliance checking

## Error Handling

### Error Codes

The library uses standardized error codes for different failure types:

```javascript
const ERROR_CODES = {
    INVALID_NETWORK: 'INVALID_NETWORK',
    INVALID_THRESHOLD_PARAMS: 'INVALID_THRESHOLD_PARAMS',
    VALIDATION_FAILED: 'VALIDATION_FAILED',
    RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
    OPERATION_TIMEOUT: 'OPERATION_TIMEOUT',
    INSUFFICIENT_ENTROPY: 'INSUFFICIENT_ENTROPY',
    MEMORY_CLEAR_FAILED: 'MEMORY_CLEAR_FAILED',
    SHARE_GENERATION_FAILED: 'SHARE_GENERATION_FAILED',
    SIGNATURE_ERROR: 'SIGNATURE_ERROR',
    THRESHOLD_SIGNATURE_ERROR: 'THRESHOLD_SIGNATURE_ERROR',
    NONCE_REUSE_DETECTED: 'NONCE_REUSE_DETECTED',
    PARTICIPANT_COUNT_TOO_HIGH: 'PARTICIPANT_COUNT_TOO_HIGH',
    NO_SHARES_AVAILABLE: 'NO_SHARES_AVAILABLE',
    PRIVATE_KEY_RECONSTRUCTION_FAILED: 'PRIVATE_KEY_RECONSTRUCTION_FAILED'
};
```

### NonCustodialWalletError

All library errors inherit from `NonCustodialWalletError`:

```javascript
try {
    const wallet = NonCustodialWalletFactory.generateRandom('main', 3, 2);
} catch (error) {
    if (error instanceof NonCustodialWalletError) {
        console.log('Error code:', error.code);
        console.log('Error message:', error.message);
        console.log('Error details:', error.details);
        console.log('Timestamp:', error.timestamp);
    }
}
```

### Common Error Handling Patterns

```javascript
// Threshold parameter validation
try {
    const wallet = new NonCustodialWallet('main', 10, 15); // Invalid: threshold > group size
} catch (error) {
    if (error.code === 'INVALID_THRESHOLD_PARAMS') {
        console.log('Invalid threshold configuration');
        console.log('Group size:', error.details.groupSize);
        console.log('Threshold:', error.details.threshold);
    }
}

// Rate limit handling
try {
    for (let i = 0; i < 1000; i++) {
        wallet.deriveChildKey(0, 0, i, 'taproot');
    }
} catch (error) {
    if (error.code === 'RATE_LIMIT_EXCEEDED') {
        console.log('Too many requests, waiting...');
        await new Promise(resolve => setTimeout(resolve, 1000));
        // Retry operation
    }
}

// Threshold signature error handling
try {
    const signedTx = await wallet.signTaprootTransaction(tx, utxos);
} catch (error) {
    switch (error.code) {
        case 'THRESHOLD_SIGNATURE_ERROR':
            console.log('Threshold signing failed:', error.details);
            break;
        case 'NONCE_REUSE_DETECTED':
            console.log('CRITICAL: Nonce reuse detected');
            break;
        case 'NO_SHARES_AVAILABLE':
            console.log('No threshold shares available for signing');
            break;
        default:
            console.log('Unknown error:', error.message);
            break;
    }
}
```

## Best Practices

### 1. Threshold Scheme Selection

```javascript
// ✅ Recommended threshold schemes
const schemes = {
    high_security: { groupSize: 5, threshold: 4 },    // 80% required
    medium_security: { groupSize: 3, threshold: 2 },  // 67% required  
    basic_security: { groupSize: 7, threshold: 4 }    // 57% required
};

// ❌ Avoid low security ratios
const weak_scheme = { groupSize: 5, threshold: 2 };  // Only 40% required
```

### 2. Secure Share Management

```javascript
// ✅ Distribute shares securely
const { wallet, thresholdInfo } = NonCustodialWalletFactory.generateRandom('main', 3, 2);

// Store shares in different secure locations
const shares = wallet.shares;
shares.forEach((share, index) => {
    // Store each share with different custodians/devices
    console.log(`Share ${index + 1} → Secure Location ${index + 1}`);
    secureStorage.store(`participant_${index + 1}`, share);
});

// ❌ Don't store all shares together
// localStorage.setItem('all_shares', JSON.stringify(shares)); // Dangerous!
```

### 3. Address Type Selection

```javascript
// ✅ Use Taproot for new applications (best privacy + efficiency)
const newAddress = wallet.deriveChildKey(0, 0, 0, 'taproot');

// ✅ Use SegWit for broad compatibility
const compatAddress = wallet.deriveChildKey(0, 0, 0, 'segwit');

// ⚠️ Only use Legacy if absolutely necessary
const legacyAddress = wallet.deriveChildKey(0, 0, 0, 'legacy');
```

### 4. Transaction Signing

```javascript
// ✅ Always verify transaction details before signing
async function secureTransactionSigning(transaction, utxos) {
    // Verify transaction contents
    const summary = analyzTransaction(transaction);
    console.log('Transaction Summary:', summary);
    
    // Check for suspicious patterns
    if (summary.totalOutput > summary.totalInput * 0.9) {
        console.warn('⚠️  High output ratio detected');
    }
    
    // Sign with appropriate method
    if (utxos.every(utxo => utxo.addressType === 'taproot')) {
        return await wallet.signTaprootTransaction(transaction, utxos);
    } else {
        return await wallet.signTransaction(transaction, utxos);
    }
}
```

### 5. Fee Management

```javascript
// ✅ Use appropriate fee rates with threshold overhead consideration
const feeRates = {
    urgent: 50,   // High priority
    normal: 15,   // Standard
    economy: 5    // Low priority
};

// Account for threshold signature overhead
const sizeEstimate = ThresholdTransactionManager.estimateTransactionSize(
    2, // inputs
    2, // outputs
    'p2tr', // input type
    { groupSize: 3, threshold: 2 } // threshold info
);

const feeEstimate = ThresholdTransactionManager.calculateFee(
    sizeEstimate.vsize,
    feeRates.normal,
    'normal'
);

console.log(`Estimated fee: ${feeEstimate.totalFee} sats`);
console.log(`Threshold overhead: ${sizeEstimate.thresholdOverhead} bytes`);
```

### 6. Error Handling

```javascript
// ✅ Always handle specific threshold errors
async function robustThresholdOperation() {
    try {
        const signedTx = await wallet.signTaprootTransaction(tx, utxos);
        return signedTx;
    } catch (error) {
        switch (error.code) {
            case 'RATE_LIMIT_EXCEEDED':
                await delay(1000);
                return await wallet.signTaprootTransaction(tx, utxos);
                
            case 'THRESHOLD_SIGNATURE_ERROR':
                console.error('Threshold signing failed:', error.details);
                throw new Error('Unable to generate threshold signature');
                
            case 'NO_SHARES_AVAILABLE':
                console.error('Missing threshold shares');
                throw new Error('Wallet not properly initialized');
                
            case 'NONCE_REUSE_DETECTED':
                console.error('CRITICAL SECURITY VIOLATION');
                throw new Error('Nonce reuse detected - operation aborted');
                
            default:
                console.error('Unknown error:', error.message);
                throw error;
        }
    }
}
```

### 7. Memory Management

```javascript
// ✅ Always cleanup sensitive data
async function secureWalletUsage() {
    const { wallet } = NonCustodialWalletFactory.generateRandom('main', 3, 2);
    
    try {
        // Use wallet for operations
        const address = wallet.deriveChildKey(0, 0, 0, 'taproot');
        const tx = await wallet.signTransaction(transaction, utxos);
        
        return tx;
    } finally {
        // Always cleanup, even if operations fail
        wallet.cleanup();
        console.log('Sensitive data cleared from memory');
    }
}
```

### 8. Backup Strategy

```javascript
// ✅ Implement comprehensive backup strategy
function createSecureBackup(wallet) {
    const backupData = {
        network: wallet.network,
        version: wallet.version,
        thresholdInfo: wallet.thresholdInfo,
        shares: wallet.shares,
        created: Date.now(),
        checksum: calculateChecksum(wallet.shares)
    };
    
    // Split backup across multiple secure locations
    const locations = [
        'hardware_wallet_1',
        'encrypted_cloud_storage',
        'physical_paper_backup',
        'trusted_custodian'
    ];
    
    locations.forEach((location, index) => {
        const partialBackup = {
            ...backupData,
            location,
            partIndex: index,
            totalParts: locations.length
        };
        
        secureStore(location, partialBackup);
    });
    
    return backupData;
}
```

## Configuration

### Security Configuration

```javascript
const SECURITY_CONFIG = {
    MAX_PARTICIPANTS: 50,
    MAX_VALIDATIONS_PER_SECOND: 500,
    VALIDATION_TIMEOUT_MS: 5000,
    MEMORY_CLEAR_PASSES: 3,
    MIN_ENTROPY_THRESHOLD: 0.7,
    NONCE_HISTORY_SIZE: 1000,
    RATE_LIMIT_CLEANUP_INTERVAL: 60000
};
```

### Threshold Configuration

```javascript
// Recommended threshold configurations for different use cases
const THRESHOLD_CONFIGS = {
    personal: { groupSize: 3, threshold: 2 },      // Personal wallet backup
    corporate: { groupSize: 5, threshold: 3 },     // Corporate treasury
    enterprise: { groupSize: 7, threshold: 5 },    // High-security enterprise
    consortium: { groupSize: 9, threshold: 6 }     // Multi-party consortium
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
- Threshold shares are cached for performance
- Automatic cleanup prevents memory leaks
- Configurable cache limits based on participant count
- Secure memory clearing with multiple passes

### Signature Performance
- Threshold ECDSA signing: ~5-15ms per input (depends on group size)
- Threshold Schnorr signing: ~8-25ms per input (depends on group size)
- Batch operations are optimized for multiple participants
- Share reconstruction overhead scales with threshold size

### Transaction Size Impact
- Legacy threshold signatures: +10 bytes overhead per input
- SegWit threshold signatures: +10 bytes overhead per input  
- Taproot threshold signatures: +15 bytes overhead per input
- Script path spending: Additional merkle proof data

### Fee Optimization
- Taproot provides ~11% size reduction vs SegWit
- SegWit provides ~40% reduction vs Legacy
- Threshold overhead is minimal (10-15 bytes per input)
- Batch transactions optimize per-output costs

## Advanced Topics

### Custom Threshold Schemes

```javascript
// Create custom threshold configurations for specific needs
class CustomThresholdScheme {
    static createMultiTier(config) {
        // Example: Different thresholds for different amounts
        return {
            smallAmounts: { groupSize: 3, threshold: 2 },   // < 0.1 BTC
            mediumAmounts: { groupSize: 5, threshold: 3 },  // 0.1-1 BTC  
            largeAmounts: { groupSize: 7, threshold: 5 }    // > 1 BTC
        };
    }
    
    static createTimeBasedScheme(config) {
        // Example: Lower threshold after time delay
        return {
            immediate: { groupSize: 5, threshold: 4 },      // 4-of-5 immediately
            delayed: { groupSize: 5, threshold: 3 }         // 3-of-5 after 24h
        };
    }
}
```

### Integration with Hardware Wallets

```javascript
// Example integration with hardware wallet for share storage
async function integrateHardwareWallet(wallet) {
    const shares = wallet.shares;
    
    // Store shares on different hardware devices
    for (let i = 0; i < shares.length; i++) {
        const deviceId = `hardware_wallet_${i + 1}`;
        
        try {
            await hardwareWallet.connect(deviceId);
            await hardwareWallet.storeThresholdShare(shares[i], {
                walletId: wallet.getSummary().id,
                participantIndex: i,
                threshold: wallet.thresholdInfo.threshold,
                groupSize: wallet.thresholdInfo.groupSize
            });
            
            console.log(`Share ${i + 1} stored on ${deviceId}`);
        } catch (error) {
            console.error(`Failed to store share on ${deviceId}:`, error);
        }
    }
}
```

### Multi-Signature vs Threshold Signatures

| Feature | Multi-Signature | Threshold Signatures |
|---------|----------------|---------------------|
| **Setup** | On-chain setup required | Off-chain setup |
| **Privacy** | Reveals scheme (2-of-3) | Looks like single signature |
| **Size** | Larger transactions | Standard signature size |
| **Fees** | Higher fees | Standard fees |
| **Flexibility** | Limited schemes | Any t-of-n scheme |
| **Recovery** | Blockchain visible | Private recovery |

## Troubleshooting

### Common Issues

#### Issue: "Rate limit exceeded"
**Cause:** Too many operations in short time period
**Solution:**
```javascript
// Add delays between operations
await delay(100); // 100ms delay
const result = await wallet.deriveChildKey(0, 0, index, 'taproot');
```

#### Issue: "No shares available"
**Cause:** Wallet not properly initialized with threshold shares
**Solution:**
```javascript
// Verify wallet has shares
if (!wallet.shares || wallet.shares.length === 0) {
    throw new Error('Wallet missing threshold shares');
}

// Or restore from backup
const wallet = NonCustodialWalletFactory.fromThresholdShares(network, shares, config);
```

#### Issue: "Threshold signature failed"
**Cause:** Insufficient or invalid threshold shares
**Solution:**
```javascript
// Verify threshold configuration
if (availableShares.length < wallet.thresholdInfo.threshold) {
    throw new Error(`Need ${wallet.thresholdInfo.threshold} shares, have ${availableShares.length}`);
}

// Validate share quality
availableShares.forEach((share, index) => {
    if (!NonCustodialSecurityUtils.validateShareEntropy(share)) {
        console.warn(`Share ${index} has low entropy`);
    }
});
```

#### Issue: "Nonce reuse detected"
**Cause:** Same message signed multiple times
**Solution:**
```javascript
// Use unique auxiliary randomness for each signature
const auxRand = randomBytes(32);
const signature = await wallet.signTaprootTransaction(tx, utxos, { auxRand });
```

### Debug Mode

```javascript
// Enable detailed logging for debugging
const wallet = new NonCustodialWallet('test', 3, 2, {
    debug: true,
    logLevel: 'verbose'
});

// Monitor security metrics
setInterval(() => {
    const metrics = wallet.getSummary().securityMetrics;
    console.log('Security Metrics:', metrics);
}, 30000);
```

## Contributing

### Development Setup

```bash
# Clone repository
git clone https://github.com/your-org/non-custodial-wallet.git
cd non-custodial-wallet

# Install dependencies
npm install

# Run tests
npm test

# Run threshold-specific tests
npm run test:threshold

# Run Taproot tests
npm run test:taproot
```

### Testing

```javascript
// Example test for threshold functionality
describe('NonCustodialWallet', () => {
    test('should create 2-of-3 threshold wallet', async () => {
        const { wallet } = NonCustodialWalletFactory.generateRandom('test', 3, 2);
        
        expect(wallet.thresholdInfo.groupSize).toBe(3);
        expect(wallet.thresholdInfo.threshold).toBe(2);
        expect(wallet.shares).toHaveLength(3);
        
        wallet.cleanup();
    });
    
    test('should sign Taproot transaction with threshold Schnorr', async () => {
        const { wallet } = NonCustodialWalletFactory.generateRandom('test', 3, 2);
        
        const tx = createMockTaprootTransaction();
        const utxos = createMockTaprootUtxos();
        
        const signedTx = await wallet.signTaprootTransaction(tx, utxos);
        
        expect(signedTx.taprootSigned).toBe(true);
        expect(signedTx.bip341Compliant).toBe(true);
        
        wallet.cleanup();
    });
});
```

### Code Style

- Use ES6+ features and async/await
- Follow JSDoc documentation standards
- Implement comprehensive error handling
- Add security warnings for sensitive operations
- Use TypeScript for better type safety (optional)

### Security Considerations for Contributors

- Never log sensitive data (private keys, shares)
- Use constant-time operations for cryptographic comparisons
- Implement proper memory clearing for sensitive data
- Add rate limiting for all public methods
- Validate all inputs thoroughly
- Use secure random number generation

## License

MIT License - see LICENSE file for details.

## Support

For questions and support:
- GitHub Issues: [Report bugs and request features](https://github.com/your-org/non-custodial-wallet/issues)
- Documentation: [Full API documentation](https://docs.your-org.com/non-custodial-wallet)
- Community: [Discord server](https://discord.gg/your-org)

## Changelog

### v3.0.0 (Current)
- ✅ Full refactoring to match custodial wallet patterns
- ✅ Complete Taproot support with BIP340 Schnorr signatures
- ✅ BIP341 compliant signature hash computation
- ✅ Threshold signature scheme for all address types
- ✅ Enhanced security features and validation
- ✅ Comprehensive error handling and documentation

### v2.1.0
- Enhanced input validation and security checks
- Timing attack prevention with constant-time operations
- DoS protection with rate limiting
- Secure memory management
- Nonce reuse prevention

### v1.0.0
- Initial threshold signature implementation
- Basic ECDSA threshold signatures
- Legacy and SegWit address support
- Distributed key generation