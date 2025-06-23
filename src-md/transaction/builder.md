# Transaction Builder

Comprehensive Bitcoin transaction builder with support for all address types, advanced scripting, and Taproot features.

## Description

This module provides a complete transaction builder for creating Bitcoin transactions with support for Legacy, SegWit, and Taproot inputs and outputs. It includes automatic fee calculation, UTXO management integration, signature hash computation, and comprehensive validation. The builder supports complex scenarios including multi-signature, threshold signatures, and script path spending.

## Example

```javascript
import { TransactionBuilder } from 'j-bitcoin';

// Create new transaction builder
const builder = new TransactionBuilder({
    network: 'main',
    feeRate: 10, // satoshis per vbyte
    enableRBF: true, // Replace-by-Fee
    dustThreshold: 546
});

// Add inputs (UTXOs to spend)
builder.addInput({
    txid: 'previous_transaction_id',
    vout: 0,
    value: 100000, // satoshis
    scriptPubKey: Buffer.from('script_pubkey_hex', 'hex'),
    type: 'p2wpkh', // SegWit input
    publicKey: Buffer.from('public_key_hex', 'hex')
});

// Add Legacy input
builder.addInput({
    txid: 'legacy_transaction_id',
    vout: 1,
    value: 50000,
    scriptPubKey: Buffer.from('76a914...88ac', 'hex'), // P2PKH script
    type: 'p2pkh',
    address: '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'
});

// Add Taproot input
builder.addInput({
    txid: 'taproot_transaction_id',
    vout: 0,
    value: 200000,
    scriptPubKey: Buffer.from('5120...', 'hex'), // P2TR script
    type: 'p2tr',
    internalKey: Buffer.from('internal_key_32_bytes', 'hex'),
    merkleRoot: Buffer.from('merkle_root_32_bytes', 'hex') // null for key-path
});

// Add outputs
builder.addOutput({
    address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', // SegWit address
    value: 75000
});

builder.addOutput({
    address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', // Legacy address
    value: 25000
});

// Add change output (automatically calculated)
builder.addChangeOutput('bc1qchange_address_here');

// Build transaction
const transaction = builder.build();
console.log('Transaction:', transaction);
console.log('Transaction Size:', transaction.vsize, 'vbytes');
console.log('Total Fee:', transaction.fee, 'satoshis');
console.log('Fee Rate:', transaction.feeRate, 'sat/vbyte');

// Sign transaction
const privateKeys = {
    'previous_transaction_id:0': 'private_key_wif_1',
    'legacy_transaction_id:1': 'private_key_wif_2',
    'taproot_transaction_id:0': 'taproot_private_key'
};

const signedTx = await builder.sign(privateKeys);
console.log('Signed Transaction:', signedTx.toHex());

// Validate transaction
const validation = builder.validate();
console.log('Transaction Valid:', validation.isValid);
console.log('Validation Details:', validation.details);

// Advanced: Batch payment transaction
const batchBuilder = new TransactionBuilder({ network: 'main' });

const payments = [
    { address: 'bc1q...', value: 10000 },
    { address: '1A1z...', value: 15000 },
    { address: 'bc1p...', value: 20000 } // Taproot
];

batchBuilder.addBatchPayments(payments);
batchBuilder.addInput(largeUtxo);
batchBuilder.addChangeOutput(changeAddress);

const batchTx = batchBuilder.build();
console.log('Batch Payment Transaction:', batchTx);
```

## API Reference

### Classes

#### `TransactionBuilder`
Main transaction builder class with comprehensive Bitcoin transaction support.

**Constructor:**
```javascript
new TransactionBuilder(options = {})
```

**Options:**
- `network` (string) - Network type ('main' or 'test')
- `feeRate` (number) - Fee rate in satoshis per vbyte (default: 1)
- `enableRBF` (boolean) - Enable Replace-by-Fee (default: false)
- `dustThreshold` (number) - Dust threshold in satoshis (default: 546)
- `lockTime` (number) - Transaction lock time (default: 0)
- `version` (number) - Transaction version (default: 2)
- `maxFeeRate` (number) - Maximum allowed fee rate (default: 1000)
- `estimateWitnessSize` (boolean) - Estimate witness sizes (default: true)

**Instance Methods:**

##### `builder.addInput(input)`
Adds an input (UTXO) to the transaction.

**Parameters:**
- `input` (Object) - Input specification
  - `txid` (string) - Previous transaction ID
  - `vout` (number) - Output index in previous transaction
  - `value` (number) - Value in satoshis
  - `scriptPubKey` (Buffer) - Previous output script
  - `type` (string) - Input type ('p2pkh', 'p2sh', 'p2wpkh', 'p2wsh', 'p2tr')
  - `address` (string) - Previous output address (optional)
  - `sequence` (number) - Input sequence number (default: 0xfffffffe for RBF)
  - `witnessScript` (Buffer) - Witness script for P2WSH (optional)
  - `redeemScript` (Buffer) - Redeem script for P2SH (optional)
  - `internalKey` (Buffer) - Taproot internal key (for P2TR)
  - `merkleRoot` (Buffer) - Taproot merkle root (for P2TR script path)
  - `controlBlock` (Buffer) - Taproot control block (for script path)

**Returns:**
- `TransactionBuilder` - Builder instance for chaining

##### `builder.addOutput(output)`
Adds an output to the transaction.

**Parameters:**
- `output` (Object) - Output specification
  - `address` (string) - Destination address
  - `value` (number) - Value in satoshis
  - `script` (Buffer) - Custom output script (alternative to address)

**Returns:**
- `TransactionBuilder` - Builder instance for chaining

##### `builder.addChangeOutput(address, minValue = null)`
Adds a change output with automatically calculated value.

**Parameters:**
- `address` (string) - Change address
- `minValue` (number) - Minimum change value (dust threshold)

**Returns:**
- `TransactionBuilder` - Builder instance for chaining

##### `builder.addBatchPayments(payments)`
Adds multiple outputs for batch payments.

**Parameters:**
- `payments` (Array<Object>) - Array of payment objects
  - `address` (string) - Destination address
  - `value` (number) - Value in satoshis

**Returns:**
- `TransactionBuilder` - Builder instance for chaining

##### `builder.setFeeRate(feeRate)`
Sets the fee rate for the transaction.

**Parameters:**
- `feeRate` (number) - Fee rate in satoshis per vbyte

**Returns:**
- `TransactionBuilder` - Builder instance for chaining

##### `builder.build()`
Builds the transaction with fee calculation and validation.

**Returns:**
- Object with transaction data:
  - `transaction` (Object) - Raw transaction object
  - `hex` (string) - Transaction hex string
  - `txid` (string) - Transaction ID
  - `size` (number) - Transaction size in bytes
  - `vsize` (number) - Virtual size for fee calculation
  - `weight` (number) - Transaction weight
  - `fee` (number) - Total fee in satoshis
  - `feeRate` (number) - Effective fee rate
  - `inputTotal` (number) - Total input value
  - `outputTotal` (number) - Total output value
  - `changeValue` (number) - Change output value

**Throws:**
- `TransactionBuilderError` - If transaction building fails

##### `builder.sign(privateKeys, options = {})`
Signs the transaction with provided private keys.

**Parameters:**
- `privateKeys` (Object|Array) - Private keys for signing
  - Object format: `{ 'txid:vout': 'private_key_wif' }`
  - Array format: `['private_key_1', 'private_key_2']` (order matches inputs)
- `options` (Object) - Signing options
  - `sighashType` (number) - Signature hash type (default: 0x01)
  - `schnorrSigning` (boolean) - Use Schnorr for Taproot (default: true)
  - `deterministicNonces` (boolean) - Use deterministic nonces (default: true)

**Returns:**
- Object with signed transaction:
  - `transaction` (Object) - Signed transaction
  - `hex` (string) - Signed transaction hex
  - `complete` (boolean) - Whether all inputs are signed
  - `signatures` (Array) - Signature information for each input

##### `builder.validate()`
Validates the built transaction for correctness.

**Returns:**
- Object with validation result:
  - `isValid` (boolean) - Overall validation result
  - `errors` (Array<string>) - Validation errors
  - `warnings` (Array<string>) - Validation warnings
  - `details` (Object) - Detailed validation information
    - `inputsValid` (boolean) - Input validation
    - `outputsValid` (boolean) - Output validation
    - `feeValid` (boolean) - Fee validation
    - `scriptValid` (boolean) - Script validation
    - `sizeValid` (boolean) - Size validation

##### `builder.estimateSize()`
Estimates transaction size before building.

**Returns:**
- Object with size estimates:
  - `size` (number) - Estimated size in bytes
  - `vsize` (number) - Estimated virtual size
  - `weight` (number) - Estimated weight
  - `fee` (number) - Estimated fee

##### `builder.clone()`
Creates a copy of the transaction builder.

**Returns:**
- `TransactionBuilder` - New builder instance with same configuration

### Transaction Types Support

#### Legacy Transactions (P2PKH/P2SH)
```javascript
builder.addInput({
    type: 'p2pkh',
    // Standard P2PKH input
});

builder.addInput({
    type: 'p2sh',
    redeemScript: Buffer.from('redeem_script'),
    // P2SH input with redeem script
});
```

#### SegWit Transactions (P2WPKH/P2WSH)
```javascript
builder.addInput({
    type: 'p2wpkh',
    // Native SegWit input
});

builder.addInput({
    type: 'p2wsh',
    witnessScript: Buffer.from('witness_script'),
    // SegWit script hash input
});
```

#### Taproot Transactions (P2TR)
```javascript
// Key path spending
builder.addInput({
    type: 'p2tr',
    internalKey: Buffer.from('internal_key'),
    merkleRoot: null // null for key-path only
});

// Script path spending
builder.addInput({
    type: 'p2tr',
    internalKey: Buffer.from('internal_key'),
    merkleRoot: Buffer.from('merkle_root'),
    controlBlock: Buffer.from('control_block'),
    script: Buffer.from('spending_script')
});
```

### Fee Calculation

#### Fee Estimation Methods
- **Size-based**: Fee = size * feeRate
- **Weight-based**: Fee = weight / 4 * feeRate  
- **Virtual size**: Fee = vsize * feeRate (recommended)

#### Dynamic Fee Adjustment
```javascript
// Auto-adjust fee based on mempool
builder.setDynamicFee({
    target: 6, // blocks
    fallbackRate: 10 // sat/vbyte
});

// Fee bumping for RBF
builder.bumpFee(newFeeRate);
```

### Advanced Features

#### Replace-by-Fee (RBF)
```javascript
const builder = new TransactionBuilder({
    enableRBF: true
});

// Later, create replacement transaction
const replacement = builder.createRBFReplacement({
    newFeeRate: 20,
    addInputs: [additionalUtxo]
});
```

#### Child-Pays-for-Parent (CPFP)
```javascript
builder.createCPFPTransaction({
    parentTxid: 'unconfirmed_parent_tx',
    childFeeRate: 50 // Higher fee rate
});
```

#### Multi-Signature Support
```javascript
builder.addInput({
    type: 'p2sh',
    redeemScript: multisigScript,
    requiredSignatures: 2,
    totalSigners: 3
});

// Sign with multiple keys
await builder.signMultisig(input, [privKey1, privKey2]);
```

#### Threshold Signatures
```javascript
// Add threshold signature input
builder.addInput({
    type: 'threshold',
    thresholdShares: shares,
    requiredThreshold: 2
});

// Sign with threshold protocol
await builder.signThreshold(inputIndex, thresholdShares);
```

### Security Features

- **Input Validation** - Comprehensive validation of all inputs and outputs
- **Fee Limits** - Maximum fee rate protection
- **Dust Prevention** - Automatic dust output detection and prevention
- **Script Validation** - Script syntax and semantic validation
- **Signature Verification** - Cryptographic signature validation
- **Double Spend Protection** - UTXO conflict detection
- **Memory Safety** - Secure handling of private keys and sensitive data

### Error Handling

#### Error Types
- `INSUFFICIENT_FUNDS` - Not enough input value for outputs + fees
- `INVALID_INPUT` - Input format or reference invalid
- `INVALID_OUTPUT` - Output format or value invalid
- `SCRIPT_ERROR` - Script validation or execution error
- `SIGNING_ERROR` - Signature generation or verification error
- `FEE_TOO_HIGH` - Fee exceeds maximum allowed
- `DUST_OUTPUT` - Output value below dust threshold
- `SIZE_LIMIT_EXCEEDED` - Transaction size exceeds limits

### Performance Optimization

#### Building Performance
- **Lazy evaluation** - Only compute when needed
- **Caching** - Cache expensive computations
- **Batch operations** - Optimize for multiple operations
- **Memory pooling** - Reuse buffers and objects

#### Signing Performance
- **Parallel signing** - Sign multiple inputs concurrently
- **Hardware acceleration** - Use native crypto when available
- **Signature caching** - Cache signature computations
- **Batch verification** - Verify multiple signatures together

### Best Practices

1. **Validate inputs** before adding to builder
2. **Set appropriate fee rates** for network conditions
3. **Use RBF** for time-sensitive transactions
4. **Implement proper error handling** for all operations
5. **Clear sensitive data** after signing
6. **Validate final transaction** before broadcasting
7. **Use appropriate address types** for recipients
8. **Consider privacy implications** of input/output linking
9. **Test with small amounts** first
10. **Keep private keys secure** during signing process

### Integration Examples

#### With UTXO Manager
```javascript
const utxos = await utxoManager.getSpendableUTXOs(amount + fee);
utxos.forEach(utxo => builder.addInput(utxo));
```

#### With Wallet
```javascript
const wallet = new CustodialWallet(network, seed);
const address = wallet.deriveReceivingAddress(0);
builder.addChangeOutput(address);
```

#### With Fee Estimation Service
```javascript
const feeRate = await feeEstimator.estimateFee(6); // 6 blocks
builder.setFeeRate(feeRate);
```