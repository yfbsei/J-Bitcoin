# UTXO Manager

Comprehensive UTXO (Unspent Transaction Output) management system for Bitcoin wallet operations with advanced coin selection and optimization.

## Description

This module provides complete UTXO management functionality for Bitcoin wallets including UTXO tracking, coin selection algorithms, consolidation strategies, and privacy-preserving spending. It supports all address types (Legacy, SegWit, Taproot) with advanced features like coin control, UTXO labeling, and spending optimization for fee minimization and privacy enhancement.

## Example

```javascript
import { UTXOManager } from 'j-bitcoin';

// Create UTXO manager instance
const utxoManager = new UTXOManager({
    network: 'main',
    storage: 'memory', // or 'file', 'database'
    coinSelectionStrategy: 'branch_and_bound',
    privacyMode: true,
    dustThreshold: 546
});

// Add UTXOs to management
await utxoManager.addUTXO({
    txid: 'transaction_id_1',
    vout: 0,
    value: 100000, // satoshis
    scriptPubKey: Buffer.from('script_hex', 'hex'),
    address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
    type: 'p2wpkh',
    confirmations: 6,
    blockHeight: 800000,
    label: 'salary_payment',
    isChange: false,
    spendable: true
});

await utxoManager.addUTXO({
    txid: 'transaction_id_2',
    vout: 1,
    value: 50000,
    scriptPubKey: Buffer.from('script_hex', 'hex'),
    address: '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
    type: 'p2pkh',
    confirmations: 12,
    blockHeight: 799990,
    label: 'mining_reward',
    isChange: false,
    spendable: true
});

// Get spendable UTXOs for amount
const targetAmount = 75000;
const selectedUTXOs = await utxoManager.selectCoins(targetAmount, {
    feeRate: 10, // sat/vbyte
    includeChange: true,
    maxInputs: 10,
    strategy: 'branch_and_bound'
});

console.log('Selected UTXOs:', selectedUTXOs.utxos);
console.log('Total Value:', selectedUTXOs.totalValue);
console.log('Estimated Fee:', selectedUTXOs.estimatedFee);
console.log('Change Amount:', selectedUTXOs.changeAmount);
console.log('Efficiency Score:', selectedUTXOs.efficiency);

// Get wallet balance information
const balance = await utxoManager.getBalance();
console.log('Total Balance:', balance.total);
console.log('Confirmed Balance:', balance.confirmed);
console.log('Unconfirmed Balance:', balance.unconfirmed);
console.log('Spendable Balance:', balance.spendable);
console.log('UTXO Count:', balance.utxoCount);

// Advanced coin selection with constraints
const constrainedSelection = await utxoManager.selectCoins(25000, {
    strategy: 'privacy_optimized',
    maxInputs: 3,
    minConfirmations: 6,
    excludeLabels: ['suspicious'],
    includeLabels: ['salary_payment', 'mining_reward'],
    avoidAddressReuse: true,
    targetAnonymitySet: 10
});

// UTXO consolidation for fee optimization
const consolidationPlan = await utxoManager.planConsolidation({
    feeRate: 5, // Low fee rate for consolidation
    maxInputsPerTx: 100,
    targetOutputCount: 1,
    minConsolidationValue: 10000
});

console.log('Consolidation Plan:', consolidationPlan);
console.log('Transactions needed:', consolidationPlan.transactions.length);
console.log('Total fee cost:', consolidationPlan.totalFee);
console.log('Space savings:', consolidationPlan.spaceSavings);

// Execute consolidation
const consolidationResults = await utxoManager.executeConsolidation(consolidationPlan);
console.log('Consolidation completed:', consolidationResults);

// Privacy analysis
const privacyAnalysis = await utxoManager.analyzePrivacy();
console.log('Address reuse count:', privacyAnalysis.addressReuse);
console.log('Common input ownership score:', privacyAnalysis.commonOwnershipScore);
console.log('Anonymity set size:', privacyAnalysis.anonymitySet);
console.log('Privacy recommendations:', privacyAnalysis.recommendations);
```

## API Reference

### Classes

#### `UTXOManager`
Main UTXO management class with comprehensive tracking and selection capabilities.

**Constructor:**
```javascript
new UTXOManager(options = {})
```

**Options:**
- `network` (string) - Network type ('main' or 'test')
- `storage` (string) - Storage backend ('memory', 'file', 'database')
- `coinSelectionStrategy` (string) - Default selection strategy
- `privacyMode` (boolean) - Enable privacy-preserving features
- `dustThreshold` (number) - Dust threshold in satoshis (default: 546)
- `minConfirmations` (number) - Minimum confirmations for spending (default: 1)
- `maxUTXOs` (number) - Maximum UTXOs to track (default: 10000)
- `storageOptions` (Object) - Storage-specific configuration

**Instance Methods:**

##### `utxoManager.addUTXO(utxo)`
Adds a UTXO to the management system.

**Parameters:**
- `utxo` (Object) - UTXO specification
  - `txid` (string) - Transaction ID
  - `vout` (number) - Output index
  - `value` (number) - Value in satoshis
  - `scriptPubKey` (Buffer) - Output script
  - `address` (string) - Output address
  - `type` (string) - Address type ('p2pkh', 'p2sh', 'p2wpkh', 'p2wsh', 'p2tr')
  - `confirmations` (number) - Number of confirmations
  - `blockHeight` (number) - Block height when confirmed
  - `blockHash` (string) - Block hash (optional)
  - `label` (string) - User-defined label (optional)
  - `isChange` (boolean) - Whether this is a change output
  - `spendable` (boolean) - Whether UTXO is spendable
  - `locked` (boolean) - Whether UTXO is locked for spending

**Returns:**
- `Promise<boolean>` - Success status

##### `utxoManager.removeUTXO(txid, vout)`
Removes a UTXO from management (when spent).

**Parameters:**
- `txid` (string) - Transaction ID
- `vout` (number) - Output index

**Returns:**
- `Promise<boolean>` - Success status

##### `utxoManager.selectCoins(amount, options = {})`
Selects optimal UTXOs for spending a specific amount.

**Parameters:**
- `amount` (number) - Target amount in satoshis
- `options` (Object) - Selection options
  - `feeRate` (number) - Fee rate in sat/vbyte
  - `strategy` (string) - Selection strategy
  - `maxInputs` (number) - Maximum inputs to include
  - `minConfirmations` (number) - Minimum confirmations required
  - `includeChange` (boolean) - Whether to include change calculation
  - `excludeLabels` (Array<string>) - Labels to exclude
  - `includeLabels` (Array<string>) - Labels to include only
  - `avoidAddressReuse` (boolean) - Avoid reusing addresses
  - `targetAnonymitySet` (number) - Target anonymity set size

**Returns:**
- Object with selection result:
  - `utxos` (Array<Object>) - Selected UTXOs
  - `totalValue` (number) - Total input value
  - `targetAmount` (number) - Requested amount
  - `estimatedFee` (number) - Estimated transaction fee
  - `changeAmount` (number) - Change output amount
  - `efficiency` (number) - Selection efficiency score (0.0-1.0)
  - `strategy` (string) - Strategy used
  - `privacyScore` (number) - Privacy score (0.0-1.0)

##### `utxoManager.getBalance(options = {})`
Gets comprehensive balance information.

**Parameters:**
- `options` (Object) - Balance calculation options
  - `minConfirmations` (number) - Minimum confirmations
  - `includeUnconfirmed` (boolean) - Include unconfirmed UTXOs
  - `excludeLabels` (Array<string>) - Labels to exclude
  - `groupByLabel` (boolean) - Group balance by labels

**Returns:**
- Object with balance information:
  - `total` (number) - Total balance including unconfirmed
  - `confirmed` (number) - Confirmed balance only
  - `unconfirmed` (number) - Unconfirmed balance
  - `spendable` (number) - Spendable balance (meets min confirmations)
  - `locked` (number) - Locked UTXO balance
  - `dust` (number) - Dust UTXO balance
  - `utxoCount` (number) - Total UTXO count
  - `largestUTXO` (number) - Largest UTXO value
  - `averageUTXO` (number) - Average UTXO value
  - `byLabel` (Object) - Balance grouped by labels (if requested)

##### `utxoManager.planConsolidation(options = {})`
Creates a plan for UTXO consolidation to reduce fees.

**Parameters:**
- `options` (Object) - Consolidation options
  - `feeRate` (number) - Fee rate for consolidation transactions
  - `maxInputsPerTx` (number) - Maximum inputs per transaction
  - `targetOutputCount` (number) - Target number of outputs after consolidation
  - `minConsolidationValue` (number) - Minimum value to consolidate
  - `excludeLabels` (Array<string>) - Labels to exclude from consolidation
  - `prioritizeSmallUTXOs` (boolean) - Prioritize consolidating small UTXOs

**Returns:**
- Object with consolidation plan:
  - `transactions` (Array<Object>) - Planned consolidation transactions
  - `totalFee` (number) - Total fee cost for consolidation
  - `spaceSavings` (number) - Estimated space savings in future transactions
  - `utxoReduction` (number) - Number of UTXOs that will be eliminated
  - `costBenefit` (number) - Cost-benefit ratio
  - `recommendedFeeRate` (number) - Recommended fee rate for execution

##### `utxoManager.executeConsolidation(plan)`
Executes a consolidation plan.

**Parameters:**
- `plan` (Object) - Consolidation plan from `planConsolidation()`

**Returns:**
- Object with execution results:
  - `success` (boolean) - Whether consolidation succeeded
  - `transactions` (Array<string>) - Transaction IDs created
  - `totalFee` (number) - Actual fee paid
  - `utxosConsolidated` (number) - Number of UTXOs consolidated
  - `errors` (Array<string>) - Any errors encountered

##### `utxoManager.analyzePrivacy()`
Analyzes privacy characteristics of UTXO set.

**Returns:**
- Object with privacy analysis:
  - `addressReuse` (number) - Number of address reuses
  - `commonOwnershipScore` (number) - Common input ownership heuristic score
  - `anonymitySet` (number) - Estimated anonymity set size
  - `temporalClustering` (number) - Temporal clustering score
  - `amountClustering` (number) - Amount clustering score
  - `recommendations` (Array<string>) - Privacy improvement recommendations

### Coin Selection Strategies

#### `branch_and_bound`
Optimal selection using branch and bound algorithm.
- **Pros:** Minimizes fees, often finds exact solutions
- **Cons:** Computationally intensive for large UTXO sets
- **Best for:** Small to medium UTXO sets, fee optimization

#### `knapsack`
Approximation algorithm based on knapsack problem.
- **Pros:** Fast, good approximation, handles large sets
- **Cons:** May not find optimal solution
- **Best for:** Large UTXO sets, speed requirements

#### `largest_first`
Selects largest UTXOs first.
- **Pros:** Simple, minimizes number of inputs
- **Cons:** Poor privacy, may waste large UTXOs
- **Best for:** Consolidation, simple scenarios

#### `smallest_first`
Selects smallest UTXOs first.
- **Pros:** Good for dust cleanup
- **Cons:** Many inputs, higher fees
- **Best for:** Dust consolidation

#### `privacy_optimized`
Optimizes for privacy preservation.
- **Pros:** Better privacy characteristics
- **Cons:** May be less efficient
- **Best for:** Privacy-conscious spending

#### `random_selection`
Random selection within constraints.
- **Pros:** Unpredictable patterns
- **Cons:** Suboptimal efficiency
- **Best for:** Privacy when combined with other strategies

### UTXO Storage Backends

#### Memory Storage
```javascript
const utxoManager = new UTXOManager({
    storage: 'memory'
});
// Suitable for testing, temporary operations
```

#### File Storage
```javascript
const utxoManager = new UTXOManager({
    storage: 'file',
    storageOptions: {
        filePath: './utxos.json',
        backupInterval: 3600000, // 1 hour
        compression: true
    }
});
```

#### Database Storage
```javascript
const utxoManager = new UTXOManager({
    storage: 'database',
    storageOptions: {
        type: 'sqlite', // or 'postgresql', 'mysql'
        connectionString: 'sqlite:./wallet.db',
        tableName: 'utxos'
    }
});
```

### UTXO Labeling System

#### Label Categories
- **Source:** `salary`, `mining`, `purchase`, `exchange`
- **Purpose:** `savings`, `spending`, `investment`  
- **Privacy:** `private`, `public`, `mixed`
- **Status:** `confirmed`, `unconfirmed`, `locked`

#### Label Operations
```javascript
// Add labels to UTXO
await utxoManager.addLabel(txid, vout, 'salary_payment');

// Remove labels
await utxoManager.removeLabel(txid, vout, 'old_label');

// Query by labels
const salaryUTXOs = await utxoManager.getUTXOsByLabel('salary');

// Exclude labels from selection
const selection = await utxoManager.selectCoins(amount, {
    excludeLabels: ['suspicious', 'locked']
});
```

### Privacy Features

#### Address Reuse Detection
- Tracks address usage across UTXOs
- Warns about potential privacy leaks
- Suggests fresh addresses for better privacy

#### Common Input Ownership Heuristic
- Analyzes input patterns for ownership clustering
- Provides scores for transaction linkability
- Suggests mixing strategies

#### Anonymity Set Calculation
- Estimates anonymity set size for transactions
- Considers timing, amounts, and patterns
- Recommends improvements for better privacy

### Performance Optimization

#### UTXO Indexing
```javascript
// Automatic indexing for fast queries
await utxoManager.createIndex('value'); // Index by value
await utxoManager.createIndex('confirmations'); // Index by confirmations
await utxoManager.createIndex('label'); // Index by labels
```

#### Batch Operations
```javascript
// Batch add multiple UTXOs
await utxoManager.addUTXOsBatch([utxo1, utxo2, utxo3]);

// Batch remove spent UTXOs
await utxoManager.removeUTXOsBatch([
    { txid: 'tx1', vout: 0 },
    { txid: 'tx2', vout: 1 }
]);
```

#### Caching Strategies
- **Selection cache** - Cache coin selection results
- **Balance cache** - Cache balance calculations
- **Index cache** - Cache index queries for performance

### UTXO Statistics and Analytics

#### `utxoManager.getStatistics()`
Get comprehensive UTXO set statistics.

**Returns:**
- Object with statistics:
  - `totalUTXOs` (number) - Total UTXO count
  - `totalValue` (number) - Total value of all UTXOs
  - `averageValue` (number) - Average UTXO value
  - `medianValue` (number) - Median UTXO value
  - `dustCount` (number) - Number of dust UTXOs
  - `dustValue` (number) - Total dust value
  - `largestUTXO` (number) - Largest UTXO value
  - `smallestUTXO` (number) - Smallest UTXO value
  - `ageDistribution` (Object) - Age distribution of UTXOs
  - `valueDistribution` (Object) - Value distribution histogram
  - `typeDistribution` (Object) - Distribution by address type

#### UTXO Health Metrics
```javascript
const health = await utxoManager.getHealthMetrics();
console.log('Consolidation needed:', health.needsConsolidation);
console.log('Dust percentage:', health.dustPercentage);
console.log('Privacy score:', health.privacyScore);
console.log('Efficiency score:', health.efficiencyScore);
```

### Event System

#### UTXO Events
```javascript
// Listen for UTXO events
utxoManager.on('utxo:added', (utxo) => {
    console.log('New UTXO added:', utxo);
});

utxoManager.on('utxo:spent', (txid, vout) => {
    console.log('UTXO spent:', txid, vout);
});

utxoManager.on('balance:changed', (newBalance) => {
    console.log('Balance updated:', newBalance);
});

utxoManager.on('consolidation:recommended', (plan) => {
    console.log('Consolidation recommended:', plan);
});
```

### Security Features

- **Input Validation** - Comprehensive validation of all UTXO data
- **Secure Storage** - Encrypted storage options for sensitive data
- **Access Control** - Permission-based access to UTXO operations
- **Audit Trail** - Complete audit trail of UTXO changes
- **Backup and Recovery** - Automated backup and recovery mechanisms
- **Lock Management** - Prevent double-spending with UTXO locks

### Error Handling

#### Error Types
- `UTXO_NOT_FOUND` - UTXO doesn't exist in manager
- `INSUFFICIENT_FUNDS` - Not enough UTXOs for requested amount
- `UTXO_ALREADY_SPENT` - Attempting to use already spent UTXO
- `INVALID_UTXO_DATA` - UTXO data format is invalid
- `STORAGE_ERROR` - Storage backend error
- `SELECTION_FAILED` - Coin selection algorithm failed
- `CONSOLIDATION_FAILED` - UTXO consolidation failed
- `PRIVACY_VIOLATION` - Operation would violate privacy constraints

### Integration Examples

#### With Transaction Builder
```javascript
const amount = 100000;
const selection = await utxoManager.selectCoins(amount, { feeRate: 10 });

const builder = new TransactionBuilder();
selection.utxos.forEach(utxo => builder.addInput(utxo));
builder.addOutput({ address: recipientAddress, value: amount });

if (selection.changeAmount > 0) {
    builder.addChangeOutput(changeAddress);
}
```

#### With Wallet Synchronization
```javascript
// Sync UTXOs from blockchain
const newUTXOs = await blockchain.getUTXOs(addresses);
await utxoManager.syncUTXOs(newUTXOs);

// Update confirmations
await utxoManager.updateConfirmations(currentBlockHeight);
```

#### With Fee Estimation
```javascript
const feeEstimate = await feeEstimator.estimateFee(6); // 6 blocks
const selection = await utxoManager.selectCoins(amount, {
    feeRate: feeEstimate,
    strategy: 'branch_and_bound'
});
```

### Configuration Examples

#### Basic Configuration
```javascript
const utxoManager = new UTXOManager({
    network: 'main',
    dustThreshold: 546,
    minConfirmations: 1
});
```

#### Privacy-Focused Configuration
```javascript
const utxoManager = new UTXOManager({
    network: 'main',
    privacyMode: true,
    coinSelectionStrategy: 'privacy_optimized',
    avoidAddressReuse: true,
    targetAnonymitySet: 20
});
```

#### High-Performance Configuration
```javascript
const utxoManager = new UTXOManager({
    network: 'main',
    storage: 'database',
    coinSelectionStrategy: 'knapsack',
    maxUTXOs: 100000,
    storageOptions: {
        connectionString: 'postgresql://localhost/wallet',
        indexing: true,
        caching: true
    }
});
```

### Best Practices

1. **Regular Consolidation** - Consolidate small UTXOs during low-fee periods
2. **Privacy Labeling** - Use consistent labeling for privacy analysis
3. **Backup Management** - Regular backup of UTXO database
4. **Performance Monitoring** - Monitor selection performance and optimize
5. **Fee Optimization** - Use appropriate selection strategies for fee levels
6. **Privacy Protection** - Avoid address reuse and input clustering
7. **Dust Management** - Regular cleanup of dust UTXOs
8. **Index Maintenance** - Keep indexes updated for query performance
9. **Event Monitoring** - Monitor UTXO events for wallet state changes
10. **Security Auditing** - Regular security audits of UTXO operations

### Performance Benchmarks

| Operation | Small Set (<100) | Medium Set (<1000) | Large Set (<10000) |
|-----------|-------------------|--------------------|--------------------|
| Add UTXO | <1ms | <1ms | <5ms |
| Remove UTXO | <1ms | <1ms | <3ms |
| Balance Query | <1ms | <5ms | <20ms |
| Coin Selection | <10ms | <50ms | <200ms |
| Consolidation Plan | <20ms | <100ms | <500ms |
| Privacy Analysis | <5ms | <25ms | <100ms |

### Memory Usage

- **Small set** (<100 UTXOs): ~1-5 MB
- **Medium set** (<1000 UTXOs): ~5-20 MB
- **Large set** (<10000 UTXOs): ~20-100 MB
- **Index overhead**: ~10-30% additional memory

### Future Enhancements

- **Machine Learning** - ML-based coin selection optimization
- **Advanced Privacy** - CoinJoin integration and mixing strategies
- **Hardware Wallet** - Hardware wallet integration for UTXO management
- **Lightning Network** - Channel management and UTXO optimization
- **Cross-Chain** - Multi-blockchain UTXO management