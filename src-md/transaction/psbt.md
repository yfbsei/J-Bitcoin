# PSBT (Partially Signed Bitcoin Transaction)

Comprehensive PSBT implementation following BIP174 for Bitcoin transaction coordination and multi-party signing.

## Description

This module provides complete PSBT (Partially Signed Bitcoin Transaction) functionality for coordinating transaction creation and signing across multiple parties. It supports all PSBT roles (Creator, Updater, Signer, Finalizer, Extractor), handles all input/output types including Taproot, and includes comprehensive validation and security features for multi-party Bitcoin transactions.

## Example

```javascript
import { 
    PSBT,
    PSBTCreator,
    PSBTUpdater,
    PSBTSigner,
    PSBTFinalizer,
    PSBTExtractor
} from 'j-bitcoin';

// Create new PSBT
const psbt = new PSBT({
    network: 'main',
    version: 2
});

// Add inputs to PSBT
psbt.addInput({
    txid: 'previous_transaction_id',
    vout: 0,
    witnessUtxo: {
        value: 100000,
        scriptPubKey: Buffer.from('0014abcdef...', 'hex') // P2WPKH
    },
    bip32Derivation: [{
        pubkey: Buffer.from('03abcdef...', 'hex'),
        masterFingerprint: Buffer.from('12345678', 'hex'),
        path: "m/84'/0'/0'/0/0"
    }]
});

// Add Taproot input
psbt.addInput({
    txid: 'taproot_transaction_id',
    vout: 1,
    witnessUtxo: {
        value: 200000,
        scriptPubKey: Buffer.from('512000112233...', 'hex') // P2TR
    },
    tapInternalKey: Buffer.from('internal_key_32_bytes', 'hex'),
    tapMerkleRoot: Buffer.from('merkle_root_32_bytes', 'hex'),
    tapBip32Derivation: [{
        pubkey: Buffer.from('02112233...', 'hex'),
        leafHashes: [Buffer.from('leaf_hash_32_bytes', 'hex')],
        masterFingerprint: Buffer.from('87654321', 'hex'),
        path: "m/86'/0'/0'/0/0"
    }]
});

// Add outputs
psbt.addOutput({
    address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
    value: 75000
});

psbt.addOutput({
    address: 'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297',
    value: 200000
});

// Add change output with derivation info
psbt.addOutput({
    address: 'bc1qchange_address_here',
    value: 24000, // Calculated change amount
    bip32Derivation: [{
        pubkey: Buffer.from('change_pubkey', 'hex'),
        masterFingerprint: Buffer.from('12345678', 'hex'),
        path: "m/84'/0'/0'/1/5"
    }]
});

// Serialize PSBT for sharing
const psbtBase64 = psbt.toBase64();
console.log('PSBT for sharing:', psbtBase64);

// Parse PSBT from base64
const receivedPSBT = PSBT.fromBase64(psbtBase64);
console.log('Parsed PSBT inputs:', receivedPSBT.inputs.length);

// Update PSBT with additional information
const updater = new PSBTUpdater(receivedPSBT);
updater.updateInput(0, {
    nonWitnessUtxo: Buffer.from('full_previous_transaction', 'hex'),
    redeemScript: Buffer.from('redeem_script', 'hex')
});

// Sign PSBT (Signer role)
const signer = new PSBTSigner({
    network: 'main',
    signingKey: 'private_key_wif'
});

const signedPSBT = await signer.sign(receivedPSBT, {
    inputIndex: 0,
    sighashType: 0x01 // SIGHASH_ALL
});

console.log('Signature added:', signedPSBT.inputs[0].partialSig.length > 0);

// Finalize PSBT (combine signatures and create final scripts)
const finalizer = new PSBTFinalizer();
const finalizedPSBT = finalizer.finalize(signedPSBT);

console.log('PSBT finalized:', finalizedPSBT.inputs[0].finalScriptWitness !== undefined);

// Extract final transaction
const extractor = new PSBTExtractor();
const finalTransaction = extractor.extract(finalizedPSBT);

console.log('Final Transaction:', finalTransaction.toHex());
console.log('Transaction ID:', finalTransaction.getId());

// Multi-party workflow example
async function multiPartyWorkflow() {
    // Party 1: Creator
    const creator = new PSBTCreator({ network: 'main' });
    const psbt = creator.create({
        inputs: [utxo1, utxo2],
        outputs: [output1, output2, changeOutput]
    });

    // Party 2: Updater (adds missing information)
    const updater = new PSBTUpdater();
    const updatedPSBT = updater.update(psbt, {
        additionalInputData: inputMetadata,
        additionalOutputData: outputMetadata
    });

    // Party 3: First signer
    const signer1 = new PSBTSigner({ signingKey: privateKey1 });
    const partiallySigned1 = await signer1.signAll(updatedPSBT);

    // Party 4: Second signer
    const signer2 = new PSBTSigner({ signingKey: privateKey2 });
    const partiallySigned2 = await signer2.signAll(partiallySigned1);

    // Party 5: Finalizer
    const finalizer = new PSBTFinalizer();
    const finalPSBT = finalizer.finalizeAll(partiallySigned2);

    // Extract and broadcast
    const extractor = new PSBTExtractor();
    const transaction = extractor.extract(finalPSBT);
    
    return transaction;
}
```

## API Reference

### Classes

#### `PSBT`
Main PSBT class implementing BIP174 specification.

**Constructor:**
```javascript
new PSBT(options = {})
```

**Options:**
- `network` (string) - Network type ('main' or 'test')
- `version` (number) - Transaction version (default: 2)
- `lockTime` (number) - Transaction lock time (default: 0)
- `globalXpubs` (Array) - Global extended public keys
- `proprietaryData` (Object) - Proprietary key-value pairs

**Static Methods:**

##### `PSBT.fromBase64(psbtString)`
Creates PSBT from base64 encoded string.

**Parameters:**
- `psbtString` (string) - Base64 encoded PSBT

**Returns:**
- `PSBT` - New PSBT instance

##### `PSBT.fromHex(psbtHex)`
Creates PSBT from hex encoded string.

**Parameters:**
- `psbtHex` (string) - Hex encoded PSBT

**Returns:**
- `PSBT` - New PSBT instance

##### `PSBT.fromBuffer(buffer)`
Creates PSBT from buffer.

**Parameters:**
- `buffer` (Buffer) - PSBT buffer

**Returns:**
- `PSBT` - New PSBT instance

**Instance Methods:**

##### `psbt.addInput(input)`
Adds an input to the PSBT.

**Parameters:**
- `input` (Object) - Input specification
  - `txid` (string) - Previous transaction ID
  - `vout` (number) - Output index
  - `sequence` (number) - Input sequence (optional)
  - `witnessUtxo` (Object) - Witness UTXO for SegWit inputs
    - `value` (number) - Output value in satoshis
    - `scriptPubKey` (Buffer) - Output script
  - `nonWitnessUtxo` (Buffer) - Full previous transaction for legacy inputs
  - `redeemScript` (Buffer) - Redeem script for P2SH
  - `witnessScript` (Buffer) - Witness script for P2WSH
  - `bip32Derivation` (Array) - BIP32 derivation paths
  - `finalScriptSig` (Buffer) - Final script signature (if finalized)
  - `finalScriptWitness` (Buffer) - Final script witness (if finalized)
  - `tapInternalKey` (Buffer) - Taproot internal key
  - `tapMerkleRoot` (Buffer) - Taproot merkle root
  - `tapBip32Derivation` (Array) - Taproot BIP32 derivation
  - `tapScriptSig` (Array) - Taproot script signatures
  - `proprietary` (Array) - Proprietary key-value pairs

**Returns:**
- `PSBT` - PSBT instance for chaining

##### `psbt.addOutput(output)`
Adds an output to the PSBT.

**Parameters:**
- `output` (Object) - Output specification
  - `address` (string) - Destination address
  - `value` (number) - Output value in satoshis
  - `script` (Buffer) - Custom output script (alternative to address)
  - `bip32Derivation` (Array) - BIP32 derivation paths for change outputs
  - `tapInternalKey` (Buffer) - Taproot internal key for change
  - `tapTree` (Object) - Taproot script tree for change
  - `tapBip32Derivation` (Array) - Taproot BIP32 derivation
  - `proprietary` (Array) - Proprietary key-value pairs

**Returns:**
- `PSBT` - PSBT instance for chaining

##### `psbt.toBase64()`
Serializes PSBT to base64 string.

**Returns:**
- `string` - Base64 encoded PSBT

##### `psbt.toHex()`
Serializes PSBT to hex string.

**Returns:**
- `string` - Hex encoded PSBT

##### `psbt.toBuffer()`
Serializes PSBT to buffer.

**Returns:**
- `Buffer` - PSBT buffer

##### `psbt.clone()`
Creates a deep copy of the PSBT.

**Returns:**
- `PSBT` - Cloned PSBT instance

##### `psbt.validate()`
Validates PSBT structure and data.

**Returns:**
- Object with validation result:
  - `isValid` (boolean) - Overall validation result
  - `errors` (Array<string>) - Validation errors
  - `warnings` (Array<string>) - Validation warnings
  - `inputValidation` (Array) - Per-input validation results
  - `outputValidation` (Array) - Per-output validation results

#### `PSBTCreator`
PSBT Creator role implementation.

**Methods:**

##### `creator.create(options)`
Creates a new PSBT from transaction components.

**Parameters:**
- `options` (Object) - Creation options
  - `inputs` (Array) - Input specifications
  - `outputs` (Array) - Output specifications
  - `version` (number) - Transaction version
  - `lockTime` (number) - Transaction lock time

**Returns:**
- `PSBT` - Created PSBT

#### `PSBTUpdater`
PSBT Updater role implementation.

**Methods:**

##### `updater.updateInput(psbt, inputIndex, updateData)`
Updates input with additional information.

**Parameters:**
- `psbt` (PSBT) - PSBT to update
- `inputIndex` (number) - Input index to update
- `updateData` (Object) - Additional input data

**Returns:**
- `PSBT` - Updated PSBT

##### `updater.updateOutput(psbt, outputIndex, updateData)`
Updates output with additional information.

**Parameters:**
- `psbt` (PSBT) - PSBT to update
- `outputIndex` (number) - Output index to update
- `updateData` (Object) - Additional output data

**Returns:**
- `PSBT` - Updated PSBT

#### `PSBTSigner`
PSBT Signer role implementation.

**Constructor:**
```javascript
new PSBTSigner(options)
```

**Options:**
- `network` (string) - Network type
- `signingKey` (string|Buffer) - Private key for signing
- `sigHashType` (number) - Default signature hash type

**Methods:**

##### `signer.sign(psbt, options = {})`
Signs specific input in PSBT.

**Parameters:**
- `psbt` (PSBT) - PSBT to sign
- `options` (Object) - Signing options
  - `inputIndex` (number) - Input index to sign
  - `sigHashType` (number) - Signature hash type
  - `tapLeafHash` (Buffer) - Tap leaf hash for script path signing

**Returns:**
- `Promise<PSBT>` - PSBT with added signature

##### `signer.signAll(psbt, options = {})`
Signs all applicable inputs in PSBT.

**Parameters:**
- `psbt` (PSBT) - PSBT to sign
- `options` (Object) - Signing options

**Returns:**
- `Promise<PSBT>` - PSBT with added signatures

##### `signer.canSign(psbt, inputIndex)`
Checks if signer can sign specific input.

**Parameters:**
- `psbt` (PSBT) - PSBT to check
- `inputIndex` (number) - Input index to check

**Returns:**
- `boolean` - Whether signer can sign this input

#### `PSBTFinalizer`
PSBT Finalizer role implementation.

**Methods:**

##### `finalizer.finalizeInput(psbt, inputIndex)`
Finalizes specific input by constructing final scripts.

**Parameters:**
- `psbt` (PSBT) - PSBT to finalize
- `inputIndex` (number) - Input index to finalize

**Returns:**
- `PSBT` - PSBT with finalized input

##### `finalizer.finalizeAll(psbt)`
Finalizes all inputs that have sufficient signatures.

**Parameters:**
- `psbt` (PSBT) - PSBT to finalize

**Returns:**
- `PSBT` - PSBT with all finalizable inputs finalized

##### `finalizer.isInputFinalizable(psbt, inputIndex)`
Checks if input has sufficient signatures for finalization.

**Parameters:**
- `psbt` (PSBT) - PSBT to check
- `inputIndex` (number) - Input index to check

**Returns:**
- `boolean` - Whether input can be finalized

#### `PSBTExtractor`
PSBT Extractor role implementation.

**Methods:**

##### `extractor.extract(psbt)`
Extracts final transaction from completely signed PSBT.

**Parameters:**
- `psbt` (PSBT) - Finalized PSBT

**Returns:**
- Object with transaction:
  - `transaction` (Object) - Bitcoin transaction object
  - `hex` (string) - Transaction hex string
  - `txid` (string) - Transaction ID
  - `size` (number) - Transaction size
  - `vsize` (number) - Virtual transaction size
  - `weight` (number) - Transaction weight

**Throws:**
- `PSBTError` - If PSBT is not fully signed and finalized

##### `extractor.canExtract(psbt)`
Checks if transaction can be extracted from PSBT.

**Parameters:**
- `psbt` (PSBT) - PSBT to check

**Returns:**
- Object with extraction feasibility:
  - `canExtract` (boolean) - Whether extraction is possible
  - `missingSignatures` (Array) - Inputs missing signatures
  - `missingFinalScripts` (Array) - Inputs missing final scripts

### PSBT Data Structures

#### Input Structure
```javascript
{
  // Required
  previousTxid: Buffer,           // 32 bytes
  previousOutputIndex: number,    // 4 bytes
  
  // Optional
  sequence: number,               // 4 bytes
  witnessUtxo: {                 // For SegWit inputs
    value: number,
    scriptPubKey: Buffer
  },
  nonWitnessUtxo: Buffer,        // Full previous transaction
  partialSig: [{                 // Partial signatures
    pubkey: Buffer,
    signature: Buffer
  }],
  redeemScript: Buffer,          // P2SH redeem script
  witnessScript: Buffer,         // P2WSH witness script
  bip32Derivation: [{           // BIP32 derivation info
    pubkey: Buffer,
    masterFingerprint: Buffer,
    path: string
  }],
  finalScriptSig: Buffer,       // Final script signature
  finalScriptWitness: Buffer,   // Final script witness
  
  // Taproot fields
  tapInternalKey: Buffer,       // 32 bytes
  tapMerkleRoot: Buffer,        // 32 bytes
  tapBip32Derivation: [{
    pubkey: Buffer,
    leafHashes: [Buffer],
    masterFingerprint: Buffer,
    path: string
  }],
  tapScriptSig: [{
    pubkey: Buffer,
    leafHash: Buffer,
    signature: Buffer
  }]
}
```

#### Output Structure
```javascript
{
  // Required
  value: number,                 // 8 bytes (satoshis)
  scriptPubKey: Buffer,         // Variable length
  
  // Optional
  bip32Derivation: [{           // For change outputs
    pubkey: Buffer,
    masterFingerprint: Buffer,
    path: string
  }],
  
  // Taproot fields
  tapInternalKey: Buffer,       // 32 bytes
  tapTree: Object,              // Script tree structure
  tapBip32Derivation: [{
    pubkey: Buffer,
    leafHashes: [Buffer],
    masterFingerprint: Buffer,
    path: string
  }]
}
```

### Signature Hash Types

#### Standard SigHash Types
- `SIGHASH_ALL` (0x01) - Sign all inputs and outputs
- `SIGHASH_NONE` (0x02) - Sign all inputs, no outputs
- `SIGHASH_SINGLE` (0x03) - Sign all inputs, corresponding output
- `SIGHASH_ANYONECANPAY` (0x80) - Can be combined with above (flag)

#### Taproot SigHash (BIP341)
- Enhanced signature hash computation for Taproot inputs
- Includes additional commitment data
- Uses tagged hashing for domain separation

### Multi-Party Workflow

#### Typical PSBT Workflow
1. **Creator** - Creates initial PSBT with inputs and outputs
2. **Updater** - Adds missing UTXO information and metadata
3. **Signer 1** - Signs inputs they control
4. **Signer 2** - Signs additional inputs (multi-sig scenario)
5. **Finalizer** - Constructs final scripts from signatures
6. **Extractor** - Extracts final transaction for broadcast

#### Hardware Wallet Integration
```javascript
// Prepare PSBT for hardware wallet
const hwPSBT = psbt.clone();
hwPSBT.clearNonEssentialData(); // Remove unnecessary data

// Send to hardware wallet for signing
const signedHwPSBT = await hardwareWallet.signPSBT(hwPSBT);

// Merge signatures back
psbt.combineSignatures(signedHwPSBT);
```

### Security Features

- **Input Validation** - Comprehensive validation of all PSBT fields
- **Signature Verification** - Cryptographic verification of all signatures
- **Script Validation** - Validation of all script types and formats
- **Double Spend Prevention** - UTXO conflict detection
- **Malleability Protection** - Protection against transaction malleability
- **Privacy Preservation** - Optional data fields to minimize information leakage
- **Error Isolation** - Secure error handling without information disclosure

### Error Handling

#### Error Types
- `PSBT_INVALID_FORMAT` - PSBT format is invalid
- `PSBT_INVALID_INPUT` - Input data is invalid
- `PSBT_INVALID_OUTPUT` - Output data is invalid
- `PSBT_SIGNING_FAILED` - Signature generation failed
- `PSBT_MISSING_UTXO` - Required UTXO information missing
- `PSBT_INSUFFICIENT_SIGNATURES` - Not enough signatures for finalization
- `PSBT_FINALIZATION_FAILED` - Script finalization failed
- `PSBT_EXTRACTION_FAILED` - Transaction extraction failed

### Best Practices

1. **Always validate PSBTs** before processing
2. **Verify UTXO information** before signing
3. **Use witness UTXOs** for SegWit inputs when possible
4. **Include derivation paths** for wallet compatibility
5. **Clear sensitive data** after operations
6. **Implement proper error handling** for all PSBT operations
7. **Use hardware wallets** for high-value transactions
8. **Validate final transaction** before broadcast
9. **Keep PSBTs confidential** during multi-party coordination
10. **Use appropriate signature hash types** for intended spending conditions

### Performance Notes

- PSBT creation: ~1-5ms depending on input/output count
- Signature addition: ~2-10ms per signature
- Finalization: ~1-3ms per input
- Serialization: ~0.5-2ms depending on size
- Validation: ~1-5ms depending on complexity