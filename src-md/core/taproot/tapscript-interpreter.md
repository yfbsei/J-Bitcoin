# Tapscript Interpreter (BIP342)

Comprehensive Tapscript interpreter implementation following BIP342 specification for Bitcoin Taproot script execution.

## Description

This module provides a complete BIP342-compliant Tapscript interpreter for executing Bitcoin scripts in Taproot context. It includes all Tapscript-specific opcodes, enhanced OP_SUCCESS handling, proper signature hash computation, and comprehensive security features including execution limits, stack management, and DoS protection.

## Example

```javascript
import { 
    TapscriptInterpreter,
    TapscriptExecutionContext,
    TAPSCRIPT_CONSTANTS,
    OPCODES 
} from 'j-bitcoin';

// Create interpreter instance
const interpreter = new TapscriptInterpreter({
    enforceMinimalPush: true,
    maxStackSize: 1000,
    maxScriptSize: 10000,
    enableOpSuccess: true
});

// Simple script execution
const script = Buffer.from([
    OPCODES.OP_1,           // Push 1 onto stack
    OPCODES.OP_2,           // Push 2 onto stack
    OPCODES.OP_ADD          // Add top two stack elements
]);

const witness = [];
const sigHash = Buffer.alloc(32, 0x01);

const result = await interpreter.execute(script, witness, sigHash);
console.log('Execution Result:', result.success);
console.log('Final Stack:', result.stack.map(item => item.toString('hex')));
console.log('Gas Used:', result.gasUsed);

// Complex Tapscript with signature verification
const complexScript = Buffer.from([
    OPCODES.OP_DUP,                    // Duplicate top stack item
    OPCODES.OP_HASH160,                // Hash with HASH160
    0x14, ...Buffer.from('pubkey_hash_20_bytes'), // Push pubkey hash
    OPCODES.OP_EQUALVERIFY,            // Verify hashes are equal
    OPCODES.OP_CHECKSIG                // Verify signature
]);

const witnessData = [
    Buffer.from('signature_64_bytes'),  // Schnorr signature
    Buffer.from('pubkey_32_bytes')      // Public key
];

const complexResult = await interpreter.execute(complexScript, witnessData, sigHash);
console.log('Signature Verification:', complexResult.success);

// Script validation with execution context
const context = new TapscriptExecutionContext({
    scriptVersion: TAPSCRIPT_CONSTANTS.LEAF_VERSION_TAPSCRIPT,
    inputIndex: 0,
    transaction: transactionData,
    utxos: previousOutputs,
    taprootAnnex: null
});

const validationResult = await interpreter.validateScript(
    complexScript,
    witnessData,
    sigHash,
    context
);

console.log('Script Valid:', validationResult.isValid);
console.log('Validation Details:', validationResult.details);

// OP_SUCCESS handling (BIP342 feature)
const successScript = Buffer.from([
    OPCODES.OP_SUCCESS80,  // OP_SUCCESS variant
    OPCODES.OP_1           // This will not be executed
]);

const successResult = await interpreter.execute(successScript, [], sigHash);
console.log('OP_SUCCESS Result:', successResult.success); // Always true

// Custom opcode extension
interpreter.registerCustomOpcode(0x70, 'OP_CUSTOM', (stack, context) => {
    // Custom opcode implementation
    if (stack.length < 2) return false;
    const a = stack.pop();
    const b = stack.pop();
    stack.push(Buffer.concat([a, b]));
    return true;
});

// Batch script validation
const scripts = [script1, script2, script3];
const witnesses = [witness1, witness2, witness3];
const sigHashes = [sigHash1, sigHash2, sigHash3];

const batchResults = await interpreter.validateBatch(scripts, witnesses, sigHashes);
console.log('Batch Validation Results:', batchResults);
```

## API Reference

### Classes

#### `TapscriptInterpreter`
Main Tapscript interpreter class with BIP342 compliance.

**Constructor:**
```javascript
new TapscriptInterpreter(options = {})
```

**Options:**
- `enforceMinimalPush` (boolean) - Enforce minimal push encoding (default: true)
- `maxStackSize` (number) - Maximum stack size (default: 1000)
- `maxScriptSize` (number) - Maximum script size (default: 10000)
- `maxOpCount` (number) - Maximum operation count (default: 201)
- `enableOpSuccess` (boolean) - Enable OP_SUCCESS opcodes (default: true)
- `timeLimitMs` (number) - Execution time limit (default: 5000ms)
- `gasLimit` (number) - Gas limit for execution (default: 1000000)

**Instance Methods:**

##### `interpreter.execute(script, witness, sigHash, context = null)`
Executes a Tapscript with witness data.

**Parameters:**
- `script` (Buffer) - Script to execute
- `witness` (Array<Buffer>) - Witness stack items
- `sigHash` (Buffer) - 32-byte signature hash
- `context` (TapscriptExecutionContext) - Execution context (optional)

**Returns:**
- Object with execution result:
  - `success` (boolean) - Whether script executed successfully
  - `stack` (Array<Buffer>) - Final stack state
  - `altStack` (Array<Buffer>) - Final alt stack state
  - `gasUsed` (number) - Gas consumed during execution
  - `opCount` (number) - Operations executed
  - `executionTime` (number) - Execution time in milliseconds
  - `errors` (Array<string>) - Any execution errors

##### `interpreter.validateScript(script, witness, sigHash, context)`
Validates a Tapscript with comprehensive checks.

**Parameters:**
- `script` (Buffer) - Script to validate
- `witness` (Array<Buffer>) - Witness data
- `sigHash` (Buffer) - Signature hash
- `context` (TapscriptExecutionContext) - Execution context

**Returns:**
- Object with validation result:
  - `isValid` (boolean) - Overall validation result
  - `details` (Object) - Detailed validation information
    - `syntaxValid` (boolean) - Script syntax validation
    - `executionValid` (boolean) - Script execution validation
    - `signatureValid` (boolean) - Signature validation
    - `consensusValid` (boolean) - Consensus rule validation
  - `executionResult` (Object) - Full execution result
  - `securityChecks` (Object) - Security validation results

##### `interpreter.validateBatch(scripts, witnesses, sigHashes, contexts = [])`
Validates multiple scripts efficiently.

**Parameters:**
- `scripts` (Array<Buffer>) - Scripts to validate
- `witnesses` (Array<Array<Buffer>>) - Witness data for each script
- `sigHashes` (Array<Buffer>) - Signature hashes
- `contexts` (Array<TapscriptExecutionContext>) - Execution contexts

**Returns:**
- Object with batch validation results:
  - `overallValid` (boolean) - Whether all scripts are valid
  - `results` (Array<Object>) - Individual validation results
  - `statistics` (Object) - Batch execution statistics

##### `interpreter.registerCustomOpcode(opcode, name, handler)`
Registers custom opcode for extended functionality.

**Parameters:**
- `opcode` (number) - Opcode value (0x50-0x61 available for custom use)
- `name` (string) - Opcode name for debugging
- `handler` (Function) - Opcode execution function

#### `TapscriptExecutionContext`
Execution context for Tapscript validation.

**Constructor:**
```javascript
new TapscriptExecutionContext(options)
```

**Options:**
- `scriptVersion` (number) - Tapscript version (default: 0xc0)
- `inputIndex` (number) - Transaction input index
- `transaction` (Object) - Transaction data
- `utxos` (Array<Object>) - Previous outputs (UTXOs)
- `taprootAnnex` (Buffer) - Taproot annex data (optional)
- `codeseparatorPosition` (number) - Code separator position
- `executionData` (Object) - Additional execution data

### Tapscript Opcodes (BIP342)

#### Enhanced Opcodes
- **OP_CHECKSIG** - Schnorr signature verification (64 bytes)
- **OP_CHECKSIGVERIFY** - Checksig with verify semantics
- **OP_CHECKMULTISIG** - Disabled in Tapscript (OP_SUCCESS)
- **OP_CHECKMULTISIGVERIFY** - Disabled in Tapscript (OP_SUCCESS)

#### OP_SUCCESS Opcodes
BIP342 introduces OP_SUCCESS opcodes that make scripts unconditionally valid:
- `OP_SUCCESS80` through `OP_SUCCESS126` (even values)
- `OP_SUCCESS129` through `OP_SUCCESS132`
- `OP_SUCCESS134` through `OP_SUCCESS137`
- And others...

#### Resource Limits
```javascript
const TAPSCRIPT_LIMITS = {
  MAX_STACK_SIZE: 1000,
  MAX_SCRIPT_SIZE: 10000,
  MAX_OP_COUNT: 201,
  MAX_ELEMENT_SIZE: 520,
  MAX_SIGNATURE_SIZE: 64,
  MAX_PUBKEY_SIZE: 32
};
```

### Signature Hash Computation

#### Tapscript Signature Hash (BIP341)
- Uses tagged hash with "TapSighash" tag
- Includes additional Tapscript-specific data
- Different computation from legacy script signature hash

#### Signature Hash Types
- `SIGHASH_ALL` (0x01) - Sign all inputs and outputs
- `SIGHASH_NONE` (0x02) - Sign all inputs, no outputs
- `SIGHASH_SINGLE` (0x03) - Sign all inputs, corresponding output
- `SIGHASH_ANYONECANPAY` (0x80) - Sign only this input (flag)

### Security Features

- **Execution Limits** - Gas limits, operation count limits, time limits
- **Stack Management** - Stack size limits, element size limits
- **DoS Protection** - Resource consumption monitoring
- **Memory Safety** - Secure buffer handling and bounds checking
- **Nonce Validation** - Signature nonce validation for Schnorr signatures
- **Consensus Validation** - Full BIP342 consensus rule enforcement
- **Side-Channel Protection** - Timing attack prevention where applicable

### Script Number Handling

#### ScriptNum Implementation
```javascript
class ScriptNum {
  static encode(number, maxSize = 4) {
    // Encodes number as script number
  }
  
  static decode(buffer, maxSize = 4) {
    // Decodes script number from buffer
  }
}
```

#### Tapscript Changes
- **OP_SUCCESS** replaces disabled opcodes
- **64-byte signatures** for Schnorr (vs 71-73 bytes for ECDSA)
- **32-byte public keys** (x-only) for Schnorr
- **Enhanced signature hash** computation

### Error Handling

#### Error Categories
- **Syntax Errors** - Invalid script structure
- **Execution Errors** - Runtime execution failures
- **Resource Errors** - Resource limit exceeded
- **Consensus Errors** - Consensus rule violations
- **Security Errors** - Security validation failures

#### Error Codes
- `SCRIPT_ERR_INVALID_STACK_OPERATION` - Invalid stack operation
- `SCRIPT_ERR_STACK_SIZE` - Stack size limit exceeded
- `SCRIPT_ERR_SCRIPT_SIZE` - Script size limit exceeded
- `SCRIPT_ERR_OP_COUNT` - Operation count limit exceeded
- `SCRIPT_ERR_INVALID_SIGNATURE` - Invalid signature format
- `SCRIPT_ERR_SIG_HASHTYPE` - Invalid signature hash type
- `SCRIPT_ERR_SCHNORR_SIG_SIZE` - Invalid Schnorr signature size
- `SCRIPT_ERR_SCHNORR_SIG` - Schnorr signature verification failed
- `SCRIPT_ERR_TAPSCRIPT_VALIDATION` - Tapscript validation failed

### Performance Optimization

#### Execution Optimizations
- **Opcode caching** for frequently used operations
- **Stack pre-allocation** for known script patterns
- **Lazy evaluation** of complex operations
- **Batch signature verification** for multiple signatures

#### Memory Management
- **Stack pooling** to reduce allocations
- **Buffer reuse** for intermediate computations
- **Garbage collection** optimization
- **Memory limit enforcement**

### Testing and Validation

#### Self-Test Suite
```javascript
const testResults = await interpreter.runSelfTests();
console.log('Self-test results:', testResults);
```

#### Test Categories
- **Basic operations** - Arithmetic, logical, stack operations
- **Signature verification** - Schnorr signature tests
- **OP_SUCCESS handling** - OP_SUCCESS opcode tests
- **Resource limits** - Limit enforcement tests
- **Edge cases** - Boundary condition tests
- **Consensus compatibility** - Bitcoin Core compatibility

### Integration Examples

#### With Transaction Validation
```javascript
const isValid = await interpreter.validateScript(
  scriptPubKey,
  witness,
  sigHash,
  context
);
```

#### With Control Block Verification
```javascript
const controlBlock = Buffer.from('control_block_data');
const script = Buffer.from('tapscript_data');
const context = new TapscriptExecutionContext({
  controlBlock,
  merkleProof: tree.getProof(scriptIndex)
});
```

#### With Batch Processing
```javascript
const batchResults = await interpreter.validateBatch(
  transactionScripts,
  transactionWitnesses,
  signatureHashes
);
```

### Best Practices

1. **Always validate scripts** before execution
2. **Set appropriate limits** for resource consumption
3. **Use execution contexts** for proper validation
4. **Handle OP_SUCCESS** opcodes correctly
5. **Implement proper error handling** for all error types
6. **Cache interpreter instances** for performance
7. **Use batch validation** for multiple scripts
8. **Monitor resource usage** in production
9. **Keep up with consensus changes** and updates
10. **Test thoroughly** with edge cases and boundary conditions