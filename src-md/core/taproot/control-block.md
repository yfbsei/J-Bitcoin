# Taproot Control Block (BIP341)

Enhanced Taproot control block implementation following BIP341 specification for script path spending.

## Description

This module implements complete BIP341 control block validation and processing for Taproot script path spending. It includes structure validation, merkle path verification, leaf version extraction, and integration with the Tapscript interpreter. The implementation provides comprehensive security features including DoS protection and timing attack prevention.

## Example

```javascript
import { 
    ControlBlock,
    ControlBlockValidator,
    CONTROL_BLOCK_CONSTANTS 
} from 'j-bitcoin';

// Create control block for script path spending
const leafVersion = 0xc0; // Tapscript version
const parity = 0; // Y-coordinate parity bit
const internalKey = Buffer.from('internal_public_key_32_bytes');
const merklePath = [
    Buffer.from('merkle_proof_hash_1_32_bytes'),
    Buffer.from('merkle_proof_hash_2_32_bytes')
];

const controlBlock = ControlBlock.create(leafVersion, parity, internalKey, merklePath);
console.log('Control Block:', controlBlock.toString('hex'));
console.log('Control Block Length:', controlBlock.length); // 33 + 32*path_length

// Parse existing control block
const existingControlBlock = Buffer.from('control_block_hex', 'hex');
const parsed = ControlBlock.parse(existingControlBlock);
console.log('Leaf Version:', parsed.leafVersion);
console.log('Parity:', parsed.parity);
console.log('Internal Key:', parsed.internalKey.toString('hex'));
console.log('Merkle Path Length:', parsed.merklePath.length);

// Validate control block structure
const isValid = ControlBlockValidator.validateStructure(existingControlBlock);
console.log('Structure Valid:', isValid);

// Verify merkle path
const scriptLeaf = Buffer.from('tapscript_content');
const merkleRoot = ControlBlock.computeMerkleRoot(scriptLeaf, parsed.merklePath);
console.log('Computed Merkle Root:', merkleRoot.toString('hex'));

// Validate complete control block with script
const validation = ControlBlock.validateWithScript(
    existingControlBlock,
    scriptLeaf,
    Buffer.from('expected_output_key_32_bytes')
);
console.log('Complete Validation:', validation.isValid);
console.log('Verification Details:', validation.details);
```

## API Reference

### Classes

#### `ControlBlock`
Main class for control block operations.

**Static Methods:**

##### `ControlBlock.create(leafVersion, parity, internalKey, merklePath)`
Creates a new control block for Taproot script path spending.

**Parameters:**
- `leafVersion` (number) - Tapscript leaf version (default: 0xc0)
- `parity` (number) - Y-coordinate parity bit (0 or 1)
- `internalKey` (Buffer) - 32-byte internal public key
- `merklePath` (Array<Buffer>) - Array of 32-byte merkle proof hashes

**Returns:**
- `Buffer` - Encoded control block

**Throws:**
- `ControlBlockError` - If parameters are invalid

##### `ControlBlock.parse(controlBlock)`
Parses a control block into its components.

**Parameters:**
- `controlBlock` (Buffer) - Control block to parse

**Returns:**
- Object with parsed components:
  - `leafVersion` (number) - Extracted leaf version
  - `parity` (number) - Y-coordinate parity
  - `internalKey` (Buffer) - 32-byte internal key
  - `merklePath` (Array<Buffer>) - Merkle proof path
  - `isValid` (boolean) - Structure validity

##### `ControlBlock.validateWithScript(controlBlock, script, expectedOutputKey)`
Validates control block with associated script and expected output.

**Parameters:**
- `controlBlock` (Buffer) - Control block to validate
- `script` (Buffer) - Tapscript content
- `expectedOutputKey` (Buffer) - Expected Taproot output key

**Returns:**
- Object with validation result:
  - `isValid` (boolean) - Overall validation result
  - `details` (Object) - Detailed validation information
    - `structureValid` (boolean) - Structure validation
    - `merkleValid` (boolean) - Merkle path validation
    - `outputKeyValid` (boolean) - Output key validation
  - `computedOutputKey` (Buffer) - Computed output key
  - `merkleRoot` (Buffer) - Computed merkle root

##### `ControlBlock.computeMerkleRoot(scriptLeaf, merklePath)`
Computes merkle root from script leaf and proof path.

**Parameters:**
- `scriptLeaf` (Buffer) - Tapscript leaf content
- `merklePath` (Array<Buffer>) - Merkle proof path

**Returns:**
- `Buffer` - 32-byte merkle root

#### `ControlBlockValidator`
Validation utilities for control blocks.

**Static Methods:**

##### `ControlBlockValidator.validateStructure(controlBlock)`
Validates control block structure according to BIP341.

**Parameters:**
- `controlBlock` (Buffer) - Control block to validate

**Returns:**
- `boolean` - True if structure is valid

**Validation Rules:**
- Length must be 33 + 32*m bytes (m = merkle path length)
- Minimum length: 33 bytes
- Maximum length: 33 + 32*128 bytes
- Must be properly aligned

##### `ControlBlockValidator.validateLeafVersion(leafVersion)`
Validates Tapscript leaf version.

**Parameters:**
- `leafVersion` (number) - Leaf version to validate

**Returns:**
- `boolean` - True if valid leaf version

**Valid Versions:**
- 0xc0: Tapscript (BIP342)
- Future versions must have even parity in bits

##### `ControlBlockValidator.validateMerklePath(merklePath)`
Validates merkle path components.

**Parameters:**
- `merklePath` (Array<Buffer>) - Merkle path to validate

**Returns:**
- `boolean` - True if path is valid

### Control Block Structure

#### BIP341 Control Block Format
```
control_block = leaf_version || parity || internal_key || merkle_path

Where:
- leaf_version: 1 byte (includes parity in LSB)
- internal_key: 32 bytes
- merkle_path: 32 * path_length bytes
```

#### Leaf Version Encoding
```
leaf_version_byte = (leaf_version & 0xfe) | (parity & 0x01)

Where:
- leaf_version: Actual leaf version (even numbers)
- parity: Y-coordinate parity of output key
```

### Merkle Path Verification

#### Path Computation Algorithm
1. Start with script leaf hash: `TapLeaf = TaggedHash("TapLeaf", leaf_version || script)`
2. For each merkle path element:
   - If current < path_element: `hash = TaggedHash("TapBranch", current || path_element)`
   - Else: `hash = TaggedHash("TapBranch", path_element || current)`
3. Final hash is merkle root

#### Output Key Derivation
```
tweak = TaggedHash("TapTweak", internal_key || merkle_root)
output_key = internal_key + G * tweak
```

### Security Features

- **Structure Validation** - Comprehensive BIP341 compliance checking
- **Merkle Path Verification** - Cryptographic merkle proof validation
- **Timing Attack Prevention** - Constant-time operations where applicable
- **DoS Protection** - Execution limits and rate limiting
- **Memory Safety** - Secure buffer handling and bounds checking
- **Input Sanitization** - Thorough validation of all inputs

### Constants

#### `CONTROL_BLOCK_CONSTANTS`
Constants for control block operations.

```javascript
{
  BASE_SIZE: 33,                    // Minimum control block size
  HASH_SIZE: 32,                    // Merkle path element size
  MIN_SIZE: 33,                     // Absolute minimum size
  MAX_SIZE: 33 + (32 * 128),        // Maximum size (128 levels)
  LEAF_VERSION_MASK: 0xfe,          // Mask for leaf version
  PARITY_MASK: 0x01,                // Mask for parity bit
  DEFAULT_LEAF_VERSION: 0xc0,       // Default Tapscript version
  MAX_MERKLE_DEPTH: 128,            // Maximum merkle depth
  MAX_VALIDATIONS_PER_SECOND: 50,   // Rate limiting
  TAPTWEAK_TAG: "TapTweak",         // Tagged hash tag
  TAPLEAF_TAG: "TapLeaf",           // Tagged hash tag
  TAPBRANCH_TAG: "TapBranch"        // Tagged hash tag
}
```

### Tagged Hash Implementation

#### BIP340 Tagged Hash
```javascript
TaggedHash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)
```

#### Taproot-Specific Tags
- **TapLeaf**: Hash individual script leaves
- **TapBranch**: Hash merkle tree branches  
- **TapTweak**: Generate key tweaks for output keys

### Error Codes

- `INVALID_CONTROL_BLOCK_SIZE` - Control block size invalid
- `INVALID_LEAF_VERSION` - Leaf version not supported
- `INVALID_INTERNAL_KEY` - Internal key format invalid
- `INVALID_MERKLE_PATH` - Merkle path malformed
- `MERKLE_VERIFICATION_FAILED` - Merkle proof verification failed
- `OUTPUT_KEY_MISMATCH` - Computed output key doesn't match expected
- `STRUCTURE_VALIDATION_FAILED` - Control block structure invalid
- `RATE_LIMIT_EXCEEDED` - Too many validation requests

### Best Practices

1. **Validate structure first** before processing contents
2. **Use constant-time operations** for sensitive comparisons
3. **Implement rate limiting** for public validation endpoints
4. **Cache merkle computations** when possible
5. **Clear sensitive data** after use
6. **Use proper tagged hashing** for all Taproot operations
7. **Validate leaf versions** against supported versions
8. **Implement proper error handling** without information leakage

### Performance Notes

- Control block parsing: ~0.1-0.3ms
- Merkle path verification: ~0.5-2ms (depth dependent)
- Structure validation: ~0.1ms
- Output key computation: ~1-3ms
- Complete validation: ~2-8ms depending on path length