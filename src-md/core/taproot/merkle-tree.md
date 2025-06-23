# Taproot Merkle Tree (BIP341)

Comprehensive Taproot merkle tree implementation for script path construction and verification following BIP341 specification.

## Description

This module provides complete merkle tree functionality for Taproot script path spending including tree construction, leaf hashing, branch computation, and proof generation. It implements BIP341 tagged hashing for TapLeaf and TapBranch operations with comprehensive security features and optimization for complex script trees.

## Example

```javascript
import { 
    TaprootMerkleTree,
    TaggedHash,
    MERKLE_CONSTANTS 
} from 'j-bitcoin';

// Create individual script leaves
const script1 = Buffer.from([0x51]); // OP_1 (simple script)
const script2 = Buffer.from([0x63, 0x52]); // OP_IF OP_2
const script3 = Buffer.from([0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 OP_PUSHDATA(20)

const scripts = [script1, script2, script3];

// Build merkle tree from scripts
const merkleTree = TaprootMerkleTree.fromScripts(scripts);
console.log('Merkle Root:', merkleTree.root.toString('hex'));
console.log('Tree Depth:', merkleTree.depth);
console.log('Leaf Count:', merkleTree.leaves.length);

// Get merkle proof for specific script
const proofForScript1 = merkleTree.getProof(0); // Proof for first script
console.log('Merkle Proof:', proofForScript1.map(h => h.toString('hex')));

// Verify merkle proof
const leafHash = TaprootMerkleTree.hashLeaf(script1);
const isValidProof = TaprootMerkleTree.verifyProof(
    leafHash,
    proofForScript1,
    merkleTree.root
);
console.log('Proof Valid:', isValidProof);

// Create optimized tree (Huffman-style for frequency-based optimization)
const scriptFrequencies = [
    { script: script1, frequency: 0.7 }, // Most likely to be used
    { script: script2, frequency: 0.2 },
    { script: script3, frequency: 0.1 }
];

const optimizedTree = TaprootMerkleTree.createOptimized(scriptFrequencies);
console.log('Optimized Tree Depth:', optimizedTree.depth);
console.log('Average Proof Length:', optimizedTree.getAverageProofLength());

// Tagged hash utilities
const tapLeafHash = TaggedHash.tapLeaf(0xc0, script1);
console.log('TapLeaf Hash:', tapLeafHash.toString('hex'));

const tapBranchHash = TaggedHash.tapBranch(leafHash, tapLeafHash);
console.log('TapBranch Hash:', tapBranchHash.toString('hex'));

// Tree serialization for storage
const serialized = merkleTree.serialize();
console.log('Serialized Tree:', serialized);

const reconstructed = TaprootMerkleTree.deserialize(serialized);
console.log('Trees Equal:', merkleTree.equals(reconstructed));
```

## API Reference

### Classes

#### `TaprootMerkleTree`
Main class for Taproot merkle tree operations.

**Static Methods:**

##### `TaprootMerkleTree.fromScripts(scripts, options = {})`
Creates a merkle tree from an array of scripts.

**Parameters:**
- `scripts` (Array<Buffer>) - Array of script buffers
- `options` (Object) - Tree construction options
  - `leafVersion` (number) - Tapscript leaf version (default: 0xc0)
  - `optimization` (string) - Tree optimization strategy ('balanced', 'huffman', 'none')
  - `maxDepth` (number) - Maximum tree depth (default: 128)

**Returns:**
- `TaprootMerkleTree` - Constructed merkle tree instance

**Throws:**
- `MerkleTreeError` - If tree construction fails

##### `TaprootMerkleTree.fromLeaves(leafHashes)`
Creates a merkle tree from pre-computed leaf hashes.

**Parameters:**
- `leafHashes` (Array<Buffer>) - Array of 32-byte leaf hashes

**Returns:**
- `TaprootMerkleTree` - Merkle tree instance

##### `TaprootMerkleTree.createOptimized(scriptFrequencies)`
Creates frequency-optimized merkle tree using Huffman coding principles.

**Parameters:**
- `scriptFrequencies` (Array<Object>) - Scripts with frequency weights
  - `script` (Buffer) - Script content
  - `frequency` (number) - Usage frequency (0.0-1.0)

**Returns:**
- `TaprootMerkleTree` - Optimized merkle tree

**Instance Methods:**

##### `tree.getProof(leafIndex)`
Generates merkle proof for a specific leaf.

**Parameters:**
- `leafIndex` (number) - Index of leaf to generate proof for

**Returns:**
- `Array<Buffer>` - Array of 32-byte proof hashes

##### `tree.verifyLeaf(leafIndex, script)`
Verifies that a script matches the leaf at given index.

**Parameters:**
- `leafIndex` (number) - Leaf index to verify
- `script` (Buffer) - Script to verify

**Returns:**
- `boolean` - True if script matches leaf

##### `tree.getControlBlock(leafIndex, internalKey, parity)`
Generates control block for script path spending.

**Parameters:**
- `leafIndex` (number) - Index of script to spend
- `internalKey` (Buffer) - 32-byte internal public key
- `parity` (number) - Y-coordinate parity (0 or 1)

**Returns:**
- `Buffer` - Complete control block

##### `tree.serialize()`
Serializes merkle tree for storage or transmission.

**Returns:**
- `string` - Serialized tree data (JSON format)

##### `tree.getTreeInfo()`
Gets comprehensive tree information and statistics.

**Returns:**
- Object with tree information:
  - `root` (string) - Merkle root hash
  - `depth` (number) - Maximum tree depth
  - `leafCount` (number) - Number of leaves
  - `nodeCount` (number) - Total nodes in tree
  - `averageProofLength` (number) - Average proof path length
  - `efficiency` (number) - Tree efficiency score (0.0-1.0)

#### `TaggedHash`
Utility class for BIP340/BIP341 tagged hashing.

**Static Methods:**

##### `TaggedHash.tapLeaf(leafVersion, script)`
Computes TapLeaf tagged hash for script leaves.

**Parameters:**
- `leafVersion` (number) - Tapscript leaf version
- `script` (Buffer) - Script content

**Returns:**
- `Buffer` - 32-byte TapLeaf hash

**Formula:**
```
TapLeaf = TaggedHash("TapLeaf", leafVersion || script)
```

##### `TaggedHash.tapBranch(left, right)`
Computes TapBranch tagged hash for merkle branches.

**Parameters:**
- `left` (Buffer) - Left branch hash (32 bytes)
- `right` (Buffer) - Right branch hash (32 bytes)

**Returns:**
- `Buffer` - 32-byte TapBranch hash

**Formula:**
```
TapBranch = TaggedHash("TapBranch", sort(left, right))
```

##### `TaggedHash.tapTweak(internalKey, merkleRoot)`
Computes TapTweak hash for key tweaking.

**Parameters:**
- `internalKey` (Buffer) - 32-byte internal public key
- `merkleRoot` (Buffer) - 32-byte merkle root (empty for key-path only)

**Returns:**
- `Buffer` - 32-byte TapTweak hash

##### `TaggedHash.compute(tag, data)`
Computes generic tagged hash with custom tag.

**Parameters:**
- `tag` (string) - Hash tag for domain separation
- `data` (Buffer) - Data to hash

**Returns:**
- `Buffer` - 32-byte tagged hash

### Tree Construction Algorithms

#### Balanced Tree Construction
- Creates complete binary tree when possible
- Minimizes maximum proof length
- Optimal for uniform script usage patterns

#### Huffman-Optimized Construction
- Uses frequency weights to optimize tree structure
- Frequently used scripts get shorter proof paths
- Optimal for known usage patterns

#### Tree Balancing Strategies
```javascript
// Balanced construction
const balancedTree = TaprootMerkleTree.fromScripts(scripts, {
    optimization: 'balanced'
});

// Huffman optimization
const huffmanTree = TaprootMerkleTree.fromScripts(scripts, {
    optimization: 'huffman',
    frequencies: [0.6, 0.3, 0.1] // Must match script count
});
```

### Merkle Proof Verification

#### Proof Structure
```javascript
{
  leafHash: Buffer,        // 32-byte leaf hash
  proof: Array<Buffer>,    // Merkle proof path
  leafIndex: number,       // Position in tree
  merkleRoot: Buffer       // Expected root hash
}
```

#### Verification Algorithm
1. Start with leaf hash
2. For each proof element:
   - Determine order (leaf_index bit determines left/right)
   - Compute `TapBranch(current, proof_element)`
3. Final result should equal merkle root

### Security Features

- **Hash Ordering** - Consistent lexicographic ordering of branch hashes
- **Tagged Hashing** - Domain separation prevents hash collision attacks
- **Depth Limits** - Maximum tree depth prevents DoS attacks
- **Input Validation** - Comprehensive validation of all inputs
- **Proof Verification** - Cryptographic verification of merkle proofs
- **Memory Safety** - Secure buffer handling and bounds checking
- **Side-Channel Protection** - Constant-time operations where applicable

### Constants

#### `MERKLE_CONSTANTS`
Constants for merkle tree operations.

```javascript
{
  MAX_TREE_DEPTH: 128,              // Maximum merkle tree depth
  HASH_SIZE: 32,                    // SHA256 hash size
  LEAF_VERSION_TAPSCRIPT: 0xc0,     // Default Tapscript version
  MAX_SCRIPTS_PER_TREE: 2048,       // DoS protection limit
  TAPLEAF_TAG: "TapLeaf",           // Tagged hash tag
  TAPBRANCH_TAG: "TapBranch",       // Tagged hash tag
  TAPTWEAK_TAG: "TapTweak",         // Tagged hash tag
  TREE_EFFICIENCY_THRESHOLD: 0.8,   // Efficiency warning threshold
  MAX_SERIALIZED_SIZE: 1048576      // 1MB serialization limit
}
```

### Performance Optimization

#### Tree Construction
- **O(n log n)** for balanced trees
- **O(n²)** for Huffman optimization (one-time cost)
- **Caching** of intermediate computations

#### Proof Generation
- **O(log n)** time complexity
- **O(log n)** space complexity
- **Batch proof generation** for multiple leaves

#### Memory Usage
- **O(n)** for tree storage
- **O(log n)** for proof storage
- **Lazy evaluation** of non-essential nodes

### Tree Serialization Format

#### JSON Serialization
```javascript
{
  version: "1.0",
  leafVersion: 0xc0,
  leaves: ["hash1", "hash2", ...],
  structure: {
    type: "balanced" | "huffman",
    frequencies: [0.5, 0.3, 0.2], // For huffman trees
    metadata: { /* additional data */ }
  },
  root: "merkle_root_hash"
}
```

### Error Codes

- `INVALID_SCRIPT_COUNT` - Script array is empty or too large
- `INVALID_LEAF_VERSION` - Leaf version not supported
- `TREE_DEPTH_EXCEEDED` - Tree depth exceeds maximum
- `INVALID_LEAF_INDEX` - Leaf index out of range
- `PROOF_VERIFICATION_FAILED` - Merkle proof verification failed
- `TREE_CONSTRUCTION_FAILED` - Tree construction algorithm failed
- `SERIALIZATION_FAILED` - Tree serialization failed
- `DESERIALIZATION_FAILED` - Tree deserialization failed
- `HASH_COMPUTATION_FAILED` - Tagged hash computation failed

### Best Practices

1. **Use frequency optimization** for production applications
2. **Cache merkle trees** for repeatedly used script sets
3. **Validate proofs** before accepting transactions
4. **Implement depth limits** to prevent DoS attacks
5. **Use proper leaf versions** for different script types
6. **Store serialized trees** for quick reconstruction
7. **Monitor tree efficiency** and rebalance when needed
8. **Clear sensitive data** after tree operations

### Integration Examples

#### With Control Blocks
```javascript
const tree = TaprootMerkleTree.fromScripts(scripts);
const controlBlock = tree.getControlBlock(scriptIndex, internalKey, parity);
```

#### With Transaction Building
```javascript
const proof = tree.getProof(spendingScriptIndex);
const witness = [signature, script, controlBlock];
```

#### With Script Validation
```javascript
const isValid = tree.verifyLeaf(index, providedScript);
```