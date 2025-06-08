# Taproot Merkle Tree — `merkle-tree.js`

Builds and verifies Taproot script trees as described in [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki). Provides tagged hashing for leaves and branches and deterministic lexicographic ordering.

Features:

- 🌲 Create TapLeaf and TapBranch hashes
- 🔗 Generate merkle paths for inclusion proofs
- 🧹 Secure memory cleanup helpers

---

## 🧪 Example

```js
import { TaprootMerkleTree } from './merkle-tree.js';

const tree = new TaprootMerkleTree([
  Buffer.from('51'),      // OP_TRUE leaf
  Buffer.from('6a'),      // OP_RETURN leaf
]);
console.log(tree.root.toString('hex'));
```

---

## 🧠 API Reference

### `new TaprootMerkleTree(scripts, leafVersion = 0xc0)`
Creates a tree from an array of script buffers.

### `getMerklePath(leafIndex)`
Returns `{hashes, directions}` arrays proving inclusion of a leaf.

### `destroy()`
Securely wipes all internal buffers.

**Exports:** `MerkleTreeError`, `MerkleSecurityUtils`, `TaggedHash`, `TaprootMerkleTree`, `MERKLE_CONSTANTS`.

