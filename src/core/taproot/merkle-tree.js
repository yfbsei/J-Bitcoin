/**
 * @fileoverview Taproot merkle tree implementation for script path spending
 * @version 2.1.0
 * @author yfbsei
 * @license ISC
 */

import { createHash, timingSafeEqual, randomBytes } from 'node:crypto';

class MerkleTreeError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'MerkleTreeError';
    this.code = code;
    this.details = details;
  }
}

const MERKLE_CONSTANTS = {
  HASH_SIZE: 32,
  MAX_TREE_DEPTH: 128,
  MAX_SCRIPT_SIZE: 10000,
  MAX_LEAVES: 2 ** 16,
  TAPLEAF_TAG: 'TapLeaf',
  TAPBRANCH_TAG: 'TapBranch',
  TAPTWEAK_TAG: 'TapTweak',
  DEFAULT_LEAF_VERSION: 0xc0
};

class TaggedHash {
  static create(tag, data) {
    const tagHash = createHash('sha256').update(tag).digest();
    const taggedData = Buffer.concat([tagHash, tagHash, data]);
    return createHash('sha256').update(taggedData).digest();
  }

  static createTapLeaf(leafVersion, script) {
    const data = Buffer.concat([
      Buffer.from([leafVersion]),
      Buffer.from([script.length]),
      script
    ]);
    return this.create(MERKLE_CONSTANTS.TAPLEAF_TAG, data);
  }

  static createTapBranch(left, right) {
    const ordered = Buffer.compare(left, right) < 0
      ? Buffer.concat([left, right])
      : Buffer.concat([right, left]);
    return this.create(MERKLE_CONSTANTS.TAPBRANCH_TAG, ordered);
  }

  static createTapTweak(internalKey, merkleRoot = null) {
    const data = merkleRoot
      ? Buffer.concat([internalKey, merkleRoot])
      : internalKey;
    return this.create(MERKLE_CONSTANTS.TAPTWEAK_TAG, data);
  }
}

class TaprootMerkleTree {
  constructor(scripts, leafVersion = MERKLE_CONSTANTS.DEFAULT_LEAF_VERSION) {
    if (!Array.isArray(scripts) || scripts.length === 0) {
      throw new MerkleTreeError('Scripts array is required', 'INVALID_SCRIPTS');
    }

    if (scripts.length > MERKLE_CONSTANTS.MAX_LEAVES) {
      throw new MerkleTreeError('Too many scripts', 'TOO_MANY_LEAVES');
    }

    this.leafVersion = leafVersion;
    this.scripts = scripts;
    this.leaves = [];
    this.tree = [];

    this._buildTree();
  }

  _buildTree() {
    this.leaves = this.scripts.map((script, index) => ({
      script: Buffer.isBuffer(script) ? script : Buffer.from(script),
      leafVersion: this.leafVersion,
      hash: TaggedHash.createTapLeaf(
        this.leafVersion,
        Buffer.isBuffer(script) ? script : Buffer.from(script)
      ),
      index
    }));

    if (this.leaves.length === 1) {
      this.tree = [[this.leaves[0].hash]];
      this.root = this.leaves[0].hash;
      return;
    }

    let currentLevel = this.leaves.map(leaf => leaf.hash);
    this.tree = [currentLevel];

    while (currentLevel.length > 1) {
      const nextLevel = [];

      for (let i = 0; i < currentLevel.length; i += 2) {
        if (i + 1 < currentLevel.length) {
          const branch = TaggedHash.createTapBranch(currentLevel[i], currentLevel[i + 1]);
          nextLevel.push(branch);
        } else {
          nextLevel.push(currentLevel[i]);
        }
      }

      this.tree.push(nextLevel);
      currentLevel = nextLevel;
    }

    this.root = currentLevel[0];
  }

  getRoot() {
    return this.root;
  }

  getMerklePath(leafIndex) {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new MerkleTreeError('Invalid leaf index', 'INVALID_INDEX');
    }

    const path = [];
    let index = leafIndex;

    for (let level = 0; level < this.tree.length - 1; level++) {
      const currentLevel = this.tree[level];
      const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;

      if (siblingIndex < currentLevel.length) {
        path.push({
          hash: currentLevel[siblingIndex],
          position: index % 2 === 0 ? 'right' : 'left'
        });
      }

      index = Math.floor(index / 2);
    }

    return {
      leafIndex,
      leafHash: this.leaves[leafIndex].hash,
      hashes: path.map(p => p.hash),
      positions: path.map(p => p.position)
    };
  }

  verifyInclusion(leafIndex, leafHash) {
    const path = this.getMerklePath(leafIndex);
    let computedHash = leafHash;

    for (let i = 0; i < path.hashes.length; i++) {
      computedHash = TaggedHash.createTapBranch(computedHash, path.hashes[i]);
    }

    return computedHash.equals(this.root);
  }

  getLeaf(index) {
    if (index < 0 || index >= this.leaves.length) {
      throw new MerkleTreeError('Invalid leaf index', 'INVALID_INDEX');
    }
    return { ...this.leaves[index] };
  }

  getLeafCount() {
    return this.leaves.length;
  }

  getTreeDepth() {
    return this.tree.length;
  }

  toJSON() {
    return {
      root: this.root.toString('hex'),
      leafVersion: this.leafVersion,
      leafCount: this.leaves.length,
      depth: this.tree.length,
      leaves: this.leaves.map(leaf => ({
        hash: leaf.hash.toString('hex'),
        index: leaf.index
      }))
    };
  }
}

export {
  TaprootMerkleTree,
  TaggedHash,
  MerkleTreeError,
  MERKLE_CONSTANTS
};
