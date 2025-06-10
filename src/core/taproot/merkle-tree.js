/**
 * @fileoverview Enhanced Taproot merkle tree implementation for script path spending
 * 
 * This module implements complete BIP341 merkle tree construction for Taproot script
 * trees, including TapLeaf and TapBranch hash computation, tree building algorithms,
 * and merkle path generation for script inclusion proofs.
 * 
 * SECURITY FEATURES:
 * - Comprehensive input validation and DoS protection
 * - Lexicographic ordering for deterministic tree construction
 * - Secure memory management for tree operations
 * - Rate limiting and execution time validation
 * - Integration with existing security utilities
 * 
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki|BIP341 - Taproot: SegWit version 1 spending rules}
 * @author yfbsei
 * @version 2.1.0
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Merkle tree specific error class
 */
class MerkleTreeError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'MerkleTreeError';
        this.code = code;
        this.details = details;
        this.timestamp = Date.now();
    }
}

/**
 * Taproot merkle tree constants following BIP341
 */
const MERKLE_CONSTANTS = {
    // Hash sizes and limits
    HASH_SIZE: 32,
    MAX_TREE_DEPTH: 128,
    MAX_SCRIPT_SIZE: 10000,
    MAX_LEAVES: 2 ** 16, // Reasonable limit to prevent DoS

    // BIP341 tagged hash tags
    TAPLEAF_TAG: "TapLeaf",
    TAPBRANCH_TAG: "TapBranch",
    TAPTWEAK_TAG: "TapTweak",

    // Security limits
    MAX_TREE_CONSTRUCTION_TIME_MS: 10000,
    MAX_VALIDATIONS_PER_SECOND: 50,

    // Default leaf version
    DEFAULT_LEAF_VERSION: 0xc0
};

/**
 * @typedef {Object} TapLeaf
 * @property {Buffer} script - The script content
 * @property {number} leafVersion - Leaf version (default 0xc0)
 * @property {Buffer} hash - TapLeaf hash
 * @property {number} depth - Depth in the tree
 * @property {string} path - Binary path to this leaf
 */

/**
 * @typedef {Object} TapBranch
 * @property {Buffer} leftHash - Left child hash
 * @property {Buffer} rightHash - Right child hash
 * @property {Buffer} hash - TapBranch hash
 * @property {number} depth - Depth in the tree
 */

/**
 * @typedef {Object} MerklePath
 * @property {Buffer[]} hashes - Array of sibling hashes for proof
 * @property {boolean[]} directions - Array indicating left/right direction
 * @property {number} leafIndex - Index of the leaf in the tree
 * @property {Buffer} leafHash - Hash of the target leaf
 */

/**
 * Enhanced security utilities for merkle tree operations
 */
class MerkleSecurityUtils {
    static validationHistory = new Map();
    static lastCleanup = Date.now();

    /**
     * Rate limiting for tree operations
     */
    static checkRateLimit(operation = 'merkle-operation') {
        const now = Date.now();
        const secondKey = `${operation}-${Math.floor(now / 1000)}`;
        const currentCount = this.validationHistory.get(secondKey) || 0;

        if (currentCount >= MERKLE_CONSTANTS.MAX_VALIDATIONS_PER_SECOND) {
            throw new MerkleTreeError(
                `Rate limit exceeded for ${operation}`,
                'RATE_LIMIT_EXCEEDED',
                { operation, currentCount }
            );
        }

        this.validationHistory.set(secondKey, currentCount + 1);

        // Cleanup old entries
        if (now - this.lastCleanup > 60000) {
            const cutoff = Math.floor(now / 1000) - 60;
            for (const [key] of this.validationHistory) {
                const keyTime = parseInt(key.split('-').pop());
                if (keyTime < cutoff) {
                    this.validationHistory.delete(key);
                }
            }
            this.lastCleanup = now;
        }
    }

    /**
     * Validates tree construction time
     */
    static validateConstructionTime(startTime, operation = 'tree construction') {
        const elapsed = Date.now() - startTime;
        if (elapsed > MERKLE_CONSTANTS.MAX_TREE_CONSTRUCTION_TIME_MS) {
            throw new MerkleTreeError(
                `${operation} timeout: ${elapsed}ms > ${MERKLE_CONSTANTS.MAX_TREE_CONSTRUCTION_TIME_MS}ms`,
                'CONSTRUCTION_TIMEOUT',
                { elapsed, maxTime: MERKLE_CONSTANTS.MAX_TREE_CONSTRUCTION_TIME_MS }
            );
        }
    }

    /**
     * Constant-time hash comparison
     */
    static constantTimeHashEqual(a, b) {
        if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
            return false;
        }
        if (a.length !== MERKLE_CONSTANTS.HASH_SIZE || b.length !== MERKLE_CONSTANTS.HASH_SIZE) {
            return false;
        }

        try {
            return timingSafeEqual(a, b);
        } catch (error) {
            let result = 0;
            for (let i = 0; i < MERKLE_CONSTANTS.HASH_SIZE; i++) {
                result |= a[i] ^ b[i];
            }
            return result === 0;
        }
    }

    /**
     * Secure memory clearing for hash data
     */
    static secureClear(buffer) {
        if (Buffer.isBuffer(buffer)) {
            const randomData = randomBytes(buffer.length);
            randomData.copy(buffer);
            buffer.fill(0);
        }
    }

    /**
     * Validates script content and size
     */
    static validateScript(script, fieldName = 'script') {
        if (!Buffer.isBuffer(script)) {
            throw new MerkleTreeError(
                `${fieldName} must be a Buffer`,
                'INVALID_SCRIPT_TYPE'
            );
        }

        if (script.length === 0) {
            throw new MerkleTreeError(
                `${fieldName} cannot be empty`,
                'EMPTY_SCRIPT'
            );
        }

        if (script.length > MERKLE_CONSTANTS.MAX_SCRIPT_SIZE) {
            throw new MerkleTreeError(
                `${fieldName} too large: ${script.length} > ${MERKLE_CONSTANTS.MAX_SCRIPT_SIZE}`,
                'SCRIPT_TOO_LARGE',
                { actualSize: script.length, maxSize: MERKLE_CONSTANTS.MAX_SCRIPT_SIZE }
            );
        }
    }

    /**
     * Validates hash format
     */
    static validateHash(hash, fieldName = 'hash') {
        if (!Buffer.isBuffer(hash)) {
            throw new MerkleTreeError(
                `${fieldName} must be a Buffer`,
                'INVALID_HASH_TYPE'
            );
        }

        if (hash.length !== MERKLE_CONSTANTS.HASH_SIZE) {
            throw new MerkleTreeError(
                `${fieldName} must be ${MERKLE_CONSTANTS.HASH_SIZE} bytes, got ${hash.length}`,
                'INVALID_HASH_SIZE',
                { expectedSize: MERKLE_CONSTANTS.HASH_SIZE, actualSize: hash.length }
            );
        }
    }
}

/**
 * BIP341 tagged hash implementation
 */
class TaggedHash {
    /**
     * Create a BIP341 tagged hash
     */
    static create(tag, data) {
        if (typeof tag !== 'string') {
            throw new MerkleTreeError('Tag must be a string', 'INVALID_TAG_TYPE');
        }

        if (!Buffer.isBuffer(data)) {
            throw new MerkleTreeError('Data must be a Buffer', 'INVALID_DATA_TYPE');
        }

        const tagHash = createHash('sha256').update(Buffer.from(tag, 'utf8')).digest();
        const taggedData = Buffer.concat([tagHash, tagHash, data]);
        return createHash('sha256').update(taggedData).digest();
    }

    /**
     * Create TapLeaf hash according to BIP341
     */
    static createTapLeaf(leafVersion, script) {
        MerkleSecurityUtils.validateScript(script, 'TapLeaf script');

        if (!Number.isInteger(leafVersion) || leafVersion < 0 || leafVersion > 255) {
            throw new MerkleTreeError(
                `Invalid leaf version: ${leafVersion}`,
                'INVALID_LEAF_VERSION'
            );
        }

        // TapLeaf = tagged_hash("TapLeaf", leaf_version || compact_size(script) || script)
        const leafVersionByte = Buffer.from([leafVersion]);
        const scriptLength = this.encodeCompactSize(script.length);
        const data = Buffer.concat([leafVersionByte, scriptLength, script]);

        return this.create(MERKLE_CONSTANTS.TAPLEAF_TAG, data);
    }

    /**
     * Create TapBranch hash according to BIP341
     */
    static createTapBranch(leftHash, rightHash) {
        MerkleSecurityUtils.validateHash(leftHash, 'left hash');
        MerkleSecurityUtils.validateHash(rightHash, 'right hash');

        // TapBranch = tagged_hash("TapBranch", left_hash || right_hash)
        // where left_hash and right_hash are lexicographically ordered
        const [first, second] = this.lexicographicOrder(leftHash, rightHash);
        const data = Buffer.concat([first, second]);

        return this.create(MERKLE_CONSTANTS.TAPBRANCH_TAG, data);
    }

    /**
     * Create TapTweak hash for key tweaking
     */
    static createTapTweak(internalKey, merkleRoot = null) {
        MerkleSecurityUtils.validateHash(internalKey, 'internal key');

        let data = Buffer.from(internalKey);
        if (merkleRoot) {
            MerkleSecurityUtils.validateHash(merkleRoot, 'merkle root');
            data = Buffer.concat([internalKey, merkleRoot]);
        }

        return this.create(MERKLE_CONSTANTS.TAPTWEAK_TAG, data);
    }

    /**
     * Encode value as compact size (Bitcoin varint format)
     */
    static encodeCompactSize(value) {
        if (value < 0) {
            throw new MerkleTreeError('Value cannot be negative', 'NEGATIVE_VALUE');
        }

        if (value < 0xfd) {
            return Buffer.from([value]);
        } else if (value <= 0xffff) {
            const buffer = Buffer.allocUnsafe(3);
            buffer[0] = 0xfd;
            buffer.writeUInt16LE(value, 1);
            return buffer;
        } else if (value <= 0xffffffff) {
            const buffer = Buffer.allocUnsafe(5);
            buffer[0] = 0xfe;
            buffer.writeUInt32LE(value, 1);
            return buffer;
        } else {
            const buffer = Buffer.allocUnsafe(9);
            buffer[0] = 0xff;
            buffer.writeBigUInt64LE(BigInt(value), 1);
            return buffer;
        }
    }

    /**
     * Order hashes lexicographically
     */
    static lexicographicOrder(hash1, hash2) {
        const comparison = Buffer.compare(hash1, hash2);
        return comparison <= 0 ? [hash1, hash2] : [hash2, hash1];
    }
}

/**
 * Taproot merkle tree implementation for script path spending
 */
class TaprootMerkleTree {
    constructor() {
        this.leaves = [];
        this.branches = [];
        this.root = null;
        this.builtAt = null;
        this.leafMap = new Map(); // For O(1) hash lookups
    }

    /**
     * Add a script leaf to the tree
     */
    addLeaf(script, leafVersion = MERKLE_CONSTANTS.DEFAULT_LEAF_VERSION) {
        try {
            MerkleSecurityUtils.checkRateLimit('add-leaf');
            MerkleSecurityUtils.validateScript(script, 'leaf script');

            if (this.leaves.length >= MERKLE_CONSTANTS.MAX_LEAVES) {
                throw new MerkleTreeError(
                    `Maximum leaves exceeded: ${MERKLE_CONSTANTS.MAX_LEAVES}`,
                    'MAX_LEAVES_EXCEEDED'
                );
            }

            const leafHash = TaggedHash.createTapLeaf(leafVersion, script);

            const leaf = {
                script: Buffer.from(script),
                leafVersion,
                hash: leafHash,
                depth: 0,
                path: '',
                index: this.leaves.length
            };

            this.leaves.push(leaf);
            this.leafMap.set(leafHash.toString('hex'), leaf);
            this.root = null; // Invalidate cached root

            return leaf;

        } catch (error) {
            if (error instanceof MerkleTreeError) {
                throw error;
            }
            throw new MerkleTreeError(
                `Failed to add leaf: ${error.message}`,
                'ADD_LEAF_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Build the complete merkle tree
     */
    buildTree() {
        const startTime = Date.now();

        try {
            MerkleSecurityUtils.checkRateLimit('build-tree');

            if (this.leaves.length === 0) {
                throw new MerkleTreeError(
                    'Cannot build tree with no leaves',
                    'NO_LEAVES'
                );
            }

            // Single leaf - no tree needed
            if (this.leaves.length === 1) {
                this.root = this.leaves[0].hash;
                this.leaves[0].depth = 0;
                this.leaves[0].path = '';
                this.builtAt = Date.now();
                return this.root;
            }

            // Build tree bottom-up using proper algorithm
            let currentLevel = this.leaves.map((leaf, index) => ({
                hash: leaf.hash,
                leafIndex: index,
                isLeaf: true,
                originalIndex: index
            }));

            let depth = 0;
            this.branches = [];

            while (currentLevel.length > 1) {
                MerkleSecurityUtils.validateConstructionTime(startTime);

                const nextLevel = [];
                depth++;

                // Process pairs
                for (let i = 0; i < currentLevel.length; i += 2) {
                    const left = currentLevel[i];
                    let right = currentLevel[i + 1];

                    // Handle odd number of nodes by duplicating the last one
                    if (!right) {
                        right = { ...left };
                    }

                    const branchHash = TaggedHash.createTapBranch(left.hash, right.hash);

                    const branch = {
                        leftHash: left.hash,
                        rightHash: right.hash,
                        hash: branchHash,
                        depth: depth,
                        leftChild: left,
                        rightChild: right !== left ? right : null
                    };

                    this.branches.push(branch);

                    nextLevel.push({
                        hash: branchHash,
                        isLeaf: false,
                        branchIndex: this.branches.length - 1,
                        leftChild: left,
                        rightChild: right !== left ? right : null
                    });
                }

                currentLevel = nextLevel;
            }

            this.root = currentLevel[0].hash;
            this._updateLeafPaths();
            this.builtAt = Date.now();

            MerkleSecurityUtils.validateConstructionTime(startTime, 'tree construction');

            return this.root;

        } catch (error) {
            if (error instanceof MerkleTreeError) {
                throw error;
            }
            throw new MerkleTreeError(
                `Tree construction failed: ${error.message}`,
                'TREE_CONSTRUCTION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Update leaf paths after tree construction
     */
    _updateLeafPaths() {
        if (this.leaves.length === 1) {
            this.leaves[0].path = '';
            this.leaves[0].depth = 0;
            return;
        }

        // Build a reverse lookup from hash to node for efficient path finding
        const hashToNode = new Map();

        // Add leaves to lookup
        this.leaves.forEach((leaf, index) => {
            hashToNode.set(leaf.hash.toString('hex'), {
                type: 'leaf',
                index: index,
                hash: leaf.hash
            });
        });

        // Add branches to lookup
        this.branches.forEach((branch, index) => {
            hashToNode.set(branch.hash.toString('hex'), {
                type: 'branch',
                index: index,
                hash: branch.hash,
                leftHash: branch.leftHash,
                rightHash: branch.rightHash
            });
        });

        // Find path for each leaf
        this.leaves.forEach((leaf, index) => {
            const pathInfo = this._findLeafPathNew(leaf.hash, hashToNode);
            if (pathInfo) {
                leaf.path = pathInfo.path;
                leaf.depth = pathInfo.depth;
            }
        });
    }

    /**
     * Find path to a specific leaf hash using efficient lookup
     */
    _findLeafPathNew(targetHash, hashToNode) {
        const targetHex = targetHash.toString('hex');

        // Start from the leaf
        const leafNode = hashToNode.get(targetHex);
        if (!leafNode || leafNode.type !== 'leaf') {
            return null;
        }

        // Build path by traversing up through parents
        let currentHash = targetHash;
        let path = '';
        let depth = 0;

        // Search for parent branches
        while (true) {
            let foundParent = false;

            for (const branch of this.branches) {
                const leftHex = branch.leftHash.toString('hex');
                const rightHex = branch.rightHash.toString('hex');
                const currentHex = currentHash.toString('hex');

                if (leftHex === currentHex) {
                    path = '0' + path; // Left child
                    currentHash = branch.hash;
                    depth++;
                    foundParent = true;
                    break;
                } else if (rightHex === currentHex) {
                    path = '1' + path; // Right child
                    currentHash = branch.hash;
                    depth++;
                    foundParent = true;
                    break;
                }
            }

            if (!foundParent) {
                // Reached root
                break;
            }
        }

        return { path, depth };
    }

    /**
     * Generate merkle path for a specific leaf
     */
    getMerklePath(leafIndex) {
        try {
            MerkleSecurityUtils.checkRateLimit('get-merkle-path');

            if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= this.leaves.length) {
                throw new MerkleTreeError(
                    `Invalid leaf index: ${leafIndex}`,
                    'INVALID_LEAF_INDEX',
                    { leafIndex, maxIndex: this.leaves.length - 1 }
                );
            }

            if (!this.root) {
                throw new MerkleTreeError(
                    'Tree not built yet - call buildTree() first',
                    'TREE_NOT_BUILT'
                );
            }

            const leaf = this.leaves[leafIndex];
            const path = {
                hashes: [],
                directions: [], // true = right, false = left
                leafIndex: leafIndex,
                leafHash: leaf.hash,
                merkleRoot: this.root
            };

            // Single leaf case
            if (this.leaves.length === 1) {
                return path;
            }

            // Build path by traversing from leaf to root
            let currentHash = leaf.hash;

            while (true) {
                let foundParent = false;

                for (const branch of this.branches) {
                    const leftHex = branch.leftHash.toString('hex');
                    const rightHex = branch.rightHash.toString('hex');
                    const currentHex = currentHash.toString('hex');

                    if (leftHex === currentHex) {
                        // Current node is left child, sibling is right
                        path.hashes.push(branch.rightHash);
                        path.directions.push(false); // We are left child
                        currentHash = branch.hash;
                        foundParent = true;
                        break;
                    } else if (rightHex === currentHex) {
                        // Current node is right child, sibling is left
                        path.hashes.push(branch.leftHash);
                        path.directions.push(true); // We are right child
                        currentHash = branch.hash;
                        foundParent = true;
                        break;
                    }
                }

                if (!foundParent) {
                    // Reached root
                    break;
                }
            }

            return path;

        } catch (error) {
            if (error instanceof MerkleTreeError) {
                throw error;
            }
            throw new MerkleTreeError(
                `Merkle path generation failed: ${error.message}`,
                'MERKLE_PATH_FAILED',
                { originalError: error.message, leafIndex }
            );
        }
    }

    /**
     * Verify a merkle path proof
     */
    static verifyMerklePath(leaf, merklePath, expectedRoot) {
        try {
            MerkleSecurityUtils.checkRateLimit('verify-merkle-path');
            MerkleSecurityUtils.validateHash(leaf.hash, 'leaf hash');
            MerkleSecurityUtils.validateHash(expectedRoot, 'expected root');

            if (!merklePath || typeof merklePath !== 'object') {
                throw new MerkleTreeError('Invalid merkle path object', 'INVALID_MERKLE_PATH');
            }

            const { hashes, directions } = merklePath;

            if (!Array.isArray(hashes) || !Array.isArray(directions)) {
                throw new MerkleTreeError(
                    'Merkle path must have hashes and directions arrays',
                    'INVALID_MERKLE_PATH_FORMAT'
                );
            }

            if (hashes.length !== directions.length) {
                throw new MerkleTreeError(
                    'Hashes and directions arrays must have same length',
                    'MERKLE_PATH_LENGTH_MISMATCH'
                );
            }

            if (hashes.length > MERKLE_CONSTANTS.MAX_TREE_DEPTH) {
                throw new MerkleTreeError(
                    `Merkle path too deep: ${hashes.length} > ${MERKLE_CONSTANTS.MAX_TREE_DEPTH}`,
                    'MERKLE_PATH_TOO_DEEP'
                );
            }

            // Verify path by computing root
            let currentHash = leaf.hash;

            for (let i = 0; i < hashes.length; i++) {
                const siblingHash = hashes[i];
                const isRightChild = directions[i];

                MerkleSecurityUtils.validateHash(siblingHash, `sibling hash at level ${i}`);

                // Compute parent hash
                currentHash = TaggedHash.createTapBranch(
                    isRightChild ? siblingHash : currentHash,
                    isRightChild ? currentHash : siblingHash
                );
            }

            return MerkleSecurityUtils.constantTimeHashEqual(currentHash, expectedRoot);

        } catch (error) {
            if (error instanceof MerkleTreeError) {
                throw error;
            }
            throw new MerkleTreeError(
                `Merkle path verification failed: ${error.message}`,
                'MERKLE_PATH_VERIFICATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Get leaf by hash (O(1) lookup)
     */
    getLeafByHash(hash) {
        const hashHex = Buffer.isBuffer(hash) ? hash.toString('hex') : hash;
        return this.leafMap.get(hashHex);
    }

    /**
     * Get tree summary with security metrics
     */
    getSummary() {
        return {
            leaves: this.leaves.length,
            branches: this.branches.length,
            root: this.root?.toString('hex'),
            maxDepth: this.leaves.length > 0 ? Math.max(...this.leaves.map(leaf => leaf.depth || 0)) : 0,
            builtAt: this.builtAt,
            isBuilt: this.root !== null,
            securityMetrics: {
                leafCount: this.leaves.length,
                maxAllowedLeaves: MERKLE_CONSTANTS.MAX_LEAVES,
                treeDepth: this.root ? Math.max(...this.leaves.map(leaf => leaf.depth || 0)) : 0,
                maxAllowedDepth: MERKLE_CONSTANTS.MAX_TREE_DEPTH
            }
        };
    }

    /**
     * Clear sensitive tree data
     */
    destroy() {
        try {
            console.warn('⚠️  Destroying merkle tree - clearing sensitive data');

            // Clear leaf data
            this.leaves.forEach(leaf => {
                MerkleSecurityUtils.secureClear(leaf.script);
                MerkleSecurityUtils.secureClear(leaf.hash);
            });

            // Clear branch data
            this.branches.forEach(branch => {
                MerkleSecurityUtils.secureClear(branch.leftHash);
                MerkleSecurityUtils.secureClear(branch.rightHash);
                MerkleSecurityUtils.secureClear(branch.hash);
            });

            // Clear root
            if (this.root) {
                MerkleSecurityUtils.secureClear(this.root);
            }

            this.leaves = [];
            this.branches = [];
            this.leafMap.clear();
            this.root = null;

            console.log('✅ Merkle tree destroyed securely');

        } catch (error) {
            console.error('❌ Merkle tree destruction failed:', error.message);
        }
    }
}

export {
    MerkleTreeError,
    MerkleSecurityUtils,
    TaggedHash,
    TaprootMerkleTree,
    MERKLE_CONSTANTS
};