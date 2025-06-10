/**
 * @fileoverview Enhanced Taproot control block implementation following BIP341
 * 
 * This module implements complete BIP341 control block validation including
 * structure validation, merkle path verification, leaf version extraction,
 * and integration with the Tapscript interpreter and merkle tree modules.
 * 
 * SECURITY FEATURES:
 * - Comprehensive control block structure validation (33+32m bytes)
 * - Secure merkle path verification with timing attack protection
 * - Integration with existing security utilities and validation framework
 * - DoS protection with execution limits and rate limiting
 * - Memory safety with secure buffer handling
 * 
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki|BIP341 - Taproot: SegWit version 1 spending rules}
 * @author yfbsei
 * @version 2.1.0
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { TaprootMerkleTree, TaggedHash, MERKLE_CONSTANTS } from './merkle-tree.js';
import { TAPSCRIPT_CONSTANTS } from './tapscript-interpreter.js';
import { CRYPTO_CONSTANTS } from '../constants.js';
import {
    validateNumberRange,
    validateBufferLength,
    assertValid,
    ValidationError
} from '../../utils/validation.js';

/**
 * Control block specific error class
 */
class ControlBlockError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'ControlBlockError';
        this.code = code;
        this.details = details;
        this.timestamp = Date.now();
    }
}

/**
 * BIP341 control block constants and validation parameters
 */
const CONTROL_BLOCK_CONSTANTS = {
    // Structure specifications
    BASE_SIZE: 33,                          // Leaf version + parity + internal key
    HASH_SIZE: 32,                          // Each merkle path hash
    MIN_SIZE: 33,                           // Minimum control block size
    MAX_SIZE: 33 + (32 * 128),              // Maximum size (128 merkle path levels)

    // Leaf version and parity encoding
    LEAF_VERSION_MASK: 0xfe,                // Mask for leaf version (all bits except LSB)
    PARITY_MASK: 0x01,                      // Mask for parity bit (LSB)
    DEFAULT_LEAF_VERSION: 0xc0,             // Default Tapscript version

    // Validation limits
    MAX_MERKLE_DEPTH: 128,                  // Maximum merkle tree depth
    MAX_VALIDATIONS_PER_SECOND: 50,         // Rate limiting
    MAX_VERIFICATION_TIME_MS: 5000,         // Maximum verification time

    // Tagged hash tags for BIP341
    TAPTWEAK_TAG: "TapTweak",
    TAPLEAF_TAG: "TapLeaf",
    TAPBRANCH_TAG: "TapBranch"
};

/**
 * @typedef {Object} ControlBlockData
 * @property {number} leafVersion - Leaf version extracted from control block
 * @property {number} parity - Output key parity bit (0 or 1)
 * @property {Buffer} internalKey - 32-byte internal public key
 * @property {Buffer[]} merklePath - Array of 32-byte hashes forming merkle path
 * @property {number} merkleDepth - Depth of the merkle path
 * @property {boolean} isValid - Whether the control block passed all validations
 */

/**
 * @typedef {Object} VerificationResult
 * @property {boolean} isValid - Whether verification succeeded
 * @property {Buffer} computedRoot - Computed merkle root from verification
 * @property {Buffer} expectedOutputKey - Expected output key for this script
 * @property {Object} metrics - Verification metrics and timing information
 */

/**
 * Enhanced security utilities for control block operations
 */
class ControlBlockSecurityUtils {
    static validationHistory = new Map();
    static lastCleanup = Date.now();

    /**
     * Rate limiting for control block operations
     */
    static checkRateLimit(operation = 'control-block-validation') {
        const now = Date.now();
        const secondKey = `${operation}-${Math.floor(now / 1000)}`;
        const currentCount = this.validationHistory.get(secondKey) || 0;

        if (currentCount >= CONTROL_BLOCK_CONSTANTS.MAX_VALIDATIONS_PER_SECOND) {
            throw new ControlBlockError(
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
     * Validates verification time to prevent DoS attacks
     */
    static validateVerificationTime(startTime, operation = 'control block verification') {
        const elapsed = Date.now() - startTime;
        if (elapsed > CONTROL_BLOCK_CONSTANTS.MAX_VERIFICATION_TIME_MS) {
            throw new ControlBlockError(
                `${operation} timeout: ${elapsed}ms > ${CONTROL_BLOCK_CONSTANTS.MAX_VERIFICATION_TIME_MS}ms`,
                'VERIFICATION_TIMEOUT',
                { elapsed, maxTime: CONTROL_BLOCK_CONSTANTS.MAX_VERIFICATION_TIME_MS }
            );
        }
    }

    /**
     * Constant-time buffer comparison for security
     */
    static constantTimeEqual(a, b) {
        if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
            return false;
        }
        if (a.length !== b.length) {
            return false;
        }

        try {
            return timingSafeEqual(a, b);
        } catch (error) {
            let result = 0;
            for (let i = 0; i < a.length; i++) {
                result |= a[i] ^ b[i];
            }
            return result === 0;
        }
    }

    /**
     * Validates control block buffer format and size
     */
    static validateControlBlockBuffer(controlBlock, fieldName = 'control block') {
        if (!Buffer.isBuffer(controlBlock)) {
            throw new ControlBlockError(
                `${fieldName} must be a Buffer`,
                'INVALID_CONTROL_BLOCK_TYPE'
            );
        }

        if (controlBlock.length < CONTROL_BLOCK_CONSTANTS.MIN_SIZE) {
            throw new ControlBlockError(
                `${fieldName} too small: ${controlBlock.length} < ${CONTROL_BLOCK_CONSTANTS.MIN_SIZE}`,
                'CONTROL_BLOCK_TOO_SMALL',
                { actualSize: controlBlock.length, minSize: CONTROL_BLOCK_CONSTANTS.MIN_SIZE }
            );
        }

        if (controlBlock.length > CONTROL_BLOCK_CONSTANTS.MAX_SIZE) {
            throw new ControlBlockError(
                `${fieldName} too large: ${controlBlock.length} > ${CONTROL_BLOCK_CONSTANTS.MAX_SIZE}`,
                'CONTROL_BLOCK_TOO_LARGE',
                { actualSize: controlBlock.length, maxSize: CONTROL_BLOCK_CONSTANTS.MAX_SIZE }
            );
        }

        // Validate size follows 33 + 32m format
        const remainingSize = controlBlock.length - CONTROL_BLOCK_CONSTANTS.BASE_SIZE;
        if (remainingSize % CONTROL_BLOCK_CONSTANTS.HASH_SIZE !== 0) {
            throw new ControlBlockError(
                `${fieldName} invalid size: must be 33 + 32m bytes`,
                'INVALID_CONTROL_BLOCK_SIZE',
                {
                    actualSize: controlBlock.length,
                    remainingSize,
                    expectedFormat: '33 + 32m bytes'
                }
            );
        }

        const merkleDepth = remainingSize / CONTROL_BLOCK_CONSTANTS.HASH_SIZE;
        if (merkleDepth > CONTROL_BLOCK_CONSTANTS.MAX_MERKLE_DEPTH) {
            throw new ControlBlockError(
                `Merkle depth too high: ${merkleDepth} > ${CONTROL_BLOCK_CONSTANTS.MAX_MERKLE_DEPTH}`,
                'MERKLE_DEPTH_TOO_HIGH',
                { merkleDepth, maxDepth: CONTROL_BLOCK_CONSTANTS.MAX_MERKLE_DEPTH }
            );
        }

        return true;
    }

    /**
     * Validates script buffer for Tapscript compatibility
     */
    static validateScript(script, fieldName = 'script') {
        if (!Buffer.isBuffer(script)) {
            throw new ControlBlockError(
                `${fieldName} must be a Buffer`,
                'INVALID_SCRIPT_TYPE'
            );
        }

        if (script.length === 0) {
            throw new ControlBlockError(
                `${fieldName} cannot be empty`,
                'EMPTY_SCRIPT'
            );
        }

        if (script.length > TAPSCRIPT_CONSTANTS.MAX_SCRIPT_SIZE) {
            throw new ControlBlockError(
                `${fieldName} too large: ${script.length} > ${TAPSCRIPT_CONSTANTS.MAX_SCRIPT_SIZE}`,
                'SCRIPT_TOO_LARGE',
                { actualSize: script.length, maxSize: TAPSCRIPT_CONSTANTS.MAX_SCRIPT_SIZE }
            );
        }

        return true;
    }

    /**
     * Validates internal public key format
     */
    static validateInternalKey(internalKey, fieldName = 'internal key') {
        if (!Buffer.isBuffer(internalKey)) {
            throw new ControlBlockError(
                `${fieldName} must be a Buffer`,
                'INVALID_INTERNAL_KEY_TYPE'
            );
        }

        if (internalKey.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH) {
            throw new ControlBlockError(
                `${fieldName} must be ${CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH} bytes`,
                'INVALID_INTERNAL_KEY_LENGTH',
                { expectedLength: CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH, actualLength: internalKey.length }
            );
        }

        // Validate x-coordinate is in field range
        const x = BigInt('0x' + internalKey.toString('hex'));
        const fieldPrime = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');

        if (x >= fieldPrime) {
            throw new ControlBlockError(
                `${fieldName} x-coordinate exceeds field prime`,
                'INVALID_FIELD_ELEMENT'
            );
        }

        return true;
    }
}

/**
 * Taproot control block implementation for script path spending validation
 */
class TaprootControlBlock {
    constructor() {
        this.validationCache = new Map();
        this.maxCacheSize = 100;
    }

    /**
     * Parse control block into its components with comprehensive validation
     * 
     * @param {Buffer} controlBlock - Raw control block bytes
     * @returns {ControlBlockData} Parsed control block components
     * 
     * @throws {ControlBlockError} If control block format is invalid
     */
    parseControlBlock(controlBlock) {
        const startTime = Date.now();

        try {
            ControlBlockSecurityUtils.checkRateLimit('parse-control-block');
            ControlBlockSecurityUtils.validateControlBlockBuffer(controlBlock);

            // Extract leaf version and parity from first byte
            const leafVersionAndParity = controlBlock[0];
            const leafVersion = leafVersionAndParity & CONTROL_BLOCK_CONSTANTS.LEAF_VERSION_MASK;
            const parity = leafVersionAndParity & CONTROL_BLOCK_CONSTANTS.PARITY_MASK;

            // Validate leaf version
            if (leafVersion !== CONTROL_BLOCK_CONSTANTS.DEFAULT_LEAF_VERSION) {
                throw new ControlBlockError(
                    `Unsupported leaf version: 0x${leafVersion.toString(16)}`,
                    'UNSUPPORTED_LEAF_VERSION',
                    { leafVersion, expectedVersion: CONTROL_BLOCK_CONSTANTS.DEFAULT_LEAF_VERSION }
                );
            }

            // Extract internal public key (bytes 1-32)
            const internalKey = controlBlock.slice(1, 33);
            ControlBlockSecurityUtils.validateInternalKey(internalKey);

            // Extract merkle path hashes (remaining bytes in 32-byte chunks)
            const merklePathData = controlBlock.slice(33);
            const merkleDepth = merklePathData.length / CONTROL_BLOCK_CONSTANTS.HASH_SIZE;

            const merklePath = [];
            for (let i = 0; i < merkleDepth; i++) {
                const start = i * CONTROL_BLOCK_CONSTANTS.HASH_SIZE;
                const end = start + CONTROL_BLOCK_CONSTANTS.HASH_SIZE;
                const hash = merklePathData.slice(start, end);

                if (hash.length !== CONTROL_BLOCK_CONSTANTS.HASH_SIZE) {
                    throw new ControlBlockError(
                        `Invalid merkle path hash length at index ${i}`,
                        'INVALID_MERKLE_HASH_LENGTH',
                        { index: i, actualLength: hash.length, expectedLength: CONTROL_BLOCK_CONSTANTS.HASH_SIZE }
                    );
                }

                merklePath.push(hash);
            }

            ControlBlockSecurityUtils.validateVerificationTime(startTime, 'control block parsing');

            return {
                leafVersion,
                parity,
                internalKey,
                merklePath,
                merkleDepth,
                isValid: true,
                parsedAt: Date.now()
            };

        } catch (error) {
            if (error instanceof ControlBlockError) {
                throw error;
            }
            throw new ControlBlockError(
                `Control block parsing failed: ${error.message}`,
                'PARSING_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Verify script inclusion in merkle tree using control block
     * 
     * @param {Buffer} script - Script to verify inclusion for
     * @param {Buffer} controlBlock - Control block containing merkle path
     * @param {Buffer} expectedOutputKey - Expected Taproot output key
     * @returns {VerificationResult} Comprehensive verification result
     * 
     * @throws {ControlBlockError} If verification fails or inputs are invalid
     */
    verifyScriptInclusion(script, controlBlock, expectedOutputKey) {
        const startTime = Date.now();

        try {
            ControlBlockSecurityUtils.checkRateLimit('verify-script-inclusion');
            ControlBlockSecurityUtils.validateScript(script);

            // Parse control block
            const parsedControlBlock = this.parseControlBlock(controlBlock);
            const { leafVersion, parity, internalKey, merklePath } = parsedControlBlock;

            // Validate expected output key
            if (!Buffer.isBuffer(expectedOutputKey) || expectedOutputKey.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH) {
                throw new ControlBlockError(
                    'Expected output key must be 32 bytes',
                    'INVALID_OUTPUT_KEY_LENGTH'
                );
            }

            // Compute TapLeaf hash for the script
            const tapLeafHash = TaggedHash.createTapLeaf(leafVersion, script);

            // Compute merkle root by traversing the path
            let computedRoot = tapLeafHash;

            for (let i = 0; i < merklePath.length; i++) {
                ControlBlockSecurityUtils.validateVerificationTime(startTime);

                const siblingHash = merklePath[i];

                // Create TapBranch hash with lexicographic ordering
                computedRoot = TaggedHash.createTapBranch(computedRoot, siblingHash);
            }

            // Handle single-leaf tree case (no merkle path)
            if (merklePath.length === 0) {
                computedRoot = tapLeafHash;
            }

            // Compute expected output key from internal key and merkle root
            const tapTweak = this.computeTapTweak(internalKey, computedRoot);
            const expectedKey = this.tweakInternalKey(internalKey, tapTweak, parity);

            // Verify computed output key matches expected
            const isValid = ControlBlockSecurityUtils.constantTimeEqual(expectedKey, expectedOutputKey);

            ControlBlockSecurityUtils.validateVerificationTime(startTime, 'script inclusion verification');

            return {
                isValid,
                computedRoot,
                expectedOutputKey: expectedKey,
                metrics: {
                    merkleDepth: merklePath.length,
                    verificationTime: Date.now() - startTime,
                    leafHash: tapLeafHash,
                    tapTweak: tapTweak
                },
                controlBlockData: parsedControlBlock
            };

        } catch (error) {
            if (error instanceof ControlBlockError) {
                throw error;
            }
            throw new ControlBlockError(
                `Script inclusion verification failed: ${error.message}`,
                'VERIFICATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Generate control block for a script in a merkle tree
     * 
     * @param {TaprootMerkleTree} merkleTree - Complete merkle tree
     * @param {number} leafIndex - Index of the target leaf
     * @param {Buffer} internalKey - Internal public key
     * @param {number} outputKeyParity - Parity of the output key (0 or 1)
     * @returns {Buffer} Complete control block for script path spending
     * 
     * @throws {ControlBlockError} If generation fails or parameters are invalid
     */
    generateControlBlock(merkleTree, leafIndex, internalKey, outputKeyParity) {
        const startTime = Date.now();

        try {
            ControlBlockSecurityUtils.checkRateLimit('generate-control-block');
            ControlBlockSecurityUtils.validateInternalKey(internalKey);

            if (!(merkleTree instanceof TaprootMerkleTree)) {
                throw new ControlBlockError(
                    'Invalid merkle tree instance',
                    'INVALID_MERKLE_TREE'
                );
            }

            const parityValidation = validateNumberRange(outputKeyParity, 0, 1, 'output key parity');
            assertValid(parityValidation);

            if (!Number.isInteger(leafIndex) || leafIndex < 0) {
                throw new ControlBlockError(
                    `Invalid leaf index: ${leafIndex}`,
                    'INVALID_LEAF_INDEX'
                );
            }

            // Get merkle path for the leaf
            const merklePath = merkleTree.getMerklePath(leafIndex);

            if (!merklePath) {
                throw new ControlBlockError(
                    `No merkle path found for leaf index ${leafIndex}`,
                    'MERKLE_PATH_NOT_FOUND'
                );
            }

            // Get leaf data
            const leaf = merkleTree.leaves[leafIndex];
            if (!leaf) {
                throw new ControlBlockError(
                    `Leaf not found at index ${leafIndex}`,
                    'LEAF_NOT_FOUND'
                );
            }

            // Construct control block
            const leafVersionAndParity = (leaf.leafVersion & CONTROL_BLOCK_CONSTANTS.LEAF_VERSION_MASK) |
                (outputKeyParity & CONTROL_BLOCK_CONSTANTS.PARITY_MASK);

            const controlBlockParts = [
                Buffer.from([leafVersionAndParity]),
                internalKey,
                ...merklePath.hashes
            ];

            const controlBlock = Buffer.concat(controlBlockParts);

            // Validate generated control block
            ControlBlockSecurityUtils.validateControlBlockBuffer(controlBlock);

            ControlBlockSecurityUtils.validateVerificationTime(startTime, 'control block generation');

            return controlBlock;

        } catch (error) {
            if (error instanceof ControlBlockError || error instanceof ValidationError) {
                throw error;
            }
            throw new ControlBlockError(
                `Control block generation failed: ${error.message}`,
                'GENERATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Compute TapTweak for key tweaking according to BIP341
     * 
     * @param {Buffer} internalKey - 32-byte internal public key
     * @param {Buffer} merkleRoot - 32-byte merkle root (or null for key-path only)
     * @returns {Buffer} 32-byte TapTweak value
     */
    computeTapTweak(internalKey, merkleRoot = null) {
        try {
            ControlBlockSecurityUtils.validateInternalKey(internalKey);

            if (merkleRoot && (!Buffer.isBuffer(merkleRoot) || merkleRoot.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH)) {
                throw new ControlBlockError(
                    'Merkle root must be 32 bytes if provided',
                    'INVALID_MERKLE_ROOT_LENGTH'
                );
            }

            return TaggedHash.createTapTweak(internalKey, merkleRoot);

        } catch (error) {
            if (error instanceof ControlBlockError) {
                throw error;
            }
            throw new ControlBlockError(
                `TapTweak computation failed: ${error.message}`,
                'TAPTWEAK_COMPUTATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Tweak internal key to create output key according to BIP341
     * 
     * @param {Buffer} internalKey - 32-byte internal public key
     * @param {Buffer} tapTweak - 32-byte TapTweak value
     * @param {number} expectedParity - Expected parity of result (0 or 1)
     * @returns {Buffer} 32-byte tweaked output key
     */
    tweakInternalKey(internalKey, tapTweak, expectedParity) {
        try {
            ControlBlockSecurityUtils.validateInternalKey(internalKey);

            if (!Buffer.isBuffer(tapTweak) || tapTweak.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH) {
                throw new ControlBlockError(
                    'TapTweak must be 32 bytes',
                    'INVALID_TAPTWEAK_LENGTH'
                );
            }

            const parityValidation = validateNumberRange(expectedParity, 0, 1, 'expected parity');
            assertValid(parityValidation);

            // Load internal key as x-only public key
            const internalPoint = secp256k1.ProjectivePoint.fromHex('02' + internalKey.toString('hex'));

            // Create tweak point: t * G
            const tweakPoint = secp256k1.ProjectivePoint.fromPrivateKey(tapTweak);

            // Compute output point: P + t*G
            const outputPoint = internalPoint.add(tweakPoint);

            // Check if point is at infinity (invalid)
            if (outputPoint.equals(secp256k1.ProjectivePoint.ZERO)) {
                throw new ControlBlockError(
                    'Tweaked key results in point at infinity',
                    'POINT_AT_INFINITY'
                );
            }

            // Get x-only representation
            const outputKeyBytes = outputPoint.toRawBytes(true); // Compressed format
            const outputKey = outputKeyBytes.slice(1); // Remove compression prefix

            // Verify parity matches expected
            const actualParity = outputKeyBytes[0] === 0x03 ? 1 : 0;
            if (actualParity !== expectedParity) {
                // If parity doesn't match, negate the internal key and try again
                const negatedInternalPoint = internalPoint.negate();
                const negatedOutputPoint = negatedInternalPoint.add(tweakPoint);

                if (negatedOutputPoint.equals(secp256k1.ProjectivePoint.ZERO)) {
                    throw new ControlBlockError(
                        'Negated tweaked key results in point at infinity',
                        'NEGATED_POINT_AT_INFINITY'
                    );
                }

                const negatedOutputKeyBytes = negatedOutputPoint.toRawBytes(true);
                const negatedOutputKey = negatedOutputKeyBytes.slice(1);
                const negatedParity = negatedOutputKeyBytes[0] === 0x03 ? 1 : 0;

                if (negatedParity === expectedParity) {
                    return negatedOutputKey;
                } else {
                    throw new ControlBlockError(
                        `Cannot achieve expected parity ${expectedParity}`,
                        'PARITY_MISMATCH',
                        { expectedParity, actualParity, negatedParity }
                    );
                }
            }

            return outputKey;

        } catch (error) {
            if (error instanceof ControlBlockError || error instanceof ValidationError) {
                throw error;
            }
            throw new ControlBlockError(
                `Key tweaking failed: ${error.message}`,
                'KEY_TWEAKING_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Validate control block against a complete merkle tree
     * 
     * @param {Buffer} controlBlock - Control block to validate
     * @param {TaprootMerkleTree} merkleTree - Complete merkle tree
     * @param {number} leafIndex - Expected leaf index
     * @returns {boolean} True if control block is valid for the tree and leaf
     */
    validateAgainstTree(controlBlock, merkleTree, leafIndex) {
        try {
            ControlBlockSecurityUtils.checkRateLimit('validate-against-tree');

            const parsed = this.parseControlBlock(controlBlock);
            const expectedPath = merkleTree.getMerklePath(leafIndex);

            if (!expectedPath) {
                return false;
            }

            // Compare merkle paths
            if (parsed.merklePath.length !== expectedPath.hashes.length) {
                return false;
            }

            for (let i = 0; i < parsed.merklePath.length; i++) {
                if (!ControlBlockSecurityUtils.constantTimeEqual(parsed.merklePath[i], expectedPath.hashes[i])) {
                    return false;
                }
            }

            return true;

        } catch (error) {
            return false;
        }
    }

    /**
     * Get control block validation summary
     * 
     * @param {Buffer} controlBlock - Control block to analyze
     * @returns {Object} Comprehensive validation summary
     */
    getValidationSummary(controlBlock) {
        try {
            const parsed = this.parseControlBlock(controlBlock);

            return {
                isValid: parsed.isValid,
                structure: {
                    totalSize: controlBlock.length,
                    baseSize: CONTROL_BLOCK_CONSTANTS.BASE_SIZE,
                    merklePathSize: controlBlock.length - CONTROL_BLOCK_CONSTANTS.BASE_SIZE,
                    merkleDepth: parsed.merkleDepth
                },
                leafVersion: {
                    value: parsed.leafVersion,
                    hex: '0x' + parsed.leafVersion.toString(16),
                    isSupported: parsed.leafVersion === CONTROL_BLOCK_CONSTANTS.DEFAULT_LEAF_VERSION
                },
                outputKeyParity: parsed.parity,
                internalKey: parsed.internalKey.toString('hex'),
                merklePathHashes: parsed.merklePath.map(hash => hash.toString('hex')),
                securityMetrics: {
                    parsedAt: parsed.parsedAt,
                    isWithinLimits: parsed.merkleDepth <= CONTROL_BLOCK_CONSTANTS.MAX_MERKLE_DEPTH,
                    hasValidStructure: true
                }
            };

        } catch (error) {
            return {
                isValid: false,
                error: error.message,
                errorCode: error.code,
                structure: {
                    totalSize: controlBlock?.length || 0,
                    isValidSize: false
                }
            };
        }
    }

    /**
     * Clear validation cache and cleanup
     */
    clearCache() {
        this.validationCache.clear();
        console.log('Control block validation cache cleared');
    }
}

export {
    ControlBlockError,
    ControlBlockSecurityUtils,
    TaprootControlBlock,
    CONTROL_BLOCK_CONSTANTS
};