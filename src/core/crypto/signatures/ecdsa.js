/**
 * @fileoverview Enhanced ECDSA implementation with comprehensive security fixes
 * 
 * This module provides a hardened ECDSA implementation addressing critical security
 * vulnerabilities while maintaining Bitcoin protocol compliance. Includes proper
 * input validation, signature canonicalization, transaction signing support,
 * and comprehensive error handling.
 * 
 * @see {@link https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm|ECDSA on Bitcoin Wiki}
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki|BIP62 - Dealing with malleability}
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki|BIP143 - Transaction Signature Verification for Version 0 Witness Program}
 * @author yfbsei
 * @version 2.1.1
 */

import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { decodeWIFPrivateKey } from '../../../encoding/address/decode.js';
import { CRYPTO_CONSTANTS } from '../../constants.js';
import BN from 'bn.js';

/**
 * ECDSA-specific error class for proper error handling
 */
class ECDSAError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'ECDSAError';
        this.code = code;
        this.details = details;
        this.timestamp = Date.now();
    }
}

/**
 * Bitcoin SIGHASH types for transaction signing
 */
const SIGHASH_TYPES = {
    ALL: 0x01,
    NONE: 0x02,
    SINGLE: 0x03,
    ANYONECANPAY: 0x80,
    // Combined flags
    ALL_ANYONECANPAY: 0x81,
    NONE_ANYONECANPAY: 0x82,
    SINGLE_ANYONECANPAY: 0x83
};

/**
 * Curve order for secp256k1 (for signature validation)
 */
const CURVE_ORDER = new BN(CRYPTO_CONSTANTS.SECP256K1_ORDER, 'hex');
const CURVE_HALF_ORDER = CURVE_ORDER.shrn(1); // n/2 for low-S enforcement (fixed division)

/**
 * Bitcoin message signing prefix
 */
const BITCOIN_MESSAGE_PREFIX = "Bitcoin Signed Message:\n";

/**
 * Input validation utilities
 */
class ECDSAValidator {
    /**
     * Validates that a value is a valid private key
     */
    static validatePrivateKey(privateKey) {
        if (!privateKey) {
            throw new ECDSAError('Private key is required', 'MISSING_PRIVATE_KEY');
        }

        let keyBuffer;
        try {
            if (typeof privateKey === 'string') {
                keyBuffer = decodeWIFPrivateKey(privateKey).keyMaterial;
            } else if (Buffer.isBuffer(privateKey) || privateKey instanceof Uint8Array) {
                keyBuffer = Buffer.from(privateKey);
            } else {
                throw new ECDSAError('Invalid private key format', 'INVALID_PRIVATE_KEY_FORMAT');
            }
        } catch (error) {
            throw new ECDSAError(
                'Failed to decode private key',
                'PRIVATE_KEY_DECODE_FAILED',
                { originalError: error.message }
            );
        }

        // Validate key length
        if (keyBuffer.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH) {
            throw new ECDSAError(
                `Private key must be ${CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH} bytes`,
                'INVALID_PRIVATE_KEY_LENGTH',
                { actualLength: keyBuffer.length }
            );
        }

        // Validate key is in valid range [1, n-1]
        const keyBN = new BN(keyBuffer);
        if (keyBN.isZero() || keyBN.gte(CURVE_ORDER)) {
            throw new ECDSAError(
                'Private key is outside valid curve range',
                'PRIVATE_KEY_OUT_OF_RANGE'
            );
        }

        return keyBuffer;
    }

    /**
     * Validates that a value is a valid public key point on secp256k1
     */
    static validatePublicKey(publicKey) {
        if (!publicKey) {
            throw new ECDSAError('Public key is required', 'MISSING_PUBLIC_KEY');
        }

        let keyBuffer;
        if (typeof publicKey === 'string') {
            try {
                keyBuffer = Buffer.from(publicKey, 'hex');
            } catch (error) {
                throw new ECDSAError('Invalid public key hex format', 'INVALID_PUBLIC_KEY_HEX');
            }
        } else if (Buffer.isBuffer(publicKey) || publicKey instanceof Uint8Array) {
            keyBuffer = Buffer.from(publicKey);
        } else {
            throw new ECDSAError('Invalid public key format', 'INVALID_PUBLIC_KEY_FORMAT');
        }

        // Validate key length (compressed: 33 bytes, uncompressed: 65 bytes)
        if (keyBuffer.length !== 33 && keyBuffer.length !== 65) {
            throw new ECDSAError(
                'Public key must be 33 (compressed) or 65 (uncompressed) bytes',
                'INVALID_PUBLIC_KEY_LENGTH',
                { actualLength: keyBuffer.length }
            );
        }

        // Validate point is on curve by attempting to parse it
        try {
            secp256k1.ProjectivePoint.fromHex(keyBuffer);
        } catch (error) {
            throw new ECDSAError(
                'Public key point is not on secp256k1 curve',
                'INVALID_CURVE_POINT',
                { originalError: error.message }
            );
        }

        return keyBuffer;
    }

    /**
     * Validates ECDSA signature format and components
     */
    static validateSignature(signature) {
        if (!signature) {
            throw new ECDSAError('Signature is required', 'MISSING_SIGNATURE');
        }

        let sigBuffer;
        if (Buffer.isBuffer(signature) || signature instanceof Uint8Array) {
            sigBuffer = Buffer.from(signature);
        } else {
            throw new ECDSAError('Invalid signature format', 'INVALID_SIGNATURE_FORMAT');
        }

        // For compact signatures (64 bytes: 32r + 32s)
        if (sigBuffer.length === 64) {
            const r = new BN(sigBuffer.slice(0, 32));
            const s = new BN(sigBuffer.slice(32, 64));

            // Validate r and s are in range [1, n-1]
            if (r.isZero() || r.gte(CURVE_ORDER)) {
                throw new ECDSAError('Signature r component out of range', 'INVALID_SIGNATURE_R');
            }
            if (s.isZero() || s.gte(CURVE_ORDER)) {
                throw new ECDSAError('Signature s component out of range', 'INVALID_SIGNATURE_S');
            }

            return { r, s, format: 'compact' };
        }

        // Try to parse as DER-encoded signature
        try {
            const sig = secp256k1.Signature.fromDER(sigBuffer);
            const r = new BN(sig.r.toString());
            const s = new BN(sig.s.toString());

            if (r.isZero() || r.gte(CURVE_ORDER)) {
                throw new ECDSAError('Signature r component out of range', 'INVALID_SIGNATURE_R');
            }
            if (s.gte(CURVE_ORDER)) {
                throw new ECDSAError('Signature s component out of range', 'INVALID_SIGNATURE_S');
            }

            return { r, s, format: 'der', signature: sig };
        } catch (error) {
            throw new ECDSAError(
                'Invalid signature encoding',
                'INVALID_SIGNATURE_ENCODING',
                { originalError: error.message }
            );
        }
    }

    /**
     * Validates message format
     */
    static validateMessage(message) {
        if (message === null || message === undefined) {
            throw new ECDSAError('Message is required', 'MISSING_MESSAGE');
        }

        if (typeof message === 'string') {
            return Buffer.from(message, 'utf8');
        } else if (Buffer.isBuffer(message) || message instanceof Uint8Array) {
            return Buffer.from(message);
        } else {
            throw new ECDSAError('Message must be string, Buffer, or Uint8Array', 'INVALID_MESSAGE_FORMAT');
        }
    }

    /**
     * Validates SIGHASH type
     */
    static validateSighashType(sighashType) {
        const validTypes = Object.values(SIGHASH_TYPES);
        if (!validTypes.includes(sighashType)) {
            throw new ECDSAError(
                'Invalid SIGHASH type',
                'INVALID_SIGHASH_TYPE',
                { provided: sighashType, valid: validTypes }
            );
        }
        return sighashType;
    }
}

/**
 * Transaction signature hash computation utilities
 */
class TransactionHasher {
    /**
     * Creates Bitcoin message hash with proper prefix
     */
    static createMessageHash(message) {
        const messageBuffer = ECDSAValidator.validateMessage(message);
        const prefix = Buffer.from(BITCOIN_MESSAGE_PREFIX, 'utf8');
        const messageLength = this._getCompactSizeBuffer(messageBuffer.length);
        const prefixLength = this._getCompactSizeBuffer(prefix.length);

        // Bitcoin message format: prefix_length + prefix + message_length + message
        const fullMessage = Buffer.concat([
            prefixLength, prefix,
            messageLength, messageBuffer
        ]);

        // Double SHA256 hash
        const hash1 = createHash('sha256').update(fullMessage).digest();
        const hash2 = createHash('sha256').update(hash1).digest();

        return hash2;
    }

    /**
     * Creates BIP143 signature hash for SegWit transactions
     */
    static createBIP143Hash(transaction, inputIndex, scriptCode, amount, sighashType) {
        ECDSAValidator.validateSighashType(sighashType);

        const hashPrevouts = this._getHashPrevouts(transaction, sighashType);
        const hashSequence = this._getHashSequence(transaction, sighashType);
        const hashOutputs = this._getHashOutputs(transaction, inputIndex, sighashType);

        const input = transaction.inputs[inputIndex];
        if (!input) {
            throw new ECDSAError('Invalid input index', 'INVALID_INPUT_INDEX');
        }

        // Convert version and lockTime to 4-byte little-endian
        const versionBuffer = Buffer.allocUnsafe(4);
        versionBuffer.writeUInt32LE(transaction.version, 0);

        const lockTimeBuffer = Buffer.allocUnsafe(4);
        lockTimeBuffer.writeUInt32LE(transaction.lockTime, 0);

        // Convert amount to 8-byte little-endian
        const amountBuffer = Buffer.allocUnsafe(8);
        amountBuffer.writeBigUInt64LE(BigInt(amount), 0);

        // Convert sequence to 4-byte little-endian
        const sequenceBuffer = Buffer.allocUnsafe(4);
        sequenceBuffer.writeUInt32LE(input.sequence, 0);

        // Convert sighash type to 4-byte little-endian
        const sighashBuffer = Buffer.allocUnsafe(4);
        sighashBuffer.writeUInt32LE(sighashType, 0);

        // BIP143 signature hash construction
        const data = Buffer.concat([
            versionBuffer,                                // nVersion (4 bytes)
            hashPrevouts,                                 // hashPrevouts (32 bytes)
            hashSequence,                                 // hashSequence (32 bytes)
            Buffer.from(input.previousOutput, 'hex'),     // outpoint (36 bytes)
            scriptCode,                                   // scriptCode
            amountBuffer,                                 // amount (8 bytes)
            sequenceBuffer,                               // nSequence (4 bytes)
            hashOutputs,                                  // hashOutputs (32 bytes)
            lockTimeBuffer,                               // nLockTime (4 bytes)
            sighashBuffer                                 // sighash type (4 bytes)
        ]);

        // Double SHA256
        const hash1 = createHash('sha256').update(data).digest();
        return createHash('sha256').update(hash1).digest();
    }

    /**
     * Helper method to get compact size buffer
     */
    static _getCompactSizeBuffer(value) {
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
     * Helper method to compute hashPrevouts
     */
    static _getHashPrevouts(transaction, sighashType) {
        if (sighashType & SIGHASH_TYPES.ANYONECANPAY) {
            return Buffer.alloc(32, 0); // Zero hash
        }

        const prevouts = transaction.inputs.map(input =>
            Buffer.from(input.previousOutput, 'hex')
        );
        const concat = Buffer.concat(prevouts);
        const hash1 = createHash('sha256').update(concat).digest();
        return createHash('sha256').update(hash1).digest();
    }

    /**
     * Helper method to compute hashSequence
     */
    static _getHashSequence(transaction, sighashType) {
        if ((sighashType & SIGHASH_TYPES.ANYONECANPAY) ||
            (sighashType & 0x1f) === SIGHASH_TYPES.SINGLE ||
            (sighashType & 0x1f) === SIGHASH_TYPES.NONE) {
            return Buffer.alloc(32, 0); // Zero hash
        }

        const sequences = transaction.inputs.map(input => {
            const sequenceBuffer = Buffer.allocUnsafe(4);
            sequenceBuffer.writeUInt32LE(input.sequence, 0);
            return sequenceBuffer;
        });
        const concat = Buffer.concat(sequences);
        const hash1 = createHash('sha256').update(concat).digest();
        return createHash('sha256').update(hash1).digest();
    }

    /**
     * Helper method to compute hashOutputs
     */
    static _getHashOutputs(transaction, inputIndex, sighashType) {
        const type = sighashType & 0x1f;

        if (type === SIGHASH_TYPES.SINGLE) {
            if (inputIndex >= transaction.outputs.length) {
                throw new ECDSAError('SIGHASH_SINGLE with invalid input index', 'INVALID_SIGHASH_SINGLE');
            }
            // Hash only the output at the same index
            const output = transaction.outputs[inputIndex];
            const amountBuffer = Buffer.allocUnsafe(8);
            amountBuffer.writeBigUInt64LE(BigInt(output.amount), 0);

            const outputData = Buffer.concat([
                amountBuffer,
                Buffer.from(output.scriptPubKey, 'hex')
            ]);
            const hash1 = createHash('sha256').update(outputData).digest();
            return createHash('sha256').update(hash1).digest();
        } else if (type === SIGHASH_TYPES.NONE) {
            return Buffer.alloc(32, 0); // Zero hash
        } else {
            // SIGHASH_ALL - hash all outputs
            const outputs = transaction.outputs.map(output => {
                const amountBuffer = Buffer.allocUnsafe(8);
                amountBuffer.writeBigUInt64LE(BigInt(output.amount), 0);

                return Buffer.concat([
                    amountBuffer,
                    Buffer.from(output.scriptPubKey, 'hex')
                ]);
            });
            const concat = Buffer.concat(outputs);
            const hash1 = createHash('sha256').update(concat).digest();
            return createHash('sha256').update(hash1).digest();
        }
    }
}

/**
 * Signature canonicalization utilities
 */
class SignatureCanonicalizer {
    /**
     * Enforces low-S rule to prevent signature malleability
     */
    static canonicalizeSignature(signature) {
        const validated = ECDSAValidator.validateSignature(signature);
        let { r, s } = validated;

        // Enforce low-S rule: if s > n/2, use n - s
        if (s.gt(CURVE_HALF_ORDER)) {
            s = CURVE_ORDER.sub(s);
        }

        return {
            r: r.toBuffer('be', 32),
            s: s.toBuffer('be', 32),
            isCanonical: true
        };
    }

    /**
     * Checks if signature is already canonical
     */
    static isCanonical(signature) {
        try {
            const validated = ECDSAValidator.validateSignature(signature);
            return validated.s.lte(CURVE_HALF_ORDER);
        } catch (error) {
            return false;
        }
    }
}

/**
 * Enhanced ECDSA implementation with comprehensive security features
 */
class EnhancedECDSA {
    /**
     * Configuration options for ECDSA operations
     */
    constructor(options = {}) {
        this.enforceCanonical = options.enforceCanonical !== false; // Default true
        this.enableCache = options.enableCache === true; // Default false for security
        this.extraEntropy = options.extraEntropy || null;

        // Initialize cache if enabled
        if (this.enableCache) {
            this.publicKeyCache = new Map();
            this.maxCacheSize = options.maxCacheSize || 100;
        }
    }

    /**
     * Signs a message with enhanced security and Bitcoin protocol compliance
     */
    async sign(privateKey, message, options = {}) {
        try {
            // Validate inputs
            const keyBuffer = ECDSAValidator.validatePrivateKey(privateKey);
            const messageBuffer = ECDSAValidator.validateMessage(message);

            // Prepare message hash
            let messageHash;
            if (options.bitcoinMessage) {
                messageHash = TransactionHasher.createMessageHash(messageBuffer);
            } else {
                messageHash = messageBuffer;
            }

            // Add extra entropy if specified
            let auxRand = options.extraEntropy || this.extraEntropy;
            if (!auxRand) {
                auxRand = randomBytes(32); // Secure randomness
            }

            // Create signature with proper nonce generation
            const signature = secp256k1.sign(messageHash, keyBuffer, {
                extraEntropy: auxRand,
                lowS: this.enforceCanonical // Enforce canonical signatures
            });

            // Get recovery ID
            const recoveryId = signature.recovery || 0;

            // Return canonical signature
            const compactSig = signature.toCompactRawBytes();
            const canonicalized = this.enforceCanonical ?
                SignatureCanonicalizer.canonicalizeSignature(compactSig) :
                { r: compactSig.slice(0, 32), s: compactSig.slice(32, 64) };

            return {
                signature: Buffer.concat([canonicalized.r, canonicalized.s]),
                recoveryId,
                messageHash: Buffer.from(messageHash),
                isCanonical: canonicalized.isCanonical || this.enforceCanonical
            };

        } catch (error) {
            if (error instanceof ECDSAError) {
                throw error;
            }
            throw new ECDSAError(
                'Signing operation failed',
                'SIGN_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Verifies an ECDSA signature with comprehensive validation
     */
    async verify(signature, message, publicKey, options = {}) {
        try {
            // Validate inputs
            const sigValidated = ECDSAValidator.validateSignature(signature);
            const messageBuffer = ECDSAValidator.validateMessage(message);
            const pubKeyBuffer = ECDSAValidator.validatePublicKey(publicKey);

            // Check signature canonicality if enforced
            if (this.enforceCanonical && !SignatureCanonicalizer.isCanonical(signature)) {
                throw new ECDSAError(
                    'Non-canonical signature rejected',
                    'NON_CANONICAL_SIGNATURE'
                );
            }

            // Prepare message hash
            let messageHash;
            if (options.bitcoinMessage) {
                messageHash = TransactionHasher.createMessageHash(messageBuffer);
            } else {
                messageHash = messageBuffer;
            }

            // Verify signature using Noble curves
            let sig;
            if (sigValidated.format === 'compact') {
                sig = secp256k1.Signature.fromCompact(signature);
            } else {
                sig = sigValidated.signature;
            }

            return secp256k1.verify(sig, messageHash, pubKeyBuffer);

        } catch (error) {
            if (error instanceof ECDSAError) {
                throw error;
            }
            throw new ECDSAError(
                'Verification operation failed',
                'VERIFY_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Recovers public key from signature with validation
     */
    async recoverPublicKey(signature, message, recoveryId, options = {}) {
        try {
            // Validate inputs
            ECDSAValidator.validateSignature(signature);
            const messageBuffer = ECDSAValidator.validateMessage(message);

            if (!Number.isInteger(recoveryId) || recoveryId < 0 || recoveryId > 3) {
                throw new ECDSAError(
                    'Recovery ID must be 0, 1, 2, or 3',
                    'INVALID_RECOVERY_ID'
                );
            }

            // Prepare message hash
            let messageHash;
            if (options.bitcoinMessage) {
                messageHash = TransactionHasher.createMessageHash(messageBuffer);
            } else {
                messageHash = messageBuffer;
            }

            // Recover public key
            const sig = secp256k1.Signature.fromCompact(signature).addRecoveryBit(recoveryId);
            const recoveredPoint = sig.recoverPublicKey(messageHash);

            // Validate recovered point is on curve
            const publicKey = recoveredPoint.toRawBytes(true); // Compressed format
            ECDSAValidator.validatePublicKey(publicKey);

            return {
                publicKey: Buffer.from(publicKey),
                compressed: true
            };

        } catch (error) {
            if (error instanceof ECDSAError) {
                throw error;
            }
            throw new ECDSAError(
                'Public key recovery failed',
                'RECOVERY_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Signs a Bitcoin transaction input with BIP143 support
     */
    async signTransaction(privateKey, transaction, inputIndex, options = {}) {
        try {
            const {
                scriptCode,
                amount,
                sighashType = SIGHASH_TYPES.ALL,
                isSegwit = false
            } = options;

            ECDSAValidator.validatePrivateKey(privateKey);
            ECDSAValidator.validateSighashType(sighashType);

            if (!Number.isInteger(inputIndex) || inputIndex < 0) {
                throw new ECDSAError('Invalid input index', 'INVALID_INPUT_INDEX');
            }

            if (!transaction || !transaction.inputs || !transaction.outputs) {
                throw new ECDSAError('Invalid transaction format', 'INVALID_TRANSACTION');
            }

            if (inputIndex >= transaction.inputs.length) {
                throw new ECDSAError('Input index out of range', 'INPUT_INDEX_OUT_OF_RANGE');
            }

            let sigHash;
            if (isSegwit) {
                if (!scriptCode || !amount) {
                    throw new ECDSAError(
                        'SegWit signing requires scriptCode and amount',
                        'MISSING_SEGWIT_PARAMS'
                    );
                }
                sigHash = TransactionHasher.createBIP143Hash(
                    transaction, inputIndex, scriptCode, amount, sighashType
                );
            } else {
                throw new ECDSAError(
                    'Legacy transaction signing not yet implemented',
                    'LEGACY_SIGNING_NOT_IMPLEMENTED'
                );
            }

            // Sign the hash
            const result = await this.sign(privateKey, sigHash, {
                bitcoinMessage: false // Already hashed
            });

            // Append SIGHASH type to signature
            const signatureWithSighash = Buffer.concat([
                result.signature,
                Buffer.from([sighashType])
            ]);

            return {
                signature: signatureWithSighash,
                signatureHash: result.messageHash,
                sighashType
            };

        } catch (error) {
            if (error instanceof ECDSAError) {
                throw error;
            }
            throw new ECDSAError(
                'Transaction signing failed',
                'TRANSACTION_SIGN_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Batch verification for multiple signatures (performance optimization)
     */
    async verifyBatch(signatures) {
        const results = [];

        for (const { signature, message, publicKey, options = {} } of signatures) {
            try {
                const result = await this.verify(signature, message, publicKey, options);
                results.push({ success: true, result });
            } catch (error) {
                results.push({ success: false, error });
            }
        }

        return results;
    }

    /**
     * Clears sensitive data from memory (best effort in JavaScript)
     */
    clearMemory() {
        if (this.enableCache && this.publicKeyCache) {
            this.publicKeyCache.clear();
        }

        // Clear any other sensitive state
        this.extraEntropy = null;
    }
}

// Export enhanced ECDSA with backward compatibility
const enhancedECDSA = new EnhancedECDSA({ enforceCanonical: true });

/**
 * Backward-compatible API that maintains existing interface
 */
const ECDSA = {
    // Enhanced methods with security fixes
    async sign(privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS", message = "Hello world") {
        const result = await enhancedECDSA.sign(privateKey, message, { bitcoinMessage: true });
        return [result.signature, result.recoveryId];
    },

    async verify(signature, message = "Hello World", publicKey) {
        return await enhancedECDSA.verify(signature, message, publicKey, { bitcoinMessage: true });
    },

    async retrieve_public_key(message = "Hello world", signature, recovery = 0) {
        const result = await enhancedECDSA.recoverPublicKey(signature, message, recovery, { bitcoinMessage: true });
        return result.publicKey;
    },

    // New enhanced API
    Enhanced: EnhancedECDSA,
    Validator: ECDSAValidator,
    TransactionHasher,
    SignatureCanonicalizer,
    SIGHASH_TYPES,
    ECDSAError
};

export default ECDSA;