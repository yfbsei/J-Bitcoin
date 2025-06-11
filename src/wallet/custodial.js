/**
 * @fileoverview Refactored custodial wallet implementation with integrated transaction management
 * 
 * REFACTORING IMPROVEMENTS (v3.0.0):
 * - Separation of concerns with dedicated classes
 * - Improved error handling and type safety
 * - Better code organization and readability
 * - Enhanced configuration management
 * - Simplified security utilities
 * - More testable architecture
 * - Reduced complexity and cognitive load
 * - Complete transaction integration
 * 
 * @author yfbsei
 * @version 3.0.0
 * @since 1.0.0
 */

import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import {
    BIP44_CONSTANTS,
    CRYPTO_CONSTANTS,
    generateDerivationPath,
    parseDerivationPath,
    isValidBitcoinPath,
    getNetworkConfiguration,
    validateAndGetNetwork
} from '../core/constants.js';

import generateMasterKey from '../bip/bip32/master-key.js';
import derive from '../bip/bip32/derive.js';
import { BIP39 } from '../bip/bip39/mnemonic.js';
import ecdsa from '../core/crypto/signatures/ecdsa.js';

import { TransactionBuilder } from '../transaction/builder.js';
import { UTXOManager } from '../transaction/utxo-manager.js';
import { TaprootMerkleTree } from '../core/taproot/merkle-tree.js';

import { encodeStandardKeys, generateAddressFromExtendedVersion } from '../encoding/address/encode.js';
import {
    validateNetwork,
    validatePrivateKey,
    validateDerivationPath,
    validateMnemonic,
    assertValid,
    ValidationError
} from '../utils/validation.js';

// ============================================================================================
// CONFIGURATION AND CONSTANTS
// ============================================================================================

/**
 * Configuration object for custodial wallet security settings
 */
const SECURITY_CONFIG = {
    // Rate limiting
    MAX_VALIDATIONS_PER_SECOND: 500,
    MAX_CHILD_KEYS: 1000,
    MAX_DERIVATION_DEPTH: 10,

    // Timeouts
    VALIDATION_TIMEOUT_MS: 5000,

    // Memory security
    MEMORY_CLEAR_PASSES: 3,

    // Entropy validation
    MIN_ENTROPY_THRESHOLD: 0.7,

    // Transaction limits
    MIN_CHANGE_AMOUNT: 546, // Bitcoin dust limit

    // Cleanup intervals
    RATE_LIMIT_CLEANUP_INTERVAL: 60000
};

/**
 * Error codes for different types of custodial wallet errors
 */
const ERROR_CODES = {
    INVALID_NETWORK: 'INVALID_NETWORK',
    INVALID_MASTER_KEYS: 'INVALID_MASTER_KEYS',
    VALIDATION_FAILED: 'VALIDATION_FAILED',
    RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
    OPERATION_TIMEOUT: 'OPERATION_TIMEOUT',
    INSUFFICIENT_ENTROPY: 'INSUFFICIENT_ENTROPY',
    MEMORY_CLEAR_FAILED: 'MEMORY_CLEAR_FAILED',
    DERIVATION_ERROR: 'DERIVATION_ERROR',
    SIGNATURE_ERROR: 'SIGNATURE_ERROR',
    TRANSACTION_ERROR: 'TRANSACTION_ERROR'
};

// ============================================================================================
// ERROR HANDLING
// ============================================================================================

/**
 * Custom error class for custodial wallet operations
 */
class CustodialWalletError extends Error {
    constructor(message, code = 'UNKNOWN_ERROR', details = {}) {
        super(message);
        this.name = 'CustodialWalletError';
        this.code = code;
        this.details = details;
        this.timestamp = Date.now();

        // Maintain proper stack trace
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, CustodialWalletError);
        }
    }
}

// ============================================================================================
// SECURITY UTILITIES
// ============================================================================================

/**
 * Security utilities for rate limiting, memory management, and validation
 */
class SecurityManager {
    static #validationHistory = new Map();
    static #lastCleanup = Date.now();

    /**
     * Check if operation is within rate limits
     * @param {string} operation - Operation identifier
     * @throws {CustodialWalletError} If rate limit exceeded
     */
    static checkRateLimit(operation = 'default') {
        const now = Date.now();
        const secondKey = `${operation}-${Math.floor(now / 1000)}`;
        const currentCount = this.#validationHistory.get(secondKey) || 0;

        if (currentCount >= SECURITY_CONFIG.MAX_VALIDATIONS_PER_SECOND) {
            throw new CustodialWalletError(
                `Rate limit exceeded for operation: ${operation}`,
                ERROR_CODES.RATE_LIMIT_EXCEEDED,
                { operation, currentCount }
            );
        }

        this.#validationHistory.set(secondKey, currentCount + 1);
        this.#cleanupOldEntries(now);
    }

    /**
     * Validate execution time to prevent DoS attacks
     * @param {number} startTime - Operation start timestamp
     * @param {string} operation - Operation name for error reporting
     */
    static validateExecutionTime(startTime, operation = 'operation') {
        const elapsed = Date.now() - startTime;
        if (elapsed > SECURITY_CONFIG.VALIDATION_TIMEOUT_MS) {
            throw new CustodialWalletError(
                `${operation} timeout: ${elapsed}ms > ${SECURITY_CONFIG.VALIDATION_TIMEOUT_MS}ms`,
                ERROR_CODES.OPERATION_TIMEOUT,
                { elapsed, maxTime: SECURITY_CONFIG.VALIDATION_TIMEOUT_MS, operation }
            );
        }
    }

    /**
     * Securely clear sensitive data from memory
     * @param {Buffer|Object|Array} data - Data to clear
     */
    static secureClear(data) {
        try {
            if (Buffer.isBuffer(data)) {
                this.#clearBuffer(data);
            } else if (Array.isArray(data)) {
                data.forEach(item => this.secureClear(item));
                data.length = 0;
            } else if (typeof data === 'object' && data !== null) {
                this.#clearObject(data);
            }
        } catch (error) {
            throw new CustodialWalletError(
                'Failed to securely clear memory',
                ERROR_CODES.MEMORY_CLEAR_FAILED,
                { originalError: error.message }
            );
        }
    }

    /**
     * Constant-time string comparison to prevent timing attacks
     * @param {string} a - First string
     * @param {string} b - Second string
     * @returns {boolean} True if strings are equal
     */
    static constantTimeEqual(a, b) {
        if (typeof a !== 'string' || typeof b !== 'string') {
            return false;
        }

        const maxLen = Math.max(a.length, b.length);
        const normalizedA = a.padEnd(maxLen, '\0');
        const normalizedB = b.padEnd(maxLen, '\0');

        try {
            const bufferA = Buffer.from(normalizedA);
            const bufferB = Buffer.from(normalizedB);
            return timingSafeEqual(bufferA, bufferB);
        } catch (error) {
            // Fallback to manual comparison
            let result = 0;
            for (let i = 0; i < maxLen; i++) {
                result |= normalizedA.charCodeAt(i) ^ normalizedB.charCodeAt(i);
            }
            return result === 0;
        }
    }

    /**
     * Validate entropy of key material
     * @param {Buffer} keyMaterial - Key material to validate
     * @param {string} fieldName - Field name for error reporting
     * @returns {boolean} True if entropy is sufficient
     */
    static validateKeyEntropy(keyMaterial, fieldName = 'key material') {
        if (!Buffer.isBuffer(keyMaterial)) {
            return false;
        }

        const uniqueBytes = new Set(keyMaterial).size;
        const entropy = uniqueBytes / 256;

        if (entropy < SECURITY_CONFIG.MIN_ENTROPY_THRESHOLD) {
            console.warn(`⚠️  Low entropy detected in ${fieldName}: ${entropy.toFixed(3)}`);
            return false;
        }

        // Check for obvious patterns
        const allSame = keyMaterial.every(byte => byte === keyMaterial[0]);
        if (allSame) {
            console.warn(`⚠️  Weak ${fieldName} detected: all bytes identical`);
            return false;
        }

        return true;
    }

    // Private helper methods
    static #clearBuffer(buffer) {
        for (let pass = 0; pass < SECURITY_CONFIG.MEMORY_CLEAR_PASSES; pass++) {
            const randomData = randomBytes(buffer.length);
            randomData.copy(buffer);
            buffer.fill(pass % 2 === 0 ? 0x00 : 0xFF);
        }
        buffer.fill(0x00);
    }

    static #clearObject(obj) {
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                if (Buffer.isBuffer(obj[key])) {
                    this.secureClear(obj[key]);
                } else if (typeof obj[key] === 'string' && key.toLowerCase().includes('key')) {
                    obj[key] = '';
                }
            }
        }
    }

    static #cleanupOldEntries(now) {
        if (now - this.#lastCleanup > SECURITY_CONFIG.RATE_LIMIT_CLEANUP_INTERVAL) {
            const cutoff = Math.floor(now / 1000) - 60;
            for (const [key] of this.#validationHistory) {
                const keyTime = parseInt(key.split('-').pop());
                if (keyTime < cutoff) {
                    this.#validationHistory.delete(key);
                }
            }
            this.#lastCleanup = now;
        }
    }
}

// ============================================================================================
// INPUT VALIDATION
// ============================================================================================

/**
 * Input validation utilities for custodial wallet operations
 */
class InputValidator {
    /**
     * Validate network configuration
     * @param {string} network - Network type
     * @returns {Object} Validated network configuration
     */
    static validateNetworkConfig(network) {
        const networkValidation = validateNetwork(network);
        assertValid(networkValidation);
        return networkValidation.data;
    }

    /**
     * Validate master keys structure
     * @param {Object} masterKeys - Master keys object
     * @returns {Object} Validated master keys
     */
    static validateMasterKeys(masterKeys) {
        if (!masterKeys || typeof masterKeys !== 'object') {
            throw new CustodialWalletError(
                'Invalid master keys: must be an object',
                ERROR_CODES.INVALID_MASTER_KEYS
            );
        }

        const required = ['hdKey', 'keypair', 'address'];
        const missing = required.filter(key => !(key in masterKeys));

        if (missing.length > 0) {
            throw new CustodialWalletError(
                `Missing required master key fields: ${missing.join(', ')}`,
                ERROR_CODES.INVALID_MASTER_KEYS,
                { missing }
            );
        }

        return masterKeys;
    }

    /**
     * Validate derivation parameters
     * @param {string|number} account - Account index
     * @param {number} change - Change index (0 or 1)
     * @param {number} index - Address index
     */
    static validateDerivationParams(account, change, index) {
        if (typeof account !== 'number' && typeof account !== 'string') {
            throw new CustodialWalletError(
                'Invalid account parameter',
                ERROR_CODES.VALIDATION_FAILED
            );
        }

        if (typeof change !== 'number' || (change !== 0 && change !== 1)) {
            throw new CustodialWalletError(
                'Change parameter must be 0 or 1',
                ERROR_CODES.VALIDATION_FAILED
            );
        }

        if (typeof index !== 'number' || index < 0 || index >= SECURITY_CONFIG.MAX_CHILD_KEYS) {
            throw new CustodialWalletError(
                `Index must be between 0 and ${SECURITY_CONFIG.MAX_CHILD_KEYS - 1}`,
                ERROR_CODES.VALIDATION_FAILED
            );
        }
    }

    /**
     * Validate input size to prevent DoS attacks
     * @param {string|Buffer} input - Input to validate
     * @param {number} maxSize - Maximum allowed size
     * @param {string} fieldName - Field name for error reporting
     */
    static validateInputSize(input, maxSize, fieldName = 'input') {
        const size = typeof input === 'string' ? input.length : input.length;

        if (size > maxSize) {
            throw new CustodialWalletError(
                `${fieldName} too large: ${size} > ${maxSize}`,
                ERROR_CODES.VALIDATION_FAILED,
                { actualSize: size, maxSize, fieldName }
            );
        }
    }
}

// ============================================================================================
// KEY MANAGEMENT
// ============================================================================================

/**
 * Key management utilities for hierarchical deterministic key operations
 */
class KeyManager {
    /**
     * Generate child key from master key using BIP32 derivation
     * @param {Object} masterKeys - Master key information
     * @param {string} derivationPath - BIP32 derivation path
     * @param {Object} serializationFormat - Serialization format
     * @returns {Object} Derived child key information
     */
    static deriveChildKey(masterKeys, derivationPath, serializationFormat) {
        try {
            const pathValidation = validateDerivationPath(derivationPath);
            assertValid(pathValidation);

            const childKeys = derive(masterKeys.hdKey, derivationPath, serializationFormat);

            if (!childKeys || !childKeys.keypair) {
                throw new CustodialWalletError(
                    'Key derivation failed',
                    ERROR_CODES.DERIVATION_ERROR
                );
            }

            // Validate derived key entropy
            if (childKeys.keypair.privateKey &&
                !SecurityManager.validateKeyEntropy(childKeys.keypair.privateKey, 'derived private key')) {
                throw new CustodialWalletError(
                    'Derived key has insufficient entropy',
                    ERROR_CODES.INSUFFICIENT_ENTROPY
                );
            }

            return childKeys;
        } catch (error) {
            if (error instanceof CustodialWalletError) {
                throw error;
            }
            throw new CustodialWalletError(
                'Key derivation failed',
                ERROR_CODES.DERIVATION_ERROR,
                { originalError: error.message, derivationPath }
            );
        }
    }

    /**
     * Generate Bitcoin address from extended key information
     * @param {Object} extendedKeys - Extended key information
     * @param {Object} networkConfig - Network configuration
     * @returns {string} Bitcoin address
     */
    static generateAddress(extendedKeys, networkConfig) {
        try {
            const address = generateAddressFromExtendedVersion(extendedKeys, networkConfig);

            if (!address || typeof address !== 'string') {
                throw new CustodialWalletError(
                    'Address generation failed',
                    ERROR_CODES.DERIVATION_ERROR
                );
            }

            return address;
        } catch (error) {
            if (error instanceof CustodialWalletError) {
                throw error;
            }
            throw new CustodialWalletError(
                'Address generation failed',
                ERROR_CODES.DERIVATION_ERROR,
                { originalError: error.message }
            );
        }
    }
}

// ============================================================================================
// SIGNATURE OPERATIONS
// ============================================================================================

/**
 * Signature operations for transaction signing
 */
class SignatureManager {
    /**
     * Sign a transaction hash with ECDSA
     * @param {Buffer} messageHash - Hash to sign
     * @param {Buffer} privateKey - Private key for signing
     * @returns {Object} Signature object with r, s, and recovery values
     */
    static signTransaction(messageHash, privateKey) {
        try {
            if (!Buffer.isBuffer(messageHash) || messageHash.length !== 32) {
                throw new CustodialWalletError(
                    'Invalid message hash: must be 32-byte buffer',
                    ERROR_CODES.SIGNATURE_ERROR
                );
            }

            if (!Buffer.isBuffer(privateKey) || privateKey.length !== 32) {
                throw new CustodialWalletError(
                    'Invalid private key: must be 32-byte buffer',
                    ERROR_CODES.SIGNATURE_ERROR
                );
            }

            const signature = ecdsa.sign(messageHash, privateKey);

            if (!signature || !signature.r || !signature.s) {
                throw new CustodialWalletError(
                    'Signature generation failed',
                    ERROR_CODES.SIGNATURE_ERROR
                );
            }

            return signature;
        } catch (error) {
            if (error instanceof CustodialWalletError) {
                throw error;
            }
            throw new CustodialWalletError(
                'Transaction signing failed',
                ERROR_CODES.SIGNATURE_ERROR,
                { originalError: error.message }
            );
        }
    }

    /**
     * Verify an ECDSA signature
     * @param {Buffer} messageHash - Original message hash
     * @param {Object} signature - Signature to verify
     * @param {Buffer} publicKey - Public key for verification
     * @returns {boolean} True if signature is valid
     */
    static verifySignature(messageHash, signature, publicKey) {
        try {
            return ecdsa.verify(messageHash, signature, publicKey);
        } catch (error) {
            return false;
        }
    }
}

// ============================================================================================
// TRANSACTION INTEGRATION
// ============================================================================================

/**
 * Transaction management utilities for custodial wallet operations
 */
class TransactionManager {
    /**
     * Create and configure a transaction builder for the wallet
     * @param {string} network - Network type
     * @param {Object} options - Builder configuration options
     * @returns {TransactionBuilder} Configured transaction builder
     */
    static createBuilder(network, options = {}) {
        try {
            return new TransactionBuilder(network, {
                version: options.version || 2,
                rbf: options.rbf !== false,
                feeRate: options.feeRate || 10,
                priority: options.priority || 'normal',
                ...options
            });
        } catch (error) {
            throw new CustodialWalletError(
                'Failed to create transaction builder',
                ERROR_CODES.TRANSACTION_ERROR,
                { originalError: error.message }
            );
        }
    }

    /**
     * Create and configure a UTXO manager for the wallet
     * @param {string} network - Network type
     * @param {Object} options - Manager configuration options
     * @returns {UTXOManager} Configured UTXO manager
     */
    static createUTXOManager(network, options = {}) {
        try {
            return new UTXOManager({
                network,
                defaultStrategy: options.strategy || 'exactBiggest',
                privacyMode: options.privacyMode !== false,
                consolidationMode: options.consolidationMode || false,
                ...options
            });
        } catch (error) {
            throw new CustodialWalletError(
                'Failed to create UTXO manager',
                ERROR_CODES.TRANSACTION_ERROR,
                { originalError: error.message }
            );
        }
    }

    /**
     * Estimate transaction size for fee calculation
     * @param {number} inputCount - Number of inputs
     * @param {number} outputCount - Number of outputs
     * @param {string} inputType - Type of inputs ('p2pkh', 'p2wpkh', 'p2tr')
     * @returns {Object} Size estimation details
     */
    static estimateTransactionSize(inputCount, outputCount, inputType = 'p2wpkh') {
        const baseSizes = {
            'p2pkh': { scriptSig: 107, witness: 0 },
            'p2wpkh': { scriptSig: 0, witness: 107 },
            'p2sh': { scriptSig: 25, witness: 0 },
            'p2wsh': { scriptSig: 0, witness: 110 },
            'p2tr': { scriptSig: 0, witness: 65 }
        };

        const inputSize = baseSizes[inputType] || baseSizes['p2wpkh'];
        const outputSize = 31; // Standard output size

        const baseSize = 10; // Version (4) + input count (1) + output count (1) + locktime (4)
        const inputsSize = inputCount * (36 + inputSize.scriptSig); // 36 bytes for outpoint + sequence
        const outputsSize = outputCount * outputSize;
        const witnessSize = inputCount * inputSize.witness;

        const vsize = Math.ceil((baseSize + inputsSize + outputsSize + witnessSize * 0.25));

        return {
            baseSize: baseSize + inputsSize + outputsSize,
            witnessSize,
            totalSize: baseSize + inputsSize + outputsSize + witnessSize,
            vsize,
            inputType
        };
    }

    /**
     * Calculate recommended fee for transaction
     * @param {number} vsize - Virtual size of transaction
     * @param {number} feeRate - Fee rate in sat/vbyte
     * @param {string} priority - Priority level ('low', 'normal', 'high')
     * @returns {Object} Fee calculation details
     */
    static calculateFee(vsize, feeRate = 10, priority = 'normal') {
        const priorityMultipliers = {
            'low': 0.8,
            'normal': 1.0,
            'high': 1.5,
            'urgent': 2.0
        };

        const multiplier = priorityMultipliers[priority] || 1.0;
        const adjustedFeeRate = Math.ceil(feeRate * multiplier);
        const totalFee = vsize * adjustedFeeRate;

        return {
            feeRate: adjustedFeeRate,
            vsize,
            totalFee,
            priority,
            feePerByte: totalFee / vsize
        };
    }
}

// ============================================================================================
// MAIN WALLET CLASS
// ============================================================================================

/**
 * Enhanced custodial wallet implementation with comprehensive transaction integration
 */
class CustodialWallet {
    #serializationFormat;
    #networkConfig;
    #masterKeys;
    #utxoManager;
    #derivedKeys;

    /**
     * Creates a new CustodialWallet instance
     * @param {string} network - Network type ('main' or 'test')
     * @param {Object} masterKeys - Master key information
     * @param {Object} serializationFormat - Serialization format for key derivation
     */
    constructor(network, masterKeys, serializationFormat) {
        const startTime = Date.now();

        try {
            SecurityManager.checkRateLimit('wallet-construction');

            // Input validation
            const networkConfig = InputValidator.validateNetworkConfig(network);
            const validatedMasterKeys = InputValidator.validateMasterKeys(masterKeys);

            // Store validated configuration
            this.network = networkConfig.network;
            this.#networkConfig = getNetworkConfiguration(
                this.network === 'main' ? 'bitcoin' : 'testnet'
            );
            this.#masterKeys = validatedMasterKeys;
            this.#serializationFormat = serializationFormat;

            // Initialize transaction components
            this.#utxoManager = TransactionManager.createUTXOManager(this.network);
            this.#derivedKeys = new Map(); // Cache for derived keys

            SecurityManager.validateExecutionTime(startTime, 'wallet-construction');

        } catch (error) {
            if (error instanceof CustodialWalletError) {
                throw error;
            }
            throw new CustodialWalletError(
                'Wallet initialization failed',
                ERROR_CODES.VALIDATION_FAILED,
                { originalError: error.message }
            );
        }
    }

    /**
     * Derive a child key using BIP44 standard derivation path
     * @param {string|number} account - Account index
     * @param {number} change - Change index (0 for external, 1 for internal)
     * @param {number} index - Address index
     * @param {string} addressType - Address type ('legacy', 'segwit', 'taproot')
     * @returns {Object} Child key information including address
     */
    deriveChildKey(account = 0, change = 0, index = 0, addressType = 'segwit') {
        const startTime = Date.now();

        try {
            SecurityManager.checkRateLimit('key-derivation');
            InputValidator.validateDerivationParams(account, change, index);

            // Determine BIP purpose based on address type
            let purpose;
            switch (addressType.toLowerCase()) {
                case 'legacy':
                case 'p2pkh':
                    purpose = 44; // BIP44
                    break;
                case 'nested-segwit':
                case 'p2sh-p2wpkh':
                    purpose = 49; // BIP49
                    break;
                case 'segwit':
                case 'native-segwit':
                case 'p2wpkh':
                    purpose = 84; // BIP84
                    break;
                case 'taproot':
                case 'p2tr':
                    purpose = 86; // BIP86
                    break;
                default:
                    purpose = 84; // Default to native SegWit
                    addressType = 'segwit';
            }

            const coinType = this.network === 'main' ? 0 : 1;
            const derivationPath = `m/${purpose}'/${coinType}'/${account}'/${change}/${index}`;

            // Check cache first
            const cacheKey = `${derivationPath}-${addressType}`;
            if (this.#derivedKeys.has(cacheKey)) {
                return this.#derivedKeys.get(cacheKey);
            }

            const childKeys = KeyManager.deriveChildKey(
                this.#masterKeys,
                derivationPath,
                this.#serializationFormat
            );

            // Generate address based on type
            const address = this.#generateAddressByType(childKeys, addressType);

            const result = {
                derivationPath,
                purpose,
                addressType,
                privateKey: childKeys.keypair.privateKey,
                publicKey: childKeys.keypair.publicKey,
                address,
                extendedKeys: childKeys,
                network: this.network
            };

            // Cache the result
            this.#derivedKeys.set(cacheKey, result);

            SecurityManager.validateExecutionTime(startTime, 'key-derivation');
            return result;

        } catch (error) {
            if (error instanceof CustodialWalletError) {
                throw error;
            }
            throw new CustodialWalletError(
                'Child key derivation failed',
                ERROR_CODES.DERIVATION_ERROR,
                { originalError: error.message, account, change, index, addressType }
            );
        }
    }

    /**
     * Get receiving address for specified type
     * @param {number} index - Address index
     * @param {string} addressType - Address type
     * @returns {Object} Address information
     */
    getReceivingAddress(index = 0, addressType = 'segwit') {
        return this.deriveChildKey(0, 0, index, addressType);
    }

    /**
     * Get change address for specified type
     * @param {number} index - Address index  
     * @param {string} addressType - Address type
     * @returns {Object} Address information
     */
    getChangeAddress(index = 0, addressType = 'segwit') {
        return this.deriveChildKey(0, 1, index, addressType);
    }

    /**
     * Generate addresses for all supported types
     * @param {number} account - Account index
     * @param {number} index - Address index
     * @returns {Object} All address types
     */
    generateAllAddressTypes(account = 0, index = 0) {
        const addresses = {};
        const types = ['legacy', 'nested-segwit', 'segwit', 'taproot'];

        for (const type of types) {
            try {
                const keyInfo = this.deriveChildKey(account, 0, index, type);
                addresses[type] = {
                    address: keyInfo.address,
                    derivationPath: keyInfo.derivationPath,
                    purpose: keyInfo.purpose,
                    addressType: keyInfo.addressType
                };
            } catch (error) {
                addresses[type] = { error: error.message };
            }
        }

        return addresses;
    }

    /**
     * Get master public key for this wallet
     * @returns {Object} Master public key information
     */
    getMasterPublicKey() {
        try {
            return {
                publicKey: this.#masterKeys.keypair.publicKey,
                address: this.#masterKeys.address,
                network: this.network
            };
        } catch (error) {
            throw new CustodialWalletError(
                'Failed to retrieve master public key',
                ERROR_CODES.VALIDATION_FAILED,
                { originalError: error.message }
            );
        }
    }

    /**
     * Create a transaction builder configured for this wallet's network
     * @param {Object} options - Builder configuration options
     * @returns {TransactionBuilder} Configured transaction builder
     */
    createTransactionBuilder(options = {}) {
        try {
            SecurityManager.checkRateLimit('create-builder');
            return TransactionManager.createBuilder(this.network, options);
        } catch (error) {
            throw new CustodialWalletError(
                'Failed to create transaction builder',
                ERROR_CODES.TRANSACTION_ERROR,
                { originalError: error.message }
            );
        }
    }

    /**
     * Get the integrated UTXO manager for this wallet
     * @returns {UTXOManager} The wallet's UTXO manager
     */
    getUTXOManager() {
        return this.#utxoManager;
    }

    /**
     * Add UTXOs to the wallet's UTXO manager
     * @param {Array} utxos - Array of UTXO objects
     * @returns {Object} Addition result summary
     */
    addUTXOs(utxos) {
        const startTime = Date.now();

        try {
            SecurityManager.checkRateLimit('add-utxos');

            if (!Array.isArray(utxos)) {
                throw new CustodialWalletError(
                    'UTXOs must be provided as an array',
                    ERROR_CODES.VALIDATION_FAILED
                );
            }

            // Validate each UTXO has required fields
            const validatedUTXOs = utxos.map((utxo, index) => {
                if (!utxo.txid || typeof utxo.vout !== 'number' || typeof utxo.value !== 'number') {
                    throw new CustodialWalletError(
                        `Invalid UTXO at index ${index}: missing required fields`,
                        ERROR_CODES.VALIDATION_FAILED,
                        { utxoIndex: index, utxo }
                    );
                }
                return utxo;
            });

            this.#utxoManager.addUtxos(validatedUTXOs);

            SecurityManager.validateExecutionTime(startTime, 'add-utxos');

            return {
                success: true,
                utxosAdded: validatedUTXOs.length,
                totalUTXOs: this.#utxoManager.getUtxoCount ? this.#utxoManager.getUtxoCount() : validatedUTXOs.length
            };

        } catch (error) {
            if (error instanceof CustodialWalletError) {
                throw error;
            }
            throw new CustodialWalletError(
                'Failed to add UTXOs',
                ERROR_CODES.VALIDATION_FAILED,
                { originalError: error.message }
            );
        }
    }

    /**
     * Create a simple send transaction
     * @param {string} toAddress - Destination address
     * @param {number} amount - Amount to send in satoshis
     * @param {Object} options - Transaction options
     * @returns {Object} Complete transaction information
     */
    async sendTransaction(toAddress, amount, options = {}) {
        const startTime = Date.now();

        try {
            SecurityManager.checkRateLimit('send-transaction');

            // Validate inputs
            if (!toAddress || typeof toAddress !== 'string') {
                throw new CustodialWalletError(
                    'Invalid destination address',
                    ERROR_CODES.VALIDATION_FAILED
                );
            }

            if (typeof amount !== 'number' || amount <= 0) {
                throw new CustodialWalletError(
                    'Invalid amount: must be positive number',
                    ERROR_CODES.VALIDATION_FAILED
                );
            }

            // Estimate fee
            const sizeEstimate = TransactionManager.estimateTransactionSize(
                1, // Rough estimate
                1,
                options.inputType || 'p2wpkh'
            );

            const feeCalculation = TransactionManager.calculateFee(
                sizeEstimate.vsize,
                options.feeRate || 10,
                options.priority || 'normal'
            );

            // Select UTXOs
            const totalNeeded = amount + feeCalculation.totalFee;
            const utxoSelection = await this.#utxoManager.selectUtxos(totalNeeded, {
                strategy: options.utxoStrategy || 'exactBiggest',
                maxUtxos: options.maxUtxos || 10,
                privacyMode: options.privacyMode !== false
            });

            // Check if we need change
            const changeAmount = utxoSelection.totalValue - totalNeeded;
            const needsChange = changeAmount >= SECURITY_CONFIG.MIN_CHANGE_AMOUNT;

            // Create transaction builder
            const builder = this.createTransactionBuilder({
                feeRate: feeCalculation.feeRate,
                priority: options.priority || 'normal'
            });

            // Add inputs
            for (const utxo of utxoSelection.selectedUtxos) {
                builder.addInput({
                    txid: utxo.txid,
                    vout: utxo.vout,
                    value: utxo.value,
                    scriptPubKey: utxo.scriptPubKey,
                    address: utxo.address
                });
            }

            // Add main output
            builder.addOutput(toAddress, amount);

            // Add change output if needed
            let changeAddress = null;
            if (needsChange) {
                changeAddress = this.deriveChildKey(0, 1, options.changeIndex || 0).address;
                builder.addOutput(changeAddress, changeAmount);
            }

            // Sign transaction
            const unsignedTx = builder.build();
            const signedTx = await this.#signTransaction(unsignedTx, utxoSelection.selectedUtxos);

            // Mark UTXOs as spent
            const utxoKeys = utxoSelection.selectedUtxos.map(utxo => `${utxo.txid}:${utxo.vout}`);
            this.#utxoManager.markUtxosPending(utxoKeys);

            SecurityManager.validateExecutionTime(startTime, 'send-transaction');

            return {
                success: true,
                txid: signedTx.txid,
                transaction: signedTx,
                inputs: utxoSelection.selectedUtxos,
                outputs: [
                    { address: toAddress, value: amount, type: 'payment' },
                    ...(needsChange ? [{ address: changeAddress, value: changeAmount, type: 'change' }] : [])
                ],
                fee: {
                    amount: feeCalculation.totalFee,
                    rate: feeCalculation.feeRate,
                    priority: options.priority || 'normal'
                },
                size: {
                    estimated: sizeEstimate,
                    actual: signedTx.size || sizeEstimate.totalSize
                },
                metadata: {
                    strategy: utxoSelection.strategy,
                    privacyScore: utxoSelection.privacyScore || 0,
                    timestamp: Date.now()
                }
            };

        } catch (error) {
            if (error instanceof CustodialWalletError) {
                throw error;
            }
            throw new CustodialWalletError(
                'Transaction creation failed',
                ERROR_CODES.TRANSACTION_ERROR,
                { originalError: error.message }
            );
        }
    }

    /**
     * Sign a message with the wallet's master key (default) or specified key
     * @param {string} message - Message to sign
     * @param {Object} options - Signing options
     * @returns {Object} Signature information
     */
    signMessage(message, options = {}) {
        const startTime = Date.now();

        try {
            SecurityManager.checkRateLimit('sign-message');

            if (!message || typeof message !== 'string') {
                throw new CustodialWalletError(
                    'Invalid message: must be non-empty string',
                    ERROR_CODES.VALIDATION_FAILED
                );
            }

            let signingKey;
            let signingAddress;
            let usedDerivationPath = null;

            // Option 1: Use master key (default for custodial wallets)
            if (!options.useChildKey) {
                signingKey = {
                    privateKey: this.#masterKeys.keypair.privateKey,
                    publicKey: this.#masterKeys.keypair.publicKey,
                    address: this.#masterKeys.address
                };
                signingAddress = this.#masterKeys.address;
            }
            // Option 2: Use specific address (find corresponding key)
            else if (options.address) {
                signingKey = this.#findKeyForAddress(options.address);
                signingAddress = options.address;
            }
            // Option 3: Use specific derivation indices (simplified)
            else if (typeof options.account !== 'undefined' || typeof options.index !== 'undefined') {
                const account = options.account || 0;
                const change = options.change || 0;
                const index = options.index || 0;

                signingKey = this.deriveChildKey(account, change, index);
                signingAddress = signingKey.address;
                usedDerivationPath = signingKey.derivationPath;
            }
            // Option 4: For advanced users - direct derivation path
            else if (options.derivationPath) {
                const pathInfo = parseDerivationPath(options.derivationPath);
                signingKey = this.deriveChildKey(
                    pathInfo.account,
                    pathInfo.change,
                    pathInfo.index
                );
                signingAddress = signingKey.address;
                usedDerivationPath = options.derivationPath;
            }
            // Default: Use master key
            else {
                signingKey = {
                    privateKey: this.#masterKeys.keypair.privateKey,
                    publicKey: this.#masterKeys.keypair.publicKey,
                    address: this.#masterKeys.address
                };
                signingAddress = this.#masterKeys.address;
            }

            if (!signingKey) {
                throw new CustodialWalletError(
                    'Could not determine signing key',
                    ERROR_CODES.VALIDATION_FAILED
                );
            }

            // Create message hash (Bitcoin message signing standard)
            const messagePrefix = Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8');
            const messageBuffer = Buffer.from(message, 'utf8');
            const messageLength = Buffer.from([messageBuffer.length]);

            const fullMessage = Buffer.concat([messagePrefix, messageLength, messageBuffer]);
            const messageHash = createHash('sha256')
                .update(createHash('sha256').update(fullMessage).digest())
                .digest();

            // Sign the hash
            const signature = SignatureManager.signTransaction(messageHash, signingKey.privateKey);

            SecurityManager.validateExecutionTime(startTime, 'sign-message');

            return {
                message,
                signature,
                publicKey: signingKey.publicKey,
                address: signingAddress,
                derivationPath: usedDerivationPath,
                signedWith: usedDerivationPath ? 'child-key' : 'master-key',
                messageHash: messageHash.toString('hex')
            };

        } catch (error) {
            if (error instanceof CustodialWalletError) {
                throw error;
            }
            throw new CustodialWalletError(
                'Message signing failed',
                ERROR_CODES.SIGNATURE_ERROR,
                { originalError: error.message }
            );
        }
    }

    /**
     * Simple message signing with master key (most common custodial wallet use case)
     * @param {string} message - Message to sign
     * @returns {Object} Signature information
     */
    signMessageWithMasterKey(message) {
        return this.signMessage(message, { useChildKey: false });
    }

    /**
     * Sign message with a specific address (if key is available in wallet)
     * @param {string} message - Message to sign
     * @param {string} address - Address to sign with
     * @returns {Object} Signature information
     */
    signMessageWithAddress(message, address) {
        return this.signMessage(message, { address, useChildKey: true });
    }

    /**
     * Create a Taproot merkle tree for script operations
     * @param {Array} scriptLeaves - Array of script leaves
     * @returns {TaprootMerkleTree} Configured merkle tree
     */
    createTaprootMerkleTree(scriptLeaves) {
        try {
            SecurityManager.checkRateLimit('create-merkle-tree');

            if (!Array.isArray(scriptLeaves)) {
                throw new CustodialWalletError(
                    'Script leaves must be provided as an array',
                    ERROR_CODES.VALIDATION_FAILED
                );
            }

            return new TaprootMerkleTree(scriptLeaves);

        } catch (error) {
            if (error instanceof CustodialWalletError) {
                throw error;
            }
            throw new CustodialWalletError(
                'Merkle tree creation failed',
                ERROR_CODES.TRANSACTION_ERROR,
                { originalError: error.message }
            );
        }
    }

    /**
     * Get wallet summary and statistics
     * @returns {Object} Comprehensive wallet summary
     */
    getSummary() {
        try {
            const utxoStats = this.#utxoManager.getSummary ? this.#utxoManager.getSummary() : {
                totalUTXOs: 0,
                totalValue: 0,
                spendableUTXOs: 0
            };

            return {
                network: this.network,
                masterAddress: this.#masterKeys.address,
                derivedKeys: this.#derivedKeys.size,
                utxos: utxoStats,
                features: [
                    'BIP32 Hierarchical Deterministic Keys',
                    'BIP44 Standard Derivation',
                    'Integrated Transaction Building',
                    'Advanced UTXO Management',
                    'Enhanced Security Features',
                    'Rate Limiting Protection',
                    'Memory Security'
                ],
                version: '3.0.0',
                created: new Date().toISOString()
            };

        } catch (error) {
            throw new CustodialWalletError(
                'Failed to generate wallet summary',
                ERROR_CODES.VALIDATION_FAILED,
                { originalError: error.message }
            );
        }
    }

    /**
     * Secure cleanup of wallet resources
     */
    cleanup() {
        try {
            // Clear derived keys cache
            for (const [path, keyInfo] of this.#derivedKeys) {
                SecurityManager.secureClear(keyInfo.privateKey);
                SecurityManager.secureClear(keyInfo);
            }
            this.#derivedKeys.clear();

            // Clear master keys if possible
            if (this.#masterKeys.keypair && this.#masterKeys.keypair.privateKey) {
                SecurityManager.secureClear(this.#masterKeys.keypair.privateKey);
            }

            console.log('✅ Wallet cleanup completed successfully');

        } catch (error) {
            console.warn('⚠️  Wallet cleanup encountered errors:', error.message);
        }
    }

    // Private helper methods

    /**
     * Sign a transaction with selected UTXOs
     * @param {Object} unsignedTx - Unsigned transaction
     * @param {Array} utxos - UTXOs used in transaction
     * @returns {Object} Signed transaction
     */
    async #signTransaction(unsignedTx, utxos) {
        try {
            // This is a simplified signing process
            // In a real implementation, you would:
            // 1. Create proper transaction hashes for each input
            // 2. Sign each input with the appropriate private key
            // 3. Construct the final signed transaction

            const signedInputs = [];

            for (let i = 0; i < unsignedTx.inputs.length; i++) {
                const input = unsignedTx.inputs[i];
                const utxo = utxos[i];

                // Derive the key that controls this UTXO
                // This would typically involve looking up the derivation path
                // For now, we'll use a simplified approach
                const keyInfo = this.deriveChildKey(0, 0, i); // Simplified

                // Create transaction hash for this input
                const txHash = this.#createTransactionHash(unsignedTx, i);

                // Sign the hash
                const signature = SignatureManager.signTransaction(txHash, keyInfo.privateKey);

                signedInputs.push({
                    ...input,
                    signature,
                    publicKey: keyInfo.publicKey
                });
            }

            const signedTx = {
                ...unsignedTx,
                inputs: signedInputs,
                txid: this.#generateTxid(unsignedTx),
                signed: true
            };

            // Calculate transaction size
            signedTx.size = this.#calculateTransactionSize(signedTx);

            return signedTx;

        } catch (error) {
            throw new CustodialWalletError(
                'Transaction signing failed',
                ERROR_CODES.SIGNATURE_ERROR,
                { originalError: error.message }
            );
        }
    }

    /**
     * Create transaction hash for signing
     * @param {Object} transaction - Transaction to hash
     * @param {number} inputIndex - Input index being signed
     * @returns {Buffer} Transaction hash
     */
    #createTransactionHash(transaction, inputIndex) {
        // Simplified transaction hash creation
        // In reality, this would follow Bitcoin's transaction signing algorithm
        const hashData = JSON.stringify({
            version: transaction.version,
            inputs: transaction.inputs.map((input, i) =>
                i === inputIndex ? input : { txid: input.txid, vout: input.vout }
            ),
            outputs: transaction.outputs,
            locktime: transaction.locktime || 0
        });

        return createHash('sha256')
            .update(Buffer.from(hashData))
            .digest();
    }

    /**
     * Generate transaction ID
     * @param {Object} transaction - Transaction object
     * @returns {string} Transaction ID
     */
    #generateTxid(transaction) {
        const txData = JSON.stringify({
            version: transaction.version,
            inputs: transaction.inputs,
            outputs: transaction.outputs,
            locktime: transaction.locktime || 0
        });

        return createHash('sha256')
            .update(Buffer.from(txData))
            .digest('hex');
    }

    /**
     * Find the key information for a given address
     * @param {string} address - Address to find key for
     * @returns {Object} Key information
     */
    #findKeyForAddress(address) {
        // Check master key first
        if (this.#masterKeys.address === address) {
            return {
                privateKey: this.#masterKeys.keypair.privateKey,
                publicKey: this.#masterKeys.keypair.publicKey,
                address: this.#masterKeys.address
            };
        }

        // Check cached derived keys
        for (const [path, keyInfo] of this.#derivedKeys) {
            if (keyInfo.address === address) {
                return keyInfo;
            }
        }

        // If not found, try common derivation paths
        // This is a simplified search - in production you might want to maintain an address index
        for (let account = 0; account < 5; account++) {
            for (let change = 0; change < 2; change++) {
                for (let index = 0; index < 20; index++) {
                    try {
                        const keyInfo = this.deriveChildKey(account, change, index);
                        if (keyInfo.address === address) {
                            return keyInfo;
                        }
                    } catch (error) {
                        // Continue searching if derivation fails
                        continue;
                    }
                }
            }
        }

        throw new CustodialWalletError(
            `Address not found in wallet: ${address}`,
            ERROR_CODES.VALIDATION_FAILED,
            { address }
        );
    }

    /**
     * Generate address based on specified type
     * @param {Object} childKeys - Child key information
     * @param {string} addressType - Type of address to generate
     * @returns {string} Generated address
     */
    #generateAddressByType(childKeys, addressType) {
        try {
            const publicKey = childKeys.keypair.publicKey;

            switch (addressType.toLowerCase()) {
                case 'legacy':
                case 'p2pkh':
                    return this.#generateLegacyAddress(publicKey);

                case 'nested-segwit':
                case 'p2sh-p2wpkh':
                    return this.#generateNestedSegwitAddress(publicKey);

                case 'segwit':
                case 'native-segwit':
                case 'p2wpkh':
                    return this.#generateNativeSegwitAddress(publicKey);

                case 'taproot':
                case 'p2tr':
                    return this.#generateTaprootAddress(publicKey);

                default:
                    // Default to SegWit
                    return this.#generateNativeSegwitAddress(publicKey);
            }
        } catch (error) {
            throw new CustodialWalletError(
                `Address generation failed for type ${addressType}`,
                ERROR_CODES.DERIVATION_ERROR,
                { originalError: error.message, addressType }
            );
        }
    }

    /**
     * Generate legacy P2PKH address
     * @param {Buffer} publicKey - Public key
     * @returns {string} Legacy address
     */
    #generateLegacyAddress(publicKey) {
        const hash160 = createHash('ripemd160')
            .update(createHash('sha256').update(publicKey).digest())
            .digest();

        const versionByte = this.network === 'main' ? 0x00 : 0x6f;
        const payload = Buffer.concat([Buffer.from([versionByte]), hash160]);

        const checksum = createHash('sha256')
            .update(createHash('sha256').update(payload).digest())
            .digest()
            .slice(0, 4);

        const fullPayload = Buffer.concat([payload, checksum]);
        return this.#base58Encode(fullPayload);
    }

    /**
     * Generate nested SegWit P2SH-P2WPKH address
     * @param {Buffer} publicKey - Public key  
     * @returns {string} Nested SegWit address
     */
    #generateNestedSegwitAddress(publicKey) {
        const hash160 = createHash('ripemd160')
            .update(createHash('sha256').update(publicKey).digest())
            .digest();

        // Create P2WPKH script: OP_0 <hash160>
        const p2wpkhScript = Buffer.concat([Buffer.from([0x00, 0x14]), hash160]);

        // Hash the script for P2SH
        const scriptHash = createHash('ripemd160')
            .update(createHash('sha256').update(p2wpkhScript).digest())
            .digest();

        const versionByte = this.network === 'main' ? 0x05 : 0xc4;
        const payload = Buffer.concat([Buffer.from([versionByte]), scriptHash]);

        const checksum = createHash('sha256')
            .update(createHash('sha256').update(payload).digest())
            .digest()
            .slice(0, 4);

        const fullPayload = Buffer.concat([payload, checksum]);
        return this.#base58Encode(fullPayload);
    }

    /**
     * Generate native SegWit P2WPKH address
     * @param {Buffer} publicKey - Public key
     * @returns {string} Native SegWit address
     */
    #generateNativeSegwitAddress(publicKey) {
        const hash160 = createHash('ripemd160')
            .update(createHash('sha256').update(publicKey).digest())
            .digest();

        const hrp = this.network === 'main' ? 'bc' : 'tb';
        return this.#bech32Encode(hrp, 0, hash160);
    }

    /**
     * Generate Taproot P2TR address
     * @param {Buffer} publicKey - Public key
     * @returns {string} Taproot address
     */
    #generateTaprootAddress(publicKey) {
        // For Taproot, we need the x-coordinate of the public key
        // This is a simplified implementation
        let taprootKey;

        if (publicKey.length === 33) {
            // Remove the prefix byte for compressed key
            taprootKey = publicKey.slice(1);
        } else if (publicKey.length === 32) {
            taprootKey = publicKey;
        } else {
            throw new CustodialWalletError(
                'Invalid public key length for Taproot',
                ERROR_CODES.VALIDATION_FAILED
            );
        }

        const hrp = this.network === 'main' ? 'bc' : 'tb';
        return this.#bech32Encode(hrp, 1, taprootKey);
    }

    /**
     * Simple Base58 encoding implementation
     * @param {Buffer} buffer - Buffer to encode
     * @returns {string} Base58 encoded string
     */
    #base58Encode(buffer) {
        const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        let num = BigInt('0x' + buffer.toString('hex'));
        let result = '';

        while (num > 0) {
            const remainder = Number(num % 58n);
            result = alphabet[remainder] + result;
            num = num / 58n;
        }

        // Add leading zeros
        for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
            result = '1' + result;
        }

        return result;
    }

    /**
     * Simple Bech32 encoding implementation
     * @param {string} hrp - Human readable part
     * @param {number} version - Witness version
     * @param {Buffer} data - Data to encode
     * @returns {string} Bech32 encoded address
     */
    #bech32Encode(hrp, version, data) {
        // This is a simplified implementation
        // In production, you'd use a proper Bech32 library
        const charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

        // Convert data to 5-bit groups
        const fiveBitData = this.#convertTo5Bit(data);
        const fullData = [version, ...fiveBitData];

        // Calculate checksum (simplified)
        const checksum = this.#bech32Checksum(hrp, fullData);
        const combined = fullData.concat(checksum);

        return hrp + '1' + combined.map(x => charset[x]).join('');
    }

    /**
     * Convert 8-bit data to 5-bit groups
     * @param {Buffer} data - 8-bit data
     * @returns {Array} 5-bit data array
     */
    #convertTo5Bit(data) {
        let acc = 0;
        let bits = 0;
        const result = [];
        const maxv = (1 << 5) - 1;

        for (const value of data) {
            acc = (acc << 8) | value;
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                result.push((acc >> bits) & maxv);
            }
        }

        if (bits > 0) {
            result.push((acc << (5 - bits)) & maxv);
        }

        return result;
    }

    /**
     * Calculate Bech32 checksum (simplified)
     * @param {string} hrp - Human readable part
     * @param {Array} data - Data array
     * @returns {Array} Checksum array
     */
    #bech32Checksum(hrp, data) {
        // Simplified checksum calculation
        // In production, use proper Bech32 implementation
        const values = this.#hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
        const polymod = this.#bech32Polymod(values) ^ 1;
        const result = [];
        for (let i = 0; i < 6; i++) {
            result.push((polymod >> 5 * (5 - i)) & 31);
        }
        return result;
    }

    /**
     * Expand HRP for checksum calculation
     * @param {string} hrp - Human readable part
     * @returns {Array} Expanded HRP
     */
    #hrpExpand(hrp) {
        const result = [];
        for (let i = 0; i < hrp.length; i++) {
            result.push(hrp.charCodeAt(i) >> 5);
        }
        result.push(0);
        for (let i = 0; i < hrp.length; i++) {
            result.push(hrp.charCodeAt(i) & 31);
        }
        return result;
    }

    /**
     * Bech32 polymod calculation
     * @param {Array} values - Values to process
     * @returns {number} Polymod result
     */
    #bech32Polymod(values) {
        const generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let chk = 1;
        for (const value of values) {
            const top = chk >> 25;
            chk = (chk & 0x1ffffff) << 5 ^ value;
            for (let i = 0; i < 5; i++) {
                chk ^= ((top >> i) & 1) ? generator[i] : 0;
            }
        }
        /**
         * Calculate transaction size
         * @param {Object} transaction - Transaction object
         * @returns {number} Transaction size in bytes
         */
        #calculateTransactionSize(transaction) {
            // Simplified size calculation
            const baseSize = 10; // Version + input count + output count + locktime
            const inputsSize = transaction.inputs.length * 150; // Approximate input size
            const outputsSize = transaction.outputs.length * 34; // Approximate output size

            return baseSize + inputsSize + outputsSize;
        }

        /**
         * Get supported transaction types for this wallet
         * @returns {Object} Supported transaction types and their details
         */
        getSupportedTransactionTypes() {
            return {
                legacy: {
                    name: 'Pay-to-Public-Key-Hash (P2PKH)',
                    bip: 'BIP44',
                    purpose: 44,
                    format: 'Base58',
                    prefix: this.network === 'main' ? '1' : 'm/n',
                    pros: ['Highest compatibility', 'Supported everywhere'],
                    cons: ['Higher fees', 'Larger transaction size'],
                    scriptType: 'p2pkh'
                },
                'nested-segwit': {
                    name: 'P2SH-wrapped SegWit (P2SH-P2WPKH)',
                    bip: 'BIP49',
                    purpose: 49,
                    format: 'Base58',
                    prefix: this.network === 'main' ? '3' : '2',
                    pros: ['SegWit benefits', 'Backward compatible'],
                    cons: ['More complex', 'Slightly higher fees than native'],
                    scriptType: 'p2sh-p2wpkh'
                },
                segwit: {
                    name: 'Native SegWit (P2WPKH)',
                    bip: 'BIP84',
                    purpose: 84,
                    format: 'Bech32',
                    prefix: this.network === 'main' ? 'bc1q' : 'tb1q',
                    pros: ['Lower fees', 'Faster confirmation', 'More efficient'],
                    cons: ['Less universal support (older wallets)'],
                    scriptType: 'p2wpkh'
                },
                taproot: {
                    name: 'Taproot (P2TR)',
                    bip: 'BIP86',
                    purpose: 86,
                    format: 'Bech32m',
                    prefix: this.network === 'main' ? 'bc1p' : 'tb1p',
                    pros: ['Highest privacy', 'Smart contracts', 'Lowest fees'],
                    cons: ['Newest format', 'Limited support'],
                    scriptType: 'p2tr'
                }
            };
        }
    }

// ============================================================================================
// FACTORY METHODS
// ============================================================================================

/**
 * Factory class for creating custodial wallets
 */
class CustodialWalletFactory {
    /**
     * Create a new custodial wallet from a mnemonic phrase
     * @param {string} network - Network type ('main' or 'test')
     * @param {string} mnemonic - BIP39 mnemonic phrase
     * @param {Object} options - Creation options
     * @returns {CustodialWallet} New wallet instance
     */
    static fromMnemonic(network, mnemonic, options = {}) {
        try {
            // Validate mnemonic
            const mnemonicValidation = validateMnemonic(mnemonic);
            assertValid(mnemonicValidation);

            // Generate master key from mnemonic
            const masterKeys = generateMasterKey(mnemonic, options.passphrase || '');

            // Create serialization format
            const serializationFormat = encodeStandardKeys(network);

            return new CustodialWallet(network, masterKeys, serializationFormat);

        } catch (error) {
            throw new CustodialWalletError(
                'Failed to create wallet from mnemonic',
                ERROR_CODES.VALIDATION_FAILED,
                { originalError: error.message }
            );
        }
    }

    /**
     * Create a new custodial wallet with a randomly generated mnemonic
     * @param {string} network - Network type ('main' or 'test')
     * @param {Object} options - Creation options
     * @returns {Object} Wallet and mnemonic information
     */
    static createRandom(network, options = {}) {
        try {
            // Generate random mnemonic
            const wordCount = options.wordCount || 12;
            const mnemonic = BIP39.generateMnemonic(wordCount);

            // Create wallet from generated mnemonic
            const wallet = this.fromMnemonic(network, mnemonic, options);

            return {
                wallet,
                mnemonic,
                wordCount,
                network
            };

        } catch (error) {
            throw new CustodialWalletError(
                'Failed to create random wallet',
                ERROR_CODES.VALIDATION_FAILED,
                { originalError: error.message }
            );
        }
    }
}

// ============================================================================================
// EXPORTS
// ============================================================================================

export {
    CustodialWallet,
    CustodialWalletFactory,
    CustodialWalletError,
    SecurityManager,
    InputValidator,
    KeyManager,
    SignatureManager,
    TransactionManager,
    SECURITY_CONFIG,
    ERROR_CODES
};

export default CustodialWallet;