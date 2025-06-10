/**
 * @fileoverview Enhanced PSBT-first transaction builder with Taproot support (FIXED)
 * 
 * FIXES IMPLEMENTED:
 * - Corrected imports and dependencies
 * - Proper address decoding integration
 * - Complete script generation implementation
 * - Enhanced security and validation
 * - Consistent immutable API pattern
 * - Better error handling and resource management
 * 
 * @author yfbsei
 * @version 2.1.1
 */

import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import rmd160 from '../core/crypto/hash/ripemd160.js';
import { BECH32 } from '../bip/BIP173-BIP350.js';
import {
    NETWORK_VERSIONS,
    CRYPTO_CONSTANTS,
    BIP44_CONSTANTS,
    validateAndGetNetwork
} from '../core/constants.js';
import {
    validateAddress,
    validateBufferLength,
    validateNumberRange,
    assertValid,
    ValidationError
} from '../utils/validation.js';
import {
    decodeLegacyAddress,
    AddressSecurityUtils,
    detectAddressFormat
} from '../utils/address-helpers.js';
import { TaprootControlBlock } from '../core/taproot/control-block.js';
import { TaprootMerkleTree } from '../core/taproot/merkle-tree.js';

/**
 * Transaction builder specific error class
 */
class TransactionBuilderError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'TransactionBuilderError';
        this.code = code;
        this.details = details;
        this.timestamp = Date.now();
    }
}

/**
 * Transaction building constants and limits
 */
const TRANSACTION_CONSTANTS = {
    // Transaction limits
    MAX_TRANSACTION_SIZE: 100000,      // 100KB standard limit
    MAX_INPUTS: 10000,                 // Reasonable limit for performance
    MAX_OUTPUTS: 10000,                // Reasonable limit for performance
    MIN_OUTPUT_VALUE: 546,             // Dust limit for most outputs
    MIN_FEE_RATE: 1,                   // 1 sat/vbyte minimum

    // Version and lock time
    DEFAULT_VERSION: 2,                // BIP68/112/113 support
    DEFAULT_LOCKTIME: 0,               // No lock time by default
    MAX_LOCKTIME: 0xffffffff,          // Maximum valid lock time

    // Sequence numbers
    RBF_SEQUENCE: 0xfffffffd,          // RBF-enabled sequence
    FINAL_SEQUENCE: 0xfffffffe,        // Final sequence (disable RBF)
    MAX_SEQUENCE: 0xffffffff,          // Maximum sequence

    // Weight calculations (witness units)
    LEGACY_INPUT_BASE_WEIGHT: 148 * 4,    // Legacy P2PKH input
    SEGWIT_INPUT_BASE_WEIGHT: 68 * 4,     // P2WPKH input
    TAPROOT_INPUT_BASE_WEIGHT: 57.5 * 4,  // P2TR input (avg)
    OUTPUT_BASE_WEIGHT: 34 * 4,           // Standard output weight
    BASE_TRANSACTION_WEIGHT: 10 * 4,      // Base transaction weight

    // Fee estimation
    DEFAULT_FEE_RATE: 10,              // 10 sat/vbyte default
    HIGH_FEE_RATE: 50,                 // 50 sat/vbyte high priority
    ECONOMY_FEE_RATE: 5,               // 5 sat/vbyte economy

    // Security limits
    MAX_VALIDATIONS_PER_SECOND: 100,   // Rate limiting
    MAX_BUILD_TIME_MS: 30000,          // 30 second build timeout
    MAX_SIGNING_TIME_MS: 60000         // 60 second signing timeout
};

/**
 * @typedef {Object} TransactionInput
 * @property {string} txid - Transaction ID of the UTXO
 * @property {number} vout - Output index in the transaction
 * @property {number} value - Value in satoshis
 * @property {Buffer} scriptPubKey - Script public key of the output
 * @property {string} type - Address type ('p2pkh', 'p2sh', 'p2wpkh', 'p2wsh', 'p2tr')
 * @property {number} sequence - Sequence number for the input
 * @property {Buffer} [witnessScript] - Witness script for segwit inputs
 * @property {Buffer} [redeemScript] - Redeem script for P2SH inputs
 * @property {Object} [taproot] - Taproot-specific data
 */

/**
 * @typedef {Object} TransactionOutput
 * @property {string} address - Destination address
 * @property {number} value - Value in satoshis
 * @property {Buffer} scriptPubKey - Generated script public key
 * @property {string} type - Address type
 * @property {Object} decodedAddress - Decoded address information
 */

/**
 * @typedef {Object} FeeOptions
 * @property {number} [feeRate] - Fee rate in sat/vbyte
 * @property {number} [absoluteFee] - Absolute fee in satoshis
 * @property {string} [priority] - Fee priority ('economy', 'normal', 'high')
 * @property {boolean} [rbf] - Enable Replace-by-Fee
 */

/**
 * Enhanced security utilities for transaction building
 */
class TransactionSecurityUtils {
    static validationHistory = new Map();
    static lastCleanup = Date.now();

    /**
     * Rate limiting for transaction operations
     */
    static checkRateLimit(operation = 'transaction-build') {
        const now = Date.now();
        const secondKey = `${operation}-${Math.floor(now / 1000)}`;
        const currentCount = this.validationHistory.get(secondKey) || 0;

        if (currentCount >= TRANSACTION_CONSTANTS.MAX_VALIDATIONS_PER_SECOND) {
            throw new TransactionBuilderError(
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
     * Validates build time to prevent DoS attacks
     */
    static validateBuildTime(startTime, operation = 'transaction build') {
        const elapsed = Date.now() - startTime;
        if (elapsed > TRANSACTION_CONSTANTS.MAX_BUILD_TIME_MS) {
            throw new TransactionBuilderError(
                `${operation} timeout: ${elapsed}ms > ${TRANSACTION_CONSTANTS.MAX_BUILD_TIME_MS}ms`,
                'BUILD_TIMEOUT',
                { elapsed, maxTime: TRANSACTION_CONSTANTS.MAX_BUILD_TIME_MS }
            );
        }
    }

    /**
     * Validates transaction size limits
     */
    static validateTransactionSize(sizeBytes, operation = 'transaction') {
        if (sizeBytes > TRANSACTION_CONSTANTS.MAX_TRANSACTION_SIZE) {
            throw new TransactionBuilderError(
                `${operation} too large: ${sizeBytes} > ${TRANSACTION_CONSTANTS.MAX_TRANSACTION_SIZE}`,
                'TRANSACTION_TOO_LARGE',
                { actualSize: sizeBytes, maxSize: TRANSACTION_CONSTANTS.MAX_TRANSACTION_SIZE }
            );
        }
    }

    /**
     * Validates input/output limits
     */
    static validateIOLimits(inputs, outputs) {
        if (inputs.length > TRANSACTION_CONSTANTS.MAX_INPUTS) {
            throw new TransactionBuilderError(
                `Too many inputs: ${inputs.length} > ${TRANSACTION_CONSTANTS.MAX_INPUTS}`,
                'TOO_MANY_INPUTS'
            );
        }

        if (outputs.length > TRANSACTION_CONSTANTS.MAX_OUTPUTS) {
            throw new TransactionBuilderError(
                `Too many outputs: ${outputs.length} > ${TRANSACTION_CONSTANTS.MAX_OUTPUTS}`,
                'TOO_MANY_OUTPUTS'
            );
        }
    }

    /**
     * Validates dust limits for outputs
     */
    static validateDustLimits(outputs) {
        for (let i = 0; i < outputs.length; i++) {
            const output = outputs[i];
            if (output.value < TRANSACTION_CONSTANTS.MIN_OUTPUT_VALUE) {
                throw new TransactionBuilderError(
                    `Output ${i} below dust limit: ${output.value} < ${TRANSACTION_CONSTANTS.MIN_OUTPUT_VALUE}`,
                    'DUST_OUTPUT',
                    { outputIndex: i, value: output.value, dustLimit: TRANSACTION_CONSTANTS.MIN_OUTPUT_VALUE }
                );
            }
        }
    }

    /**
     * Secure memory clearing for transaction data
     */
    static secureClear(data) {
        if (Buffer.isBuffer(data)) {
            const randomData = randomBytes(data.length);
            randomData.copy(data);
            data.fill(0);
        } else if (typeof data === 'object' && data !== null) {
            for (const key in data) {
                if (Buffer.isBuffer(data[key])) {
                    this.secureClear(data[key]);
                } else if (typeof data[key] === 'string' && key.includes('key')) {
                    data[key] = '';
                }
            }
        }
    }
}

/**
 * Address utilities for proper script generation
 */
class AddressUtils {
    /**
     * Create proper hash160 function (FIXED)
     */
    static hash160(data) {
        const sha256Hash = createHash('sha256').update(data).digest();
        return rmd160(sha256Hash);
    }

    /**
     * Decode address and extract hash for script generation (FIXED)
     */
    static decodeAddressForScript(address) {
        const formatInfo = detectAddressFormat(address);

        switch (formatInfo.format) {
            case 'legacy':
                const decoded = decodeLegacyAddress(address);
                return {
                    hash: decoded.hash160Buffer,
                    type: decoded.addressType,
                    network: decoded.network,
                    scriptType: decoded.addressType === 'P2PKH' ? 'p2pkh' : 'p2sh'
                };

            case 'segwit':
                // For segwit addresses, we need to decode bech32
                try {
                    const bech32Decoded = BECH32.decode(address);
                    const witnessProgram = Buffer.from(bech32Decoded.data.slice(1)); // Skip version byte

                    return {
                        hash: witnessProgram,
                        type: witnessProgram.length === 20 ? 'P2WPKH' : 'P2WSH',
                        network: bech32Decoded.hrp === 'bc' ? 'mainnet' : 'testnet',
                        scriptType: witnessProgram.length === 20 ? 'p2wpkh' : 'p2wsh',
                        witnessVersion: bech32Decoded.data[0]
                    };
                } catch (error) {
                    throw new TransactionBuilderError(
                        `Failed to decode segwit address: ${error.message}`,
                        'SEGWIT_DECODE_FAILED'
                    );
                }

            case 'taproot':
                // For taproot addresses
                try {
                    const bech32Decoded = BECH32.decode(address);
                    const witnessProgram = Buffer.from(bech32Decoded.data.slice(1)); // Skip version byte

                    if (witnessProgram.length !== 32) {
                        throw new Error('Invalid taproot witness program length');
                    }

                    return {
                        hash: witnessProgram,
                        type: 'P2TR',
                        network: bech32Decoded.hrp === 'bc' ? 'mainnet' : 'testnet',
                        scriptType: 'p2tr',
                        witnessVersion: 1
                    };
                } catch (error) {
                    throw new TransactionBuilderError(
                        `Failed to decode taproot address: ${error.message}`,
                        'TAPROOT_DECODE_FAILED'
                    );
                }

            default:
                throw new TransactionBuilderError(
                    `Unsupported address format: ${formatInfo.format}`,
                    'UNSUPPORTED_ADDRESS_FORMAT'
                );
        }
    }

    /**
     * Create scriptPubKey from decoded address (FIXED)
     */
    static createScriptPubKey(decodedAddress) {
        switch (decodedAddress.scriptType) {
            case 'p2pkh':
                // OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
                return Buffer.concat([
                    Buffer.from([0x76, 0xa9, 0x14]), // OP_DUP OP_HASH160 PUSH(20)
                    decodedAddress.hash,
                    Buffer.from([0x88, 0xac]) // OP_EQUALVERIFY OP_CHECKSIG
                ]);

            case 'p2sh':
                // OP_HASH160 <hash160> OP_EQUAL
                return Buffer.concat([
                    Buffer.from([0xa9, 0x14]), // OP_HASH160 PUSH(20)
                    decodedAddress.hash,
                    Buffer.from([0x87]) // OP_EQUAL
                ]);

            case 'p2wpkh':
                // OP_0 <hash160>
                return Buffer.concat([
                    Buffer.from([0x00, 0x14]), // OP_0 PUSH(20)
                    decodedAddress.hash
                ]);

            case 'p2wsh':
                // OP_0 <sha256>
                return Buffer.concat([
                    Buffer.from([0x00, 0x20]), // OP_0 PUSH(32)
                    decodedAddress.hash
                ]);

            case 'p2tr':
                // OP_1 <pubkey>
                return Buffer.concat([
                    Buffer.from([0x51, 0x20]), // OP_1 PUSH(32)
                    decodedAddress.hash
                ]);

            default:
                throw new TransactionBuilderError(
                    `Cannot create script for type: ${decodedAddress.scriptType}`,
                    'UNSUPPORTED_SCRIPT_TYPE'
                );
        }
    }

    /**
     * Calculate accurate script sizes for weight estimation (FIXED)
     */
    static getInputScriptSizes(inputType, redeemScript = null, witnessScript = null) {
        switch (inputType) {
            case 'p2pkh':
                return {
                    scriptSigSize: 107, // sig(72) + pubkey(33) + opcodes
                    witnessSize: 0
                };

            case 'p2sh':
                const redeemScriptSize = redeemScript ? redeemScript.length : 25; // Assume P2WPKH redeem
                return {
                    scriptSigSize: redeemScriptSize + 2, // redeemScript + opcodes
                    witnessSize: redeemScript && redeemScript[0] === 0x00 ? 107 : 0 // P2SH-wrapped segwit
                };

            case 'p2wpkh':
                return {
                    scriptSigSize: 0,
                    witnessSize: 107 // sig(72) + pubkey(33) + 2 items
                };

            case 'p2wsh':
                const witnessScriptSize = witnessScript ? witnessScript.length : 25;
                return {
                    scriptSigSize: 0,
                    witnessSize: 72 + 33 + witnessScriptSize + 10 // Estimate for 1-of-1 multisig
                };

            case 'p2tr':
                return {
                    scriptSigSize: 0,
                    witnessSize: 65 // Schnorr sig(64) + 1 item
                };

            default:
                return {
                    scriptSigSize: 100, // Conservative estimate
                    witnessSize: 0
                };
        }
    }
}

/**
 * Modern PSBT-first transaction builder with immutable pattern (FIXED)
 */
class TransactionBuilder {
    /**
     * Create a new transaction builder instance
     * 
     * @param {string} [network='main'] - Network type ('main' or 'test')
     * @param {Object} [options={}] - Builder configuration options
     */
    constructor(network = 'main', options = {}) {
        // Validate and set network
        const networkConfig = validateAndGetNetwork(network);

        // Immutable properties
        Object.defineProperties(this, {
            network: { value: network, writable: false },
            networkConfig: { value: networkConfig, writable: false },
            _buildId: { value: this._generateBuildId(), writable: false },
            _createdAt: { value: Date.now(), writable: false }
        });

        // Immutable state
        this._inputs = Object.freeze([]);
        this._outputs = Object.freeze([]);
        this._version = options.version || TRANSACTION_CONSTANTS.DEFAULT_VERSION;
        this._locktime = options.locktime || TRANSACTION_CONSTANTS.DEFAULT_LOCKTIME;
        this._rbfEnabled = options.rbf !== false; // Default true
        this._feeOptions = Object.freeze({
            feeRate: options.feeRate || TRANSACTION_CONSTANTS.DEFAULT_FEE_RATE,
            priority: options.priority || 'normal',
            rbf: this._rbfEnabled
        });

        // Builder state
        this._built = false;
        this._signed = false;
        this._psbtData = null;
        this._estimatedSize = 0;
        this._estimatedFee = 0;
    }

    /**
     * Generate unique build ID for tracking
     */
    _generateBuildId() {
        const timestamp = Date.now().toString(36);
        const random = randomBytes(4).toString('hex');
        return `txb_${timestamp}_${random}`;
    }

    /**
     * Create a new builder instance with updated properties (immutable pattern) (FIXED)
     */
    _clone(updates = {}) {
        const newBuilder = Object.create(TransactionBuilder.prototype);

        // Copy immutable properties
        Object.defineProperties(newBuilder, {
            network: { value: this.network, writable: false },
            networkConfig: { value: this.networkConfig, writable: false },
            _buildId: { value: this._buildId, writable: false },
            _createdAt: { value: this._createdAt, writable: false }
        });

        // Copy current state
        newBuilder._inputs = this._inputs;
        newBuilder._outputs = this._outputs;
        newBuilder._version = this._version;
        newBuilder._locktime = this._locktime;
        newBuilder._rbfEnabled = this._rbfEnabled;
        newBuilder._feeOptions = this._feeOptions;
        newBuilder._built = this._built;
        newBuilder._signed = this._signed;
        newBuilder._psbtData = this._psbtData;
        newBuilder._estimatedSize = this._estimatedSize;
        newBuilder._estimatedFee = this._estimatedFee;

        // Apply updates
        Object.assign(newBuilder, updates);

        return newBuilder;
    }

    /**
     * Add a UTXO input to the transaction (FIXED)
     * 
     * @param {TransactionInput} input - Input configuration
     * @returns {TransactionBuilder} New builder instance with added input
     */
    addInput(input) {
        const startTime = Date.now();

        try {
            TransactionSecurityUtils.checkRateLimit('add-input');

            // Validate input structure
            this._validateInputStructure(input);

            // Create validated input object
            const validatedInput = this._prepareInput(input);

            // Check limits
            const newInputs = [...this._inputs, validatedInput];
            TransactionSecurityUtils.validateIOLimits(newInputs, this._outputs);

            TransactionSecurityUtils.validateBuildTime(startTime, 'add input');

            return this._clone({
                _inputs: Object.freeze(newInputs),
                _built: false,
                _signed: false
            });

        } catch (error) {
            if (error instanceof TransactionBuilderError || error instanceof ValidationError) {
                throw error;
            }
            throw new TransactionBuilderError(
                `Failed to add input: ${error.message}`,
                'ADD_INPUT_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Add an output to the transaction (FIXED)
     * 
     * @param {string} address - Destination address
     * @param {number} value - Value in satoshis
     * @returns {TransactionBuilder} New builder instance with added output
     */
    addOutput(address, value) {
        const startTime = Date.now();

        try {
            TransactionSecurityUtils.checkRateLimit('add-output');

            // Validate address
            const addressValidation = validateAddress(address);
            assertValid(addressValidation);

            // Validate value
            const valueValidation = validateNumberRange(
                value,
                TRANSACTION_CONSTANTS.MIN_OUTPUT_VALUE,
                Number.MAX_SAFE_INTEGER,
                'output value'
            );
            assertValid(valueValidation);

            // Create output object with proper address decoding
            const output = this._prepareOutput(address, value);

            // Check limits
            const newOutputs = [...this._outputs, output];
            TransactionSecurityUtils.validateIOLimits(this._inputs, newOutputs);
            TransactionSecurityUtils.validateDustLimits(newOutputs);

            TransactionSecurityUtils.validateBuildTime(startTime, 'add output');

            return this._clone({
                _outputs: Object.freeze(newOutputs),
                _built: false,
                _signed: false
            });

        } catch (error) {
            if (error instanceof TransactionBuilderError || error instanceof ValidationError) {
                throw error;
            }
            throw new TransactionBuilderError(
                `Failed to add output: ${error.message}`,
                'ADD_OUTPUT_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Set fee options for the transaction
     * 
     * @param {FeeOptions} feeOptions - Fee configuration
     * @returns {TransactionBuilder} New builder instance with updated fee options
     */
    setFeeOptions(feeOptions) {
        try {
            TransactionSecurityUtils.checkRateLimit('set-fee');

            // Validate fee options
            this._validateFeeOptions(feeOptions);

            const newFeeOptions = Object.freeze({
                ...this._feeOptions,
                ...feeOptions
            });

            return this._clone({
                _feeOptions: newFeeOptions,
                _built: false,
                _signed: false
            });

        } catch (error) {
            if (error instanceof TransactionBuilderError) {
                throw error;
            }
            throw new TransactionBuilderError(
                `Failed to set fee options: ${error.message}`,
                'SET_FEE_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Enable or disable Replace-by-Fee (RBF)
     * 
     * @param {boolean} enabled - Whether to enable RBF
     * @returns {TransactionBuilder} New builder instance with updated RBF setting
     */
    setRBF(enabled) {
        try {
            const newFeeOptions = Object.freeze({
                ...this._feeOptions,
                rbf: enabled
            });

            return this._clone({
                _rbfEnabled: enabled,
                _feeOptions: newFeeOptions,
                _built: false,
                _signed: false
            });

        } catch (error) {
            throw new TransactionBuilderError(
                `Failed to set RBF: ${error.message}`,
                'SET_RBF_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Set transaction version
     * 
     * @param {number} version - Transaction version (1 or 2)
     * @returns {TransactionBuilder} New builder instance with updated version
     */
    setVersion(version) {
        try {
            const versionValidation = validateNumberRange(version, 1, 2, 'transaction version');
            assertValid(versionValidation);

            return this._clone({
                _version: version,
                _built: false,
                _signed: false
            });

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }
            throw new TransactionBuilderError(
                `Failed to set version: ${error.message}`,
                'SET_VERSION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Set transaction lock time
     * 
     * @param {number} locktime - Lock time value
     * @returns {TransactionBuilder} New builder instance with updated lock time
     */
    setLocktime(locktime) {
        try {
            const locktimeValidation = validateNumberRange(
                locktime,
                0,
                TRANSACTION_CONSTANTS.MAX_LOCKTIME,
                'locktime'
            );
            assertValid(locktimeValidation);

            return this._clone({
                _locktime: locktime,
                _built: false,
                _signed: false
            });

        } catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }
            throw new TransactionBuilderError(
                `Failed to set locktime: ${error.message}`,
                'SET_LOCKTIME_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Build the transaction and create PSBT
     * 
     * @returns {Object} Built transaction with PSBT data
     */
    build() {
        const startTime = Date.now();

        try {
            TransactionSecurityUtils.checkRateLimit('build');

            if (this._built) {
                return this._getBuiltTransaction();
            }

            // Validate transaction structure
            this._validateTransactionStructure();

            // Calculate fees and finalize amounts
            const feeCalculation = this._calculateFees();

            // Create PSBT data
            const psbtData = this._createPSBTData(feeCalculation);

            // Build raw transaction
            const rawTransaction = this._buildRawTransaction(feeCalculation);

            // Update builder state
            const updatedBuilder = this._clone({
                _built: true,
                _psbtData: psbtData,
                _estimatedSize: feeCalculation.estimatedSize,
                _estimatedFee: feeCalculation.totalFee
            });

            TransactionSecurityUtils.validateBuildTime(startTime, 'build transaction');

            return {
                builder: updatedBuilder,
                psbt: psbtData,
                rawTransaction: rawTransaction,
                fees: feeCalculation,
                metadata: {
                    buildId: this._buildId,
                    network: this.network,
                    version: this._version,
                    locktime: this._locktime,
                    rbfEnabled: this._rbfEnabled,
                    estimatedSize: feeCalculation.estimatedSize,
                    estimatedFee: feeCalculation.totalFee,
                    builtAt: Date.now()
                }
            };

        } catch (error) {
            if (error instanceof TransactionBuilderError || error instanceof ValidationError) {
                throw error;
            }
            throw new TransactionBuilderError(
                `Failed to build transaction: ${error.message}`,
                'BUILD_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Get transaction weight estimation
     * 
     * @returns {Object} Weight estimation details
     */
    estimateWeight() {
        try {
            return this._estimateTransactionWeight();
        } catch (error) {
            throw new TransactionBuilderError(
                `Failed to estimate weight: ${error.message}`,
                'WEIGHT_ESTIMATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Get fee estimation for different priorities
     * 
     * @returns {Object} Fee estimates for different priorities
     */
    estimateFees() {
        try {
            const weight = this._estimateTransactionWeight();
            const vSize = Math.ceil(weight.totalWeight / 4);

            return {
                economy: {
                    feeRate: TRANSACTION_CONSTANTS.ECONOMY_FEE_RATE,
                    totalFee: vSize * TRANSACTION_CONSTANTS.ECONOMY_FEE_RATE,
                    vSize: vSize
                },
                normal: {
                    feeRate: TRANSACTION_CONSTANTS.DEFAULT_FEE_RATE,
                    totalFee: vSize * TRANSACTION_CONSTANTS.DEFAULT_FEE_RATE,
                    vSize: vSize
                },
                high: {
                    feeRate: TRANSACTION_CONSTANTS.HIGH_FEE_RATE,
                    totalFee: vSize * TRANSACTION_CONSTANTS.HIGH_FEE_RATE,
                    vSize: vSize
                }
            };
        } catch (error) {
            throw new TransactionBuilderError(
                `Failed to estimate fees: ${error.message}`,
                'FEE_ESTIMATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Clear sensitive data from the builder
     */
    clearSensitiveData() {
        try {
            if (this._psbtData) {
                TransactionSecurityUtils.secureClear(this._psbtData);
            }

            // Clear any witness data or scripts from inputs
            this._inputs.forEach(input => {
                if (input.witnessScript) {
                    TransactionSecurityUtils.secureClear(input.witnessScript);
                }
                if (input.redeemScript) {
                    TransactionSecurityUtils.secureClear(input.redeemScript);
                }
            });

        } catch (error) {
            // Log but don't throw - clearing sensitive data should be best effort
            console.warn('Failed to clear sensitive data:', error.message);
        }
    }

    /**
     * Validate input structure (PRIVATE - FIXED)
     */
    _validateInputStructure(input) {
        if (!input || typeof input !== 'object') {
            throw new TransactionBuilderError('Input must be an object', 'INVALID_INPUT_STRUCTURE');
        }

        // Required fields
        const requiredFields = ['txid', 'vout', 'value', 'scriptPubKey'];
        for (const field of requiredFields) {
            if (!(field in input)) {
                throw new TransactionBuilderError(
                    `Missing required field: ${field}`,
                    'MISSING_INPUT_FIELD',
                    { field }
                );
            }
        }

        // Validate txid
        if (typeof input.txid !== 'string' || !/^[0-9a-fA-F]{64}$/.test(input.txid)) {
            throw new TransactionBuilderError('Invalid txid format', 'INVALID_TXID');
        }

        // Validate vout
        const voutValidation = validateNumberRange(input.vout, 0, 0xffffffff, 'vout');
        assertValid(voutValidation);

        // Validate value
        const valueValidation = validateNumberRange(input.value, 1, Number.MAX_SAFE_INTEGER, 'input value');
        assertValid(valueValidation);

        // Validate scriptPubKey
        if (!Buffer.isBuffer(input.scriptPubKey)) {
            throw new TransactionBuilderError('scriptPubKey must be a Buffer', 'INVALID_SCRIPTPUBKEY');
        }

        // Validate sequence if provided
        if ('sequence' in input) {
            const sequenceValidation = validateNumberRange(input.sequence, 0, 0xffffffff, 'sequence');
            assertValid(sequenceValidation);
        }
    }

    /**
     * Prepare and validate input object (PRIVATE - FIXED)
     */
    _prepareInput(input) {
        const preparedInput = {
            txid: input.txid,
            vout: input.vout,
            value: input.value,
            scriptPubKey: Buffer.from(input.scriptPubKey),
            type: input.type || this._detectInputType(input.scriptPubKey),
            sequence: input.sequence || (this._rbfEnabled ? TRANSACTION_CONSTANTS.RBF_SEQUENCE : TRANSACTION_CONSTANTS.FINAL_SEQUENCE)
        };

        // Add optional fields
        if (input.witnessScript) {
            preparedInput.witnessScript = Buffer.from(input.witnessScript);
        }
        if (input.redeemScript) {
            preparedInput.redeemScript = Buffer.from(input.redeemScript);
        }
        if (input.taproot) {
            preparedInput.taproot = { ...input.taproot };
        }

        return Object.freeze(preparedInput);
    }

    /**
     * Prepare and validate output object (PRIVATE - FIXED)
     */
    _prepareOutput(address, value) {
        // Decode address properly
        const decodedAddress = AddressUtils.decodeAddressForScript(address);

        // Create script public key
        const scriptPubKey = AddressUtils.createScriptPubKey(decodedAddress);

        return Object.freeze({
            address: address,
            value: value,
            scriptPubKey: scriptPubKey,
            type: decodedAddress.scriptType,
            decodedAddress: decodedAddress
        });
    }

    /**
     * Detect input type from scriptPubKey (PRIVATE)
     */
    _detectInputType(scriptPubKey) {
        if (scriptPubKey.length === 25 && scriptPubKey[0] === 0x76 && scriptPubKey[1] === 0xa9) {
            return 'p2pkh';
        }
        if (scriptPubKey.length === 23 && scriptPubKey[0] === 0xa9) {
            return 'p2sh';
        }
        if (scriptPubKey.length === 22 && scriptPubKey[0] === 0x00 && scriptPubKey[1] === 0x14) {
            return 'p2wpkh';
        }
        if (scriptPubKey.length === 34 && scriptPubKey[0] === 0x00 && scriptPubKey[1] === 0x20) {
            return 'p2wsh';
        }
        if (scriptPubKey.length === 34 && scriptPubKey[0] === 0x51 && scriptPubKey[1] === 0x20) {
            return 'p2tr';
        }
        return 'unknown';
    }

    /**
     * Validate fee options (PRIVATE)
     */
    _validateFeeOptions(feeOptions) {
        if (feeOptions.feeRate !== undefined) {
            const feeRateValidation = validateNumberRange(
                feeOptions.feeRate,
                TRANSACTION_CONSTANTS.MIN_FEE_RATE,
                1000,
                'fee rate'
            );
            assertValid(feeRateValidation);
        }

        if (feeOptions.absoluteFee !== undefined) {
            const absoluteFeeValidation = validateNumberRange(
                feeOptions.absoluteFee,
                1,
                Number.MAX_SAFE_INTEGER,
                'absolute fee'
            );
            assertValid(absoluteFeeValidation);
        }

        if (feeOptions.priority !== undefined) {
            const validPriorities = ['economy', 'normal', 'high'];
            if (!validPriorities.includes(feeOptions.priority)) {
                throw new TransactionBuilderError(
                    `Invalid priority: ${feeOptions.priority}. Must be one of: ${validPriorities.join(', ')}`,
                    'INVALID_PRIORITY'
                );
            }
        }
    }

    /**
     * Validate transaction structure before building (PRIVATE)
     */
    _validateTransactionStructure() {
        if (this._inputs.length === 0) {
            throw new TransactionBuilderError('Transaction must have at least one input', 'NO_INPUTS');
        }

        if (this._outputs.length === 0) {
            throw new TransactionBuilderError('Transaction must have at least one output', 'NO_OUTPUTS');
        }

        // Validate input/output balances
        const totalInput = this._inputs.reduce((sum, input) => sum + input.value, 0);
        const totalOutput = this._outputs.reduce((sum, output) => sum + output.value, 0);

        if (totalInput <= totalOutput) {
            throw new TransactionBuilderError(
                `Insufficient funds: input ${totalInput} <= output ${totalOutput}`,
                'INSUFFICIENT_FUNDS',
                { totalInput, totalOutput }
            );
        }

        // Check for duplicate inputs
        const inputKeys = new Set();
        for (const input of this._inputs) {
            const key = `${input.txid}:${input.vout}`;
            if (inputKeys.has(key)) {
                throw new TransactionBuilderError(
                    `Duplicate input: ${key}`,
                    'DUPLICATE_INPUT',
                    { txid: input.txid, vout: input.vout }
                );
            }
            inputKeys.add(key);
        }
    }

    /**
     * Calculate fees and validate amounts (PRIVATE - FIXED)
     */
    _calculateFees() {
        const weightEstimation = this._estimateTransactionWeight();
        const vSize = Math.ceil(weightEstimation.totalWeight / 4);

        let feeRate, totalFee;

        if (this._feeOptions.absoluteFee !== undefined) {
            totalFee = this._feeOptions.absoluteFee;
            feeRate = Math.ceil(totalFee / vSize);
        } else {
            // Determine fee rate based on priority
            switch (this._feeOptions.priority) {
                case 'economy':
                    feeRate = TRANSACTION_CONSTANTS.ECONOMY_FEE_RATE;
                    break;
                case 'high':
                    feeRate = TRANSACTION_CONSTANTS.HIGH_FEE_RATE;
                    break;
                default:
                    feeRate = this._feeOptions.feeRate || TRANSACTION_CONSTANTS.DEFAULT_FEE_RATE;
            }
            totalFee = vSize * feeRate;
        }

        // Validate fee reasonableness
        if (feeRate < TRANSACTION_CONSTANTS.MIN_FEE_RATE) {
            throw new TransactionBuilderError(
                `Fee rate too low: ${feeRate} < ${TRANSACTION_CONSTANTS.MIN_FEE_RATE}`,
                'FEE_TOO_LOW'
            );
        }

        const totalInput = this._inputs.reduce((sum, input) => sum + input.value, 0);
        const totalOutput = this._outputs.reduce((sum, output) => sum + output.value, 0);

        if (totalInput < totalOutput + totalFee) {
            throw new TransactionBuilderError(
                `Insufficient funds for fee: need ${totalOutput + totalFee}, have ${totalInput}`,
                'INSUFFICIENT_FUNDS_FOR_FEE',
                { totalInput, totalOutput, totalFee, needed: totalOutput + totalFee }
            );
        }

        return {
            feeRate,
            totalFee,
            estimatedSize: vSize,
            totalWeight: weightEstimation.totalWeight,
            breakdown: weightEstimation.breakdown,
            totalInput,
            totalOutput,
            change: totalInput - totalOutput - totalFee
        };
    }

    /**
     * Estimate transaction weight more accurately (PRIVATE - FIXED)
     */
    _estimateTransactionWeight() {
        let totalWeight = TRANSACTION_CONSTANTS.BASE_TRANSACTION_WEIGHT;
        let witnessFlag = false;
        const breakdown = {
            base: TRANSACTION_CONSTANTS.BASE_TRANSACTION_WEIGHT,
            inputs: 0,
            outputs: 0,
            witness: 0
        };

        // Calculate input weights
        for (const input of this._inputs) {
            const scriptSizes = AddressUtils.getInputScriptSizes(
                input.type,
                input.redeemScript,
                input.witnessScript
            );

            // Base input weight (36 bytes: txid + vout + sequence)
            const baseInputWeight = 36 * 4;

            // Script sig weight
            const scriptSigWeight = (scriptSizes.scriptSigSize + 1) * 4; // +1 for length byte

            breakdown.inputs += baseInputWeight + scriptSigWeight;

            // Witness weight
            if (scriptSizes.witnessSize > 0) {
                witnessFlag = true;
                breakdown.witness += scriptSizes.witnessSize;
            }
        }

        // Calculate output weights
        for (const output of this._outputs) {
            // Output weight: 8 bytes value + script length + script
            const outputWeight = (8 + 1 + output.scriptPubKey.length) * 4;
            breakdown.outputs += outputWeight;
        }

        // Add witness flag overhead if any witness data
        if (witnessFlag) {
            breakdown.witness += 2; // witness flag + marker
        }

        totalWeight = breakdown.base + breakdown.inputs + breakdown.outputs + breakdown.witness;

        // Validate estimated size
        const estimatedBytes = Math.ceil(totalWeight / 4);
        TransactionSecurityUtils.validateTransactionSize(estimatedBytes, 'estimated transaction');

        return {
            totalWeight,
            vSize: Math.ceil(totalWeight / 4),
            breakdown,
            witnessFlag
        };
    }

    /**
     * Create PSBT data structure (PRIVATE - FIXED)
     */
    _createPSBTData(feeCalculation) {
        const psbt = {
            version: this._version,
            locktime: this._locktime,
            inputs: this._inputs.map((input, index) => ({
                previousTxid: Buffer.from(input.txid, 'hex').reverse(), // Little endian
                previousVout: input.vout,
                sequence: input.sequence,
                witnessUtxo: {
                    value: input.value,
                    scriptPubKey: input.scriptPubKey
                },
                // Add additional PSBT fields based on input type
                ...this._createPSBTInputFields(input, index)
            })),
            outputs: this._outputs.map((output, index) => ({
                value: output.value,
                scriptPubKey: output.scriptPubKey,
                // Add derivation paths if needed
                ...this._createPSBTOutputFields(output, index)
            })),
            fee: feeCalculation.totalFee,
            metadata: {
                buildId: this._buildId,
                network: this.network,
                rbfEnabled: this._rbfEnabled,
                createdAt: Date.now()
            }
        };

        return Object.freeze(psbt);
    }

    /**
     * Create PSBT input fields based on input type (PRIVATE)
     */
    _createPSBTInputFields(input, index) {
        const fields = {};

        switch (input.type) {
            case 'p2sh':
                if (input.redeemScript) {
                    fields.redeemScript = input.redeemScript;
                }
                break;

            case 'p2wsh':
                if (input.witnessScript) {
                    fields.witnessScript = input.witnessScript;
                }
                break;

            case 'p2tr':
                if (input.taproot) {
                    fields.tapInternalKey = input.taproot.internalKey;
                    if (input.taproot.merkleRoot) {
                        fields.tapMerkleRoot = input.taproot.merkleRoot;
                    }
                    if (input.taproot.leafScripts) {
                        fields.tapLeafScript = input.taproot.leafScripts;
                    }
                }
                break;
        }

        return fields;
    }

    /**
     * Create PSBT output fields (PRIVATE)
     */
    _createPSBTOutputFields(output, index) {
        const fields = {};

        // Add derivation paths for change outputs if available
        // This would typically be provided by wallet software

        return fields;
    }

    /**
     * Build raw transaction structure (PRIVATE - FIXED)
     */
    _buildRawTransaction(feeCalculation) {
        return Object.freeze({
            version: this._version,
            locktime: this._locktime,
            inputs: this._inputs.map(input => ({
                txid: input.txid,
                vout: input.vout,
                scriptSig: Buffer.alloc(0), // Empty for PSBT
                sequence: input.sequence,
                witness: [] // Empty for PSBT
            })),
            outputs: this._outputs.map(output => ({
                value: output.value,
                scriptPubKey: output.scriptPubKey
            })),
            fees: {
                total: feeCalculation.totalFee,
                rate: feeCalculation.feeRate,
                vSize: feeCalculation.estimatedSize
            },
            weight: feeCalculation.totalWeight,
            size: Math.ceil(feeCalculation.totalWeight / 4)
        });
    }

    /**
     * Get built transaction data (PRIVATE)
     */
    _getBuiltTransaction() {
        if (!this._built || !this._psbtData) {
            throw new TransactionBuilderError('Transaction not built', 'NOT_BUILT');
        }

        return {
            builder: this,
            psbt: this._psbtData,
            metadata: {
                buildId: this._buildId,
                network: this.network,
                version: this._version,
                locktime: this._locktime,
                rbfEnabled: this._rbfEnabled,
                estimatedSize: this._estimatedSize,
                estimatedFee: this._estimatedFee,
                builtAt: this._psbtData.metadata.createdAt
            }
        };
    }

    /**
     * Get builder summary information
     */
    getSummary() {
        const totalInput = this._inputs.reduce((sum, input) => sum + input.value, 0);
        const totalOutput = this._outputs.reduce((sum, output) => sum + output.value, 0);

        return {
            buildId: this._buildId,
            network: this.network,
            version: this._version,
            locktime: this._locktime,
            rbfEnabled: this._rbfEnabled,
            inputCount: this._inputs.length,
            outputCount: this._outputs.length,
            totalInput,
            totalOutput,
            estimatedFee: this._estimatedFee,
            built: this._built,
            signed: this._signed,
            createdAt: this._createdAt
        };
    }

    /**
     * Get detailed input information
     */
    getInputs() {
        return this._inputs.map((input, index) => ({
            index,
            txid: input.txid,
            vout: input.vout,
            value: input.value,
            type: input.type,
            sequence: input.sequence,
            hasWitnessScript: !!input.witnessScript,
            hasRedeemScript: !!input.redeemScript,
            hasTaprootData: !!input.taproot
        }));
    }

    /**
     * Get detailed output information
     */
    getOutputs() {
        return this._outputs.map((output, index) => ({
            index,
            address: output.address,
            value: output.value,
            type: output.type,
            scriptSize: output.scriptPubKey.length
        }));
    }

    /**
     * Static factory method to create a new builder
     */
    static create(network = 'main', options = {}) {
        return new TransactionBuilder(network, options);
    }

    /**
     * Static method to validate a completed transaction
     */
    static validateTransaction(transaction) {
        try {
            // Basic structure validation
            if (!transaction || typeof transaction !== 'object') {
                return { isValid: false, error: 'Invalid transaction structure' };
            }

            // Validate required fields
            const requiredFields = ['version', 'inputs', 'outputs'];
            for (const field of requiredFields) {
                if (!(field in transaction)) {
                    return { isValid: false, error: `Missing required field: ${field}` };
                }
            }

            // Validate inputs and outputs
            if (!Array.isArray(transaction.inputs) || transaction.inputs.length === 0) {
                return { isValid: false, error: 'Transaction must have at least one input' };
            }

            if (!Array.isArray(transaction.outputs) || transaction.outputs.length === 0) {
                return { isValid: false, error: 'Transaction must have at least one output' };
            }

            // Additional validations would go here...

            return { isValid: true };

        } catch (error) {
            return {
                isValid: false,
                error: `Validation failed: ${error.message}`
            };
        }
    }
}

// Export the enhanced transaction builder
export {
    TransactionBuilder,
    TransactionBuilderError,
    TransactionSecurityUtils,
    AddressUtils,
    TRANSACTION_CONSTANTS
};

export default TransactionBuilder;