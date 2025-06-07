/**
 * @fileoverview Enhanced PSBT-first transaction builder with Taproot support
 * 
 * This module implements a modern, immutable transaction builder that follows
 * PSBT-first architecture with comprehensive support for both legacy and Taproot
 * inputs/outputs. Integrates with existing security utilities and wallet classes.
 * 
 * FEATURES:
 * - Immutable builder pattern for thread safety
 * - Comprehensive Taproot and legacy support
 * - Advanced fee estimation and RBF
 * - Integration with existing validation framework
 * - PSBT-first architecture with signing coordination
 * 
 * @author yfbsei
 * @version 2.1.0
 */

import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
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
import { AddressSecurityUtils } from '../utils/address-helpers.js';
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
    LEGACY_INPUT_WEIGHT: 148 * 4,      // Legacy P2PKH input
    SEGWIT_INPUT_WEIGHT: 68 * 4,       // P2WPKH input
    TAPROOT_INPUT_WEIGHT: 57.5 * 4,    // P2TR input (avg)
    OUTPUT_WEIGHT: 34 * 4,             // Standard output weight
    BASE_WEIGHT: 10 * 4,               // Base transaction weight

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
 * Modern PSBT-first transaction builder with immutable pattern
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

        this.network = network;
        this.networkConfig = networkConfig;

        // Immutable state
        this._inputs = [];
        this._outputs = [];
        this._version = options.version || TRANSACTION_CONSTANTS.DEFAULT_VERSION;
        this._locktime = options.locktime || TRANSACTION_CONSTANTS.DEFAULT_LOCKTIME;
        this._rbfEnabled = options.rbf !== false; // Default true
        this._feeOptions = {
            feeRate: options.feeRate || TRANSACTION_CONSTANTS.DEFAULT_FEE_RATE,
            priority: options.priority || 'normal',
            rbf: this._rbfEnabled
        };

        // Builder state
        this._built = false;
        this._signed = false;
        this._psbtData = null;
        this._estimatedSize = 0;
        this._estimatedFee = 0;

        // Security tracking
        this._createdAt = Date.now();
        this._buildId = this._generateBuildId();
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
     * Create a new builder instance with updated inputs (immutable pattern)
     */
    _clone(updates = {}) {
        const newBuilder = new TransactionBuilder(this.network, {
            version: this._version,
            locktime: this._locktime,
            rbf: this._rbfEnabled,
            feeRate: this._feeOptions.feeRate,
            priority: this._feeOptions.priority
        });

        // Copy current state
        newBuilder._inputs = [...this._inputs];
        newBuilder._outputs = [...this._outputs];
        newBuilder._feeOptions = { ...this._feeOptions };

        // Apply updates
        Object.assign(newBuilder, updates);

        return newBuilder;
    }

    /**
     * Add a UTXO input to the transaction
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
                _inputs: newInputs,
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
     * Add an output to the transaction
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

            // Create output object
            const output = this._prepareOutput(address, value, addressValidation.data);

            // Check limits
            const newOutputs = [...this._outputs, output];
            TransactionSecurityUtils.validateIOLimits(this._inputs, newOutputs);
            TransactionSecurityUtils.validateDustLimits(newOutputs);

            TransactionSecurityUtils.validateBuildTime(startTime, 'add output');

            return this._clone({
                _outputs: newOutputs,
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

            const newFeeOptions = { ...this._feeOptions, ...feeOptions };

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
            const newFeeOptions = { ...this._feeOptions, rbf: enabled };

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
            this._built = true;
            this._psbtData = psbtData;
            this._estimatedSize = feeCalculation.estimatedSize;
            this._estimatedFee = feeCalculation.totalFee;

            TransactionSecurityUtils.validateBuildTime(startTime, 'transaction build');

            return {
                buildId: this._buildId,
                rawTransaction,
                psbt: psbtData,
                fees: feeCalculation,
                metadata: this._getTransactionMetadata(),
                canSign: true,
                canBroadcast: false
            };

        } catch (error) {
            if (error instanceof TransactionBuilderError || error instanceof ValidationError) {
                throw error;
            }
            throw new TransactionBuilderError(
                `Transaction build failed: ${error.message}`,
                'BUILD_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Get transaction summary and statistics
     * 
     * @returns {Object} Comprehensive transaction summary
     */
    getSummary() {
        try {
            const inputTotal = this._inputs.reduce((sum, input) => sum + input.value, 0);
            const outputTotal = this._outputs.reduce((sum, output) => sum + output.value, 0);
            const estimatedWeight = this._estimateTransactionWeight();

            return {
                buildId: this._buildId,
                inputs: {
                    count: this._inputs.length,
                    totalValue: inputTotal,
                    types: this._getInputTypes()
                },
                outputs: {
                    count: this._outputs.length,
                    totalValue: outputTotal,
                    types: this._getOutputTypes()
                },
                fees: {
                    estimatedFee: this._estimatedFee,
                    feeRate: this._feeOptions.feeRate,
                    priority: this._feeOptions.priority
                },
                transaction: {
                    version: this._version,
                    locktime: this._locktime,
                    rbfEnabled: this._rbfEnabled,
                    estimatedWeight: estimatedWeight,
                    estimatedSize: Math.ceil(estimatedWeight / 4)
                },
                status: {
                    built: this._built,
                    signed: this._signed,
                    canBroadcast: this._signed
                },
                network: this.network,
                createdAt: this._createdAt
            };

        } catch (error) {
            throw new TransactionBuilderError(
                `Failed to generate summary: ${error.message}`,
                'SUMMARY_FAILED',
                { originalError: error.message }
            );
        }
    }

    // Private helper methods

    /**
     * Validate input structure and format
     */
    _validateInputStructure(input) {
        if (!input || typeof input !== 'object') {
            throw new TransactionBuilderError(
                'Input must be a valid object',
                'INVALID_INPUT_STRUCTURE'
            );
        }

        // Required fields
        const requiredFields = ['txid', 'vout', 'value', 'scriptPubKey'];
        for (const field of requiredFields) {
            if (!(field in input)) {
                throw new TransactionBuilderError(
                    `Input missing required field: ${field}`,
                    'MISSING_INPUT_FIELD',
                    { missingField: field }
                );
            }
        }

        // Validate txid format
        if (typeof input.txid !== 'string' || !/^[0-9a-fA-F]{64}$/.test(input.txid)) {
            throw new TransactionBuilderError(
                'Invalid txid format',
                'INVALID_TXID_FORMAT'
            );
        }

        // Validate vout
        const voutValidation = validateNumberRange(input.vout, 0, 0xffffffff, 'vout');
        assertValid(voutValidation);

        // Validate value
        const valueValidation = validateNumberRange(input.value, 1, Number.MAX_SAFE_INTEGER, 'input value');
        assertValid(valueValidation);

        // Validate scriptPubKey
        if (!Buffer.isBuffer(input.scriptPubKey)) {
            throw new TransactionBuilderError(
                'scriptPubKey must be a Buffer',
                'INVALID_SCRIPT_PUBKEY_TYPE'
            );
        }
    }

    /**
     * Prepare and validate input object
     */
    _prepareInput(input) {
        const sequence = input.sequence !== undefined
            ? input.sequence
            : (this._rbfEnabled ? TRANSACTION_CONSTANTS.RBF_SEQUENCE : TRANSACTION_CONSTANTS.FINAL_SEQUENCE);

        const sequenceValidation = validateNumberRange(sequence, 0, TRANSACTION_CONSTANTS.MAX_SEQUENCE, 'sequence');
        assertValid(sequenceValidation);

        return {
            txid: input.txid,
            vout: input.vout,
            value: input.value,
            scriptPubKey: Buffer.from(input.scriptPubKey),
            type: input.type || this._detectInputType(input.scriptPubKey),
            sequence: sequence,
            witnessScript: input.witnessScript ? Buffer.from(input.witnessScript) : undefined,
            redeemScript: input.redeemScript ? Buffer.from(input.redeemScript) : undefined,
            taproot: input.taproot ? { ...input.taproot } : undefined,
            keyPath: input.keyPath,
            derivationPath: input.derivationPath
        };
    }

    /**
     * Prepare and validate output object
     */
    _prepareOutput(address, value, addressData) {
        const scriptPubKey = this._createScriptPubKey(address, addressData);

        return {
            address: address,
            value: value,
            scriptPubKey: scriptPubKey,
            type: addressData.type || addressData.format,
            network: addressData.network || this.network
        };
    }

    /**
     * Create scriptPubKey for an address
     */
    _createScriptPubKey(address, addressData) {
        // This would integrate with your existing address decoding utilities
        // For now, return a placeholder that matches your existing patterns

        switch (addressData.type || addressData.format) {
            case 'legacy':
                if (address.startsWith('1') || address.startsWith('m') || address.startsWith('n')) {
                    // P2PKH: OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
                    const hash160 = Buffer.alloc(20); // Would decode from address
                    return Buffer.concat([
                        Buffer.from([0x76, 0xa9, 0x14]), // OP_DUP OP_HASH160 PUSH(20)
                        hash160,
                        Buffer.from([0x88, 0xac]) // OP_EQUALVERIFY OP_CHECKSIG
                    ]);
                } else {
                    // P2SH: OP_HASH160 <hash160> OP_EQUAL
                    const hash160 = Buffer.alloc(20); // Would decode from address
                    return Buffer.concat([
                        Buffer.from([0xa9, 0x14]), // OP_HASH160 PUSH(20)
                        hash160,
                        Buffer.from([0x87]) // OP_EQUAL
                    ]);
                }

            case 'segwit':
                // P2WPKH: OP_0 <hash160>
                const hash160 = Buffer.alloc(20); // Would decode from address
                return Buffer.concat([
                    Buffer.from([0x00, 0x14]), // OP_0 PUSH(20)
                    hash160
                ]);

            case 'taproot':
                // P2TR: OP_1 <pubkey>
                const pubkey = Buffer.alloc(32); // Would decode from address
                return Buffer.concat([
                    Buffer.from([0x51, 0x20]), // OP_1 PUSH(32)
                    pubkey
                ]);

            default:
                throw new TransactionBuilderError(
                    `Unsupported address type: ${addressData.type}`,
                    'UNSUPPORTED_ADDRESS_TYPE'
                );
        }
    }

    /**
     * Detect input type from scriptPubKey
     */
    _detectInputType(scriptPubKey) {
        if (scriptPubKey.length === 25 && scriptPubKey[0] === 0x76) {
            return 'p2pkh';
        }
        if (scriptPubKey.length === 23 && scriptPubKey[0] === 0xa9) {
            return 'p2sh';
        }
        if (scriptPubKey.length === 22 && scriptPubKey[0] === 0x00) {
            return 'p2wpkh';
        }
        if (scriptPubKey.length === 34 && scriptPubKey[0] === 0x00) {
            return 'p2wsh';
        }
        if (scriptPubKey.length === 34 && scriptPubKey[0] === 0x51) {
            return 'p2tr';
        }
        return 'unknown';
    }

    /**
     * Validate fee options
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
                0,
                Number.MAX_SAFE_INTEGER,
                'absolute fee'
            );
            assertValid(absoluteFeeValidation);
        }

        if (feeOptions.priority !== undefined) {
            const validPriorities = ['economy', 'normal', 'high'];
            if (!validPriorities.includes(feeOptions.priority)) {
                throw new TransactionBuilderError(
                    `Invalid priority: ${feeOptions.priority}`,
                    'INVALID_FEE_PRIORITY',
                    { validPriorities }
                );
            }
        }
    }

    /**
     * Validate complete transaction structure before building
     */
    _validateTransactionStructure() {
        if (this._inputs.length === 0) {
            throw new TransactionBuilderError(
                'Transaction must have at least one input',
                'NO_INPUTS'
            );
        }

        if (this._outputs.length === 0) {
            throw new TransactionBuilderError(
                'Transaction must have at least one output',
                'NO_OUTPUTS'
            );
        }

        // Check that we have enough inputs to cover outputs
        const inputTotal = this._inputs.reduce((sum, input) => sum + input.value, 0);
        const outputTotal = this._outputs.reduce((sum, output) => sum + output.value, 0);

        if (inputTotal <= outputTotal) {
            throw new TransactionBuilderError(
                'Insufficient input value to cover outputs and fees',
                'INSUFFICIENT_FUNDS',
                { inputTotal, outputTotal, deficit: outputTotal - inputTotal }
            );
        }
    }

    /**
     * Calculate transaction fees and sizes
     */
    _calculateFees() {
        const estimatedWeight = this._estimateTransactionWeight();
        const estimatedSize = Math.ceil(estimatedWeight / 4);

        let feeRate = this._feeOptions.feeRate;

        // Apply priority multipliers
        if (this._feeOptions.priority === 'economy') {
            feeRate = Math.max(feeRate * 0.5, TRANSACTION_CONSTANTS.MIN_FEE_RATE);
        } else if (this._feeOptions.priority === 'high') {
            feeRate = feeRate * 2;
        }

        const totalFee = this._feeOptions.absoluteFee || Math.ceil(estimatedSize * feeRate);
        const inputTotal = this._inputs.reduce((sum, input) => sum + input.value, 0);
        const outputTotal = this._outputs.reduce((sum, output) => sum + output.value, 0);

        // Validate fee is reasonable
        if (totalFee > inputTotal * 0.5) {
            console.warn(`⚠️  High fee detected: ${totalFee} sats (${((totalFee / inputTotal) * 100).toFixed(2)}% of input)`);
        }

        return {
            estimatedWeight,
            estimatedSize,
            feeRate,
            totalFee,
            inputTotal,
            outputTotal,
            change: inputTotal - outputTotal - totalFee
        };
    }

    /**
     * Estimate transaction weight in weight units
     */
    _estimateTransactionWeight() {
        let totalWeight = TRANSACTION_CONSTANTS.BASE_WEIGHT;

        // Input weights
        for (const input of this._inputs) {
            switch (input.type) {
                case 'p2pkh':
                    totalWeight += TRANSACTION_CONSTANTS.LEGACY_INPUT_WEIGHT;
                    break;
                case 'p2wpkh':
                    totalWeight += TRANSACTION_CONSTANTS.SEGWIT_INPUT_WEIGHT;
                    break;
                case 'p2tr':
                    totalWeight += TRANSACTION_CONSTANTS.TAPROOT_INPUT_WEIGHT;
                    break;
                case 'p2sh':
                    totalWeight += TRANSACTION_CONSTANTS.LEGACY_INPUT_WEIGHT + 100; // Estimate for redeem script
                    break;
                case 'p2wsh':
                    totalWeight += TRANSACTION_CONSTANTS.SEGWIT_INPUT_WEIGHT + 200; // Estimate for witness script
                    break;
                default:
                    totalWeight += TRANSACTION_CONSTANTS.LEGACY_INPUT_WEIGHT; // Conservative estimate
            }
        }

        // Output weights
        totalWeight += this._outputs.length * TRANSACTION_CONSTANTS.OUTPUT_WEIGHT;

        return totalWeight;
    }

    /**
     * Create PSBT data structure
     */
    _createPSBTData(feeCalculation) {
        const psbtData = {
            version: 0, // PSBT version
            global: {
                unsignedTx: this._createUnsignedTransaction(feeCalculation),
                xpubs: [],
                version: this._version,
                locktime: this._locktime,
                inputCount: this._inputs.length,
                outputCount: this._outputs.length,
                fallbackLocktime: this._locktime,
                proprietary: []
            },
            inputs: [],
            outputs: []
        };

        // Prepare input data for PSBT
        for (let i = 0; i < this._inputs.length; i++) {
            const input = this._inputs[i];
            const psbtInput = {
                // Universal fields
                nonWitnessUtxo: undefined, // For legacy inputs
                witnessUtxo: {
                    amount: input.value,
                    scriptPubKey: input.scriptPubKey
                },
                partialSigs: {},
                sighashType: 0x01, // SIGHASH_ALL

                // Legacy/P2SH fields
                redeemScript: input.redeemScript,

                // SegWit fields
                witnessScript: input.witnessScript,

                // HD derivation info
                bip32Derivation: input.keyPath ? [{
                    pubkey: Buffer.alloc(33), // Would be derived from keyPath
                    masterFingerprint: Buffer.alloc(4),
                    path: input.derivationPath || `m/44'/0'/0'/0/${i}`
                }] : [],

                // Taproot fields (BIP371)
                tapInternalKey: input.taproot?.internalKey,
                tapMerkleRoot: input.taproot?.merkleRoot,
                tapLeafScript: input.taproot?.leafScript ? [{
                    script: input.taproot.leafScript,
                    leafVersion: input.taproot.leafVersion || 0xc0,
                    controlBlock: input.taproot.controlBlock
                }] : [],
                tapBip32Derivation: input.taproot?.keyPath ? [{
                    pubkey: input.taproot.internalKey,
                    leafHashes: input.taproot.leafHashes || [],
                    masterFingerprint: Buffer.alloc(4),
                    path: input.derivationPath || `m/86'/0'/0'/0/${i}`
                }] : [],

                // Proprietary fields
                proprietary: []
            };

            psbtData.inputs.push(psbtInput);
        }

        // Prepare output data for PSBT
        for (let i = 0; i < this._outputs.length; i++) {
            const output = this._outputs[i];
            const psbtOutput = {
                // HD derivation info (for change outputs)
                bip32Derivation: [],

                // Taproot fields
                tapInternalKey: undefined,
                tapTree: undefined,
                tapBip32Derivation: [],

                // Proprietary fields
                proprietary: []
            };

            psbtData.outputs.push(psbtOutput);
        }

        return psbtData;
    }

    /**
     * Create unsigned transaction structure
     */
    _createUnsignedTransaction(feeCalculation) {
        return {
            version: this._version,
            locktime: this._locktime,
            inputs: this._inputs.map(input => ({
                hash: Buffer.from(input.txid, 'hex').reverse(), // Little-endian
                index: input.vout,
                script: Buffer.alloc(0), // Empty for unsigned
                sequence: input.sequence
            })),
            outputs: this._outputs.map(output => ({
                amount: output.value,
                script: output.scriptPubKey
            }))
        };
    }

    /**
     * Build raw transaction bytes
     */
    _buildRawTransaction(feeCalculation) {
        // This would implement the actual transaction serialization
        // For now, return a structure that represents the transaction
        return {
            version: this._version,
            inputs: this._inputs.map(input => ({
                previousOutputHash: input.txid,
                previousOutputIndex: input.vout,
                scriptSignature: Buffer.alloc(0), // Empty for unsigned
                sequence: input.sequence
            })),
            outputs: this._outputs.map(output => ({
                value: output.value,
                scriptPubKey: output.scriptPubKey
            })),
            locktime: this._locktime,
            size: feeCalculation.estimatedSize,
            weight: feeCalculation.estimatedWeight
        };
    }

    /**
     * Get transaction metadata for tracking
     */
    _getTransactionMetadata() {
        return {
            buildId: this._buildId,
            network: this.network,
            version: this._version,
            locktime: this._locktime,
            rbfEnabled: this._rbfEnabled,
            createdAt: this._createdAt,
            builtAt: Date.now(),
            inputTypes: this._getInputTypes(),
            outputTypes: this._getOutputTypes(),
            hasSegWit: this._hasSegWitInputs(),
            hasTaproot: this._hasTaprootInputs()
        };
    }

    /**
     * Get input type distribution
     */
    _getInputTypes() {
        const types = {};
        for (const input of this._inputs) {
            types[input.type] = (types[input.type] || 0) + 1;
        }
        return types;
    }

    /**
     * Get output type distribution
     */
    _getOutputTypes() {
        const types = {};
        for (const output of this._outputs) {
            types[output.type] = (types[output.type] || 0) + 1;
        }
        return types;
    }

    /**
     * Check if transaction has SegWit inputs
     */
    _hasSegWitInputs() {
        return this._inputs.some(input =>
            input.type === 'p2wpkh' || input.type === 'p2wsh' || input.type === 'p2tr'
        );
    }

    /**
     * Check if transaction has Taproot inputs
     */
    _hasTaprootInputs() {
        return this._inputs.some(input => input.type === 'p2tr');
    }

    /**
     * Get built transaction (if already built)
     */
    _getBuiltTransaction() {
        if (!this._built) {
            throw new TransactionBuilderError(
                'Transaction not yet built',
                'TRANSACTION_NOT_BUILT'
            );
        }

        return {
            buildId: this._buildId,
            rawTransaction: this._rawTransaction,
            psbt: this._psbtData,
            fees: {
                estimatedFee: this._estimatedFee,
                estimatedSize: this._estimatedSize,
                feeRate: this._feeOptions.feeRate
            },
            metadata: this._getTransactionMetadata(),
            canSign: true,
            canBroadcast: this._signed
        };
    }

    /**
     * Clone this builder for RBF (Replace-by-Fee) transactions
     * 
     * @param {Object} rbfOptions - RBF configuration
     * @returns {TransactionBuilder} New builder for RBF transaction
     */
    cloneForRBF(rbfOptions = {}) {
        try {
            if (!this._rbfEnabled) {
                throw new TransactionBuilderError(
                    'Original transaction does not have RBF enabled',
                    'RBF_NOT_ENABLED'
                );
            }

            const newFeeRate = rbfOptions.feeRate || (this._feeOptions.feeRate * 1.25); // 25% increase
            const newBuilder = this._clone({
                _feeOptions: {
                    ...this._feeOptions,
                    feeRate: newFeeRate
                },
                _built: false,
                _signed: false
            });

            return newBuilder;

        } catch (error) {
            if (error instanceof TransactionBuilderError) {
                throw error;
            }
            throw new TransactionBuilderError(
                `RBF clone failed: ${error.message}`,
                'RBF_CLONE_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Export builder state for persistence
     * 
     * @returns {Object} Serializable builder state
     */
    export() {
        return {
            buildId: this._buildId,
            network: this.network,
            version: this._version,
            locktime: this._locktime,
            rbfEnabled: this._rbfEnabled,
            feeOptions: this._feeOptions,
            inputs: this._inputs.map(input => ({
                ...input,
                scriptPubKey: input.scriptPubKey.toString('hex'),
                witnessScript: input.witnessScript?.toString('hex'),
                redeemScript: input.redeemScript?.toString('hex')
            })),
            outputs: this._outputs.map(output => ({
                ...output,
                scriptPubKey: output.scriptPubKey.toString('hex')
            })),
            createdAt: this._createdAt,
            built: this._built,
            signed: this._signed
        };
    }

    /**
     * Import builder state from serialized data
     * 
     * @param {Object} state - Serialized builder state
     * @returns {TransactionBuilder} Restored builder instance
     */
    static import(state) {
        const builder = new TransactionBuilder(state.network, {
            version: state.version,
            locktime: state.locktime,
            rbf: state.rbfEnabled,
            ...state.feeOptions
        });

        // Restore inputs
        builder._inputs = state.inputs.map(input => ({
            ...input,
            scriptPubKey: Buffer.from(input.scriptPubKey, 'hex'),
            witnessScript: input.witnessScript ? Buffer.from(input.witnessScript, 'hex') : undefined,
            redeemScript: input.redeemScript ? Buffer.from(input.redeemScript, 'hex') : undefined
        }));

        // Restore outputs
        builder._outputs = state.outputs.map(output => ({
            ...output,
            scriptPubKey: Buffer.from(output.scriptPubKey, 'hex')
        }));

        // Restore metadata
        builder._buildId = state.buildId;
        builder._createdAt = state.createdAt;
        builder._built = state.built;
        builder._signed = state.signed;

        return builder;
    }

    /**
     * Get builder status and capabilities
     */
    getStatus() {
        return {
            version: '2.1.0',
            features: [
                'PSBT-first architecture',
                'Immutable builder pattern',
                'Taproot and legacy support',
                'Advanced fee estimation',
                'RBF (Replace-by-Fee) support',
                'Comprehensive validation',
                'Security-focused design'
            ],
            network: this.network,
            buildId: this._buildId,
            status: {
                hasInputs: this._inputs.length > 0,
                hasOutputs: this._outputs.length > 0,
                built: this._built,
                signed: this._signed,
                canBuild: this._inputs.length > 0 && this._outputs.length > 0,
                canSign: this._built,
                canBroadcast: this._signed
            },
            limits: TRANSACTION_CONSTANTS
        };
    }

    /**
     * Cleanup sensitive data
     */
    destroy() {
        try {
            console.warn('⚠️  Destroying transaction builder - clearing sensitive data');

            // Clear input data
            this._inputs.forEach(input => {
                TransactionSecurityUtils.secureClear(input);
            });

            // Clear output data
            this._outputs.forEach(output => {
                TransactionSecurityUtils.secureClear(output);
            });

            // Clear PSBT data
            if (this._psbtData) {
                TransactionSecurityUtils.secureClear(this._psbtData);
            }

            // Reset arrays
            this._inputs = [];
            this._outputs = [];
            this._psbtData = null;

            console.log('✅ Transaction builder destroyed securely');

        } catch (error) {
            console.error('❌ Transaction builder destruction failed:', error.message);
        }
    }
}

export {
    TransactionBuilderError,
    TransactionSecurityUtils,
    TransactionBuilder,
    TRANSACTION_CONSTANTS
};