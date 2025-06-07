/**
 * @fileoverview Intelligent UTXO management with advanced selection strategies
 * 
 * This module implements comprehensive UTXO selection algorithms optimized for
 * privacy, efficiency, and fee minimization. Includes integration with mempool
 * APIs for dynamic fee estimation and RBF (Replace-by-Fee) support.
 * 
 * FEATURES:
 * - Multiple selection strategies (exactBiggest, accumSmallest, etc.)
 * - Dynamic fee estimation with mempool integration
 * - RBF transaction creation and management
 * - Privacy-preserving UTXO management
 * - Integration with transaction builder
 * 
 * @author yfbsei
 * @version 2.1.0
 */

import { createHash, randomBytes } from 'node:crypto';
import {
    validateNumberRange,
    validateAddress,
    assertValid,
    ValidationError
} from '../utils/validation.js';
import { AddressSecurityUtils } from '../utils/address-helpers.js';
import { TRANSACTION_CONSTANTS } from './builder.js';

/**
 * UTXO manager specific error class
 */
class UTXOManagerError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'UTXOManagerError';
        this.code = code;
        this.details = details;
        this.timestamp = Date.now();
    }
}

/**
 * UTXO management constants and configuration
 */
const UTXO_CONSTANTS = {
    // Selection strategy parameters
    MAX_UTXOS_PER_TRANSACTION: 100,    // Reasonable limit for performance
    MIN_UTXO_VALUE: 546,               // Dust limit
    MAX_SELECTION_ATTEMPTS: 1000,      // Prevent infinite loops
    CONSOLIDATION_THRESHOLD: 100,      // UTXOs to trigger consolidation warning

    // Privacy parameters
    PRIVACY_SCORE_THRESHOLD: 0.7,      // Minimum privacy score
    MAX_ADDRESS_REUSE: 3,              // Maximum times to reuse an address
    ANONYMITY_SET_SIZE: 10,            // Minimum anonymity set for privacy

    // Fee estimation parameters
    DEFAULT_MEMPOOL_API: 'https://mempool.space/api/v1/fees',
    FEE_ESTIMATION_TIMEOUT: 5000,      // 5 second timeout for API calls
    FEE_CACHE_DURATION: 60000,         // 1 minute cache duration
    MIN_FEE_RATE: 1,                   // 1 sat/vbyte minimum
    MAX_FEE_RATE: 1000,                // 1000 sat/vbyte maximum

    // RBF parameters
    MIN_RBF_FEE_INCREASE: 1.25,        // 25% minimum fee increase for RBF
    MAX_RBF_ATTEMPTS: 10,              // Maximum RBF attempts per transaction

    // Performance limits
    MAX_VALIDATIONS_PER_SECOND: 200,   // Rate limiting
    MAX_SELECTION_TIME_MS: 10000,      // 10 second selection timeout
    CACHE_SIZE_LIMIT: 1000             // Maximum cached items
};

/**
 * @typedef {Object} UTXO
 * @property {string} txid - Transaction ID
 * @property {number} vout - Output index
 * @property {number} value - Value in satoshis
 * @property {Buffer} scriptPubKey - Script public key
 * @property {string} address - Address that controls this UTXO
 * @property {string} type - Address type ('p2pkh', 'p2wpkh', 'p2tr', etc.)
 * @property {number} confirmations - Number of confirmations
 * @property {boolean} isSpendable - Whether UTXO is currently spendable
 * @property {string} [derivationPath] - HD wallet derivation path
 * @property {Object} [metadata] - Additional UTXO metadata
 */

/**
 * @typedef {Object} SelectionStrategy
 * @property {string} name - Strategy name
 * @property {Function} algorithm - Selection algorithm function
 * @property {Object} config - Strategy-specific configuration
 * @property {number} privacyScore - Privacy score (0-1)
 * @property {number} efficiencyScore - Efficiency score (0-1)
 */

/**
 * @typedef {Object} SelectionResult
 * @property {UTXO[]} selectedUtxos - Selected UTXOs for the transaction
 * @property {number} totalValue - Total value of selected UTXOs
 * @property {number} changeValue - Change amount to be returned
 * @property {number} estimatedFee - Estimated transaction fee
 * @property {string} strategy - Strategy used for selection
 * @property {Object} metrics - Selection performance metrics
 * @property {number} privacyScore - Overall privacy score of selection
 */

/**
 * @typedef {Object} FeeEstimation
 * @property {number} economyFee - Economy fee rate (sat/vbyte)
 * @property {number} normalFee - Normal fee rate (sat/vbyte)
 * @property {number} priorityFee - Priority fee rate (sat/vbyte)
 * @property {number} timestamp - Estimation timestamp
 * @property {string} source - Fee estimation source
 */

/**
 * Enhanced security utilities for UTXO operations
 */
class UTXOSecurityUtils {
    static validationHistory = new Map();
    static lastCleanup = Date.now();

    /**
     * Rate limiting for UTXO operations
     */
    static checkRateLimit(operation = 'utxo-operation') {
        const now = Date.now();
        const secondKey = `${operation}-${Math.floor(now / 1000)}`;
        const currentCount = this.validationHistory.get(secondKey) || 0;

        if (currentCount >= UTXO_CONSTANTS.MAX_VALIDATIONS_PER_SECOND) {
            throw new UTXOManagerError(
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
     * Validates selection time to prevent DoS attacks
     */
    static validateSelectionTime(startTime, operation = 'UTXO selection') {
        const elapsed = Date.now() - startTime;
        if (elapsed > UTXO_CONSTANTS.MAX_SELECTION_TIME_MS) {
            throw new UTXOManagerError(
                `${operation} timeout: ${elapsed}ms > ${UTXO_CONSTANTS.MAX_SELECTION_TIME_MS}ms`,
                'SELECTION_TIMEOUT',
                { elapsed, maxTime: UTXO_CONSTANTS.MAX_SELECTION_TIME_MS }
            );
        }
    }

    /**
     * Validates UTXO structure and content
     */
    static validateUTXO(utxo, fieldName = 'UTXO') {
        if (!utxo || typeof utxo !== 'object') {
            throw new UTXOManagerError(
                `${fieldName} must be a valid object`,
                'INVALID_UTXO_STRUCTURE'
            );
        }

        const requiredFields = ['txid', 'vout', 'value', 'scriptPubKey', 'address'];
        for (const field of requiredFields) {
            if (!(field in utxo)) {
                throw new UTXOManagerError(
                    `${fieldName} missing required field: ${field}`,
                    'MISSING_UTXO_FIELD',
                    { missingField: field }
                );
            }
        }

        // Validate txid format
        if (typeof utxo.txid !== 'string' || !/^[0-9a-fA-F]{64}$/.test(utxo.txid)) {
            throw new UTXOManagerError(
                `Invalid txid format in ${fieldName}`,
                'INVALID_TXID_FORMAT'
            );
        }

        // Validate vout
        const voutValidation = validateNumberRange(utxo.vout, 0, 0xffffffff, 'vout');
        assertValid(voutValidation);

        // Validate value
        const valueValidation = validateNumberRange(
            utxo.value,
            UTXO_CONSTANTS.MIN_UTXO_VALUE,
            Number.MAX_SAFE_INTEGER,
            'UTXO value'
        );
        assertValid(valueValidation);

        // Validate scriptPubKey
        if (!Buffer.isBuffer(utxo.scriptPubKey)) {
            throw new UTXOManagerError(
                `scriptPubKey must be a Buffer in ${fieldName}`,
                'INVALID_SCRIPT_PUBKEY_TYPE'
            );
        }

        // Validate address
        const addressValidation = validateAddress(utxo.address);
        assertValid(addressValidation);

        return true;
    }

    /**
     * Secure memory clearing for UTXO data
     */
    static secureClear(data) {
        if (Array.isArray(data)) {
            data.forEach(item => this.secureClear(item));
            data.length = 0;
        } else if (Buffer.isBuffer(data)) {
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
 * UTXO selection strategies implementation
 */
class UTXOSelectionStrategies {
    /**
     * Exact biggest: Select the largest UTXO that exactly covers the target
     * Best for privacy when you have a UTXO that exactly matches the target
     */
    static exactBiggest(utxos, targetValue, feeEstimate) {
        const sortedUtxos = [...utxos].sort((a, b) => b.value - a.value);

        // Try to find exact match first
        for (const utxo of sortedUtxos) {
            if (utxo.value === targetValue + feeEstimate) {
                return {
                    utxos: [utxo],
                    totalValue: utxo.value,
                    efficiency: 1.0,
                    privacy: 0.9 // High privacy - single input
                };
            }
        }

        // Find smallest UTXO that covers target + fee
        for (const utxo of sortedUtxos.reverse()) {
            if (utxo.value >= targetValue + feeEstimate) {
                return {
                    utxos: [utxo],
                    totalValue: utxo.value,
                    efficiency: 0.8,
                    privacy: 0.9
                };
            }
        }

        return null; // No single UTXO can cover the target
    }

    /**
     * Accumulate smallest: Start with smallest UTXOs and accumulate until target is met
     * Good for consolidating small UTXOs and reducing UTXO set size
     */
    static accumSmallest(utxos, targetValue, feeEstimate) {
        const sortedUtxos = [...utxos].sort((a, b) => a.value - b.value);
        const selectedUtxos = [];
        let totalValue = 0;
        const targetWithFee = targetValue + feeEstimate;

        for (const utxo of sortedUtxos) {
            selectedUtxos.push(utxo);
            totalValue += utxo.value;

            if (totalValue >= targetWithFee) {
                return {
                    utxos: selectedUtxos,
                    totalValue,
                    efficiency: 0.6, // Lower efficiency due to many inputs
                    privacy: Math.max(0.3, 1 - (selectedUtxos.length * 0.1)) // Privacy decreases with more inputs
                };
            }
        }

        return null; // Insufficient funds
    }

    /**
     * Accumulate biggest: Start with largest UTXOs and accumulate until target is met
     * Efficient for minimizing transaction size and fees
     */
    static accumBiggest(utxos, targetValue, feeEstimate) {
        const sortedUtxos = [...utxos].sort((a, b) => b.value - a.value);
        const selectedUtxos = [];
        let totalValue = 0;
        const targetWithFee = targetValue + feeEstimate;

        for (const utxo of sortedUtxos) {
            selectedUtxos.push(utxo);
            totalValue += utxo.value;

            if (totalValue >= targetWithFee) {
                return {
                    utxos: selectedUtxos,
                    totalValue,
                    efficiency: 0.9, // High efficiency - fewer inputs
                    privacy: Math.max(0.4, 1 - (selectedUtxos.length * 0.15))
                };
            }
        }

        return null; // Insufficient funds
    }

    /**
     * Random selection: Randomly select UTXOs to improve privacy
     * Best privacy but potentially less efficient
     */
    static randomSelection(utxos, targetValue, feeEstimate) {
        const shuffledUtxos = [...utxos].sort(() => Math.random() - 0.5);
        const selectedUtxos = [];
        let totalValue = 0;
        const targetWithFee = targetValue + feeEstimate;

        for (const utxo of shuffledUtxos) {
            selectedUtxos.push(utxo);
            totalValue += utxo.value;

            if (totalValue >= targetWithFee) {
                return {
                    utxos: selectedUtxos,
                    totalValue,
                    efficiency: 0.5, // Variable efficiency
                    privacy: 0.95 // Highest privacy score
                };
            }
        }

        return null; // Insufficient funds
    }

    /**
     * Branch and bound: Optimal selection algorithm for exact matches
     * Attempts to minimize change outputs for better privacy
     */
    static branchAndBound(utxos, targetValue, feeEstimate, maxAttempts = 1000) {
        const target = targetValue + feeEstimate;
        let bestMatch = null;
        let bestWaste = Number.MAX_SAFE_INTEGER;
        let attempts = 0;

        function search(index, currentUtxos, currentValue) {
            if (attempts++ > maxAttempts) return;

            if (currentValue >= target) {
                const waste = currentValue - target;
                if (waste < bestWaste) {
                    bestWaste = waste;
                    bestMatch = [...currentUtxos];
                }
                return;
            }

            if (index >= utxos.length) return;

            // Try including current UTXO
            search(index + 1, [...currentUtxos, utxos[index]], currentValue + utxos[index].value);

            // Try not including current UTXO
            search(index + 1, currentUtxos, currentValue);
        }

        search(0, [], 0);

        if (bestMatch) {
            const totalValue = bestMatch.reduce((sum, utxo) => sum + utxo.value, 0);
            return {
                utxos: bestMatch,
                totalValue,
                efficiency: 0.95, // Very efficient - optimal selection
                privacy: bestWaste === 0 ? 1.0 : 0.8 // Perfect privacy if no change
            };
        }

        return null; // No suitable combination found
    }
}

/**
 * Fee estimation service with mempool integration
 */
class FeeEstimationService {
    constructor(options = {}) {
        this.mempoolApiUrl = options.mempoolApiUrl || UTXO_CONSTANTS.DEFAULT_MEMPOOL_API;
        this.timeout = options.timeout || UTXO_CONSTANTS.FEE_ESTIMATION_TIMEOUT;
        this.cache = new Map();
        this.cacheSize = 0;
        this.maxCacheSize = UTXO_CONSTANTS.CACHE_SIZE_LIMIT;
    }

    /**
     * Get current fee estimations from mempool
     * 
     * @returns {Promise<FeeEstimation>} Current fee rates
     */
    async getCurrentFeeRates() {
        const cacheKey = 'current_fees';
        const cached = this.cache.get(cacheKey);

        // Return cached result if still valid
        if (cached && Date.now() - cached.timestamp < UTXO_CONSTANTS.FEE_CACHE_DURATION) {
            return cached;
        }

        try {
            const response = await this._fetchWithTimeout(this.mempoolApiUrl);
            const data = await response.json();

            const feeEstimation = {
                economyFee: Math.max(data.hourFee || UTXO_CONSTANTS.MIN_FEE_RATE, UTXO_CONSTANTS.MIN_FEE_RATE),
                normalFee: Math.max(data.halfHourFee || 10, UTXO_CONSTANTS.MIN_FEE_RATE),
                priorityFee: Math.max(data.fastestFee || 20, UTXO_CONSTANTS.MIN_FEE_RATE),
                timestamp: Date.now(),
                source: 'mempool_api'
            };

            // Validate fee rates are reasonable
            this._validateFeeRates(feeEstimation);

            // Cache the result
            this._setCacheItem(cacheKey, feeEstimation);

            return feeEstimation;

        } catch (error) {
            console.warn('⚠️  Fee estimation API failed, using fallback rates:', error.message);
            return this._getFallbackFeeRates();
        }
    }

    /**
     * Estimate fee for a specific transaction configuration
     * 
     * @param {number} inputCount - Number of transaction inputs
     * @param {number} outputCount - Number of transaction outputs
     * @param {string[]} inputTypes - Types of inputs ('p2pkh', 'p2wpkh', 'p2tr', etc.)
     * @param {string} priority - Fee priority ('economy', 'normal', 'priority')
     * @returns {Promise<number>} Estimated fee in satoshis
     */
    async estimateTransactionFee(inputCount, outputCount, inputTypes = [], priority = 'normal') {
        try {
            const feeRates = await this.getCurrentFeeRates();
            let feeRate;

            switch (priority) {
                case 'economy':
                    feeRate = feeRates.economyFee;
                    break;
                case 'priority':
                    feeRate = feeRates.priorityFee;
                    break;
                default:
                    feeRate = feeRates.normalFee;
            }

            const estimatedWeight = this._calculateTransactionWeight(inputCount, outputCount, inputTypes);
            const estimatedSize = Math.ceil(estimatedWeight / 4);

            return Math.ceil(estimatedSize * feeRate);

        } catch (error) {
            throw new UTXOManagerError(
                `Fee estimation failed: ${error.message}`,
                'FEE_ESTIMATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Calculate transaction weight based on input/output types
     */
    _calculateTransactionWeight(inputCount, outputCount, inputTypes) {
        let totalWeight = TRANSACTION_CONSTANTS.BASE_WEIGHT;

        // Calculate input weights based on types
        if (inputTypes.length === inputCount) {
            for (const type of inputTypes) {
                switch (type) {
                    case 'p2pkh':
                        totalWeight += TRANSACTION_CONSTANTS.LEGACY_INPUT_WEIGHT;
                        break;
                    case 'p2wpkh':
                        totalWeight += TRANSACTION_CONSTANTS.SEGWIT_INPUT_WEIGHT;
                        break;
                    case 'p2tr':
                        totalWeight += TRANSACTION_CONSTANTS.TAPROOT_INPUT_WEIGHT;
                        break;
                    default:
                        totalWeight += TRANSACTION_CONSTANTS.LEGACY_INPUT_WEIGHT; // Conservative estimate
                }
            }
        } else {
            // Use average weight if types not specified
            totalWeight += inputCount * TRANSACTION_CONSTANTS.SEGWIT_INPUT_WEIGHT;
        }

        // Add output weights
        totalWeight += outputCount * TRANSACTION_CONSTANTS.OUTPUT_WEIGHT;

        return totalWeight;
    }

    /**
     * Fetch with timeout support
     */
    async _fetchWithTimeout(url) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const response = await fetch(url, { signal: controller.signal });
            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            return response;
        } catch (error) {
            clearTimeout(timeoutId);
            throw error;
        }
    }

    /**
     * Validate fee rates are within reasonable bounds
     */
    _validateFeeRates(feeEstimation) {
        const rates = [feeEstimation.economyFee, feeEstimation.normalFee, feeEstimation.priorityFee];

        for (const rate of rates) {
            if (rate < UTXO_CONSTANTS.MIN_FEE_RATE || rate > UTXO_CONSTANTS.MAX_FEE_RATE) {
                throw new Error(`Fee rate out of bounds: ${rate}`);
            }
        }

        // Ensure ordering is correct
        if (feeEstimation.economyFee > feeEstimation.normalFee ||
            feeEstimation.normalFee > feeEstimation.priorityFee) {
            console.warn('⚠️  Fee rate ordering is incorrect, adjusting...');

            feeEstimation.economyFee = Math.min(feeEstimation.economyFee, feeEstimation.normalFee);
            feeEstimation.priorityFee = Math.max(feeEstimation.normalFee, feeEstimation.priorityFee);
        }
    }

    /**
     * Get fallback fee rates when API is unavailable
     */
    _getFallbackFeeRates() {
        return {
            economyFee: TRANSACTION_CONSTANTS.ECONOMY_FEE_RATE,
            normalFee: TRANSACTION_CONSTANTS.DEFAULT_FEE_RATE,
            priorityFee: TRANSACTION_CONSTANTS.HIGH_FEE_RATE,
            timestamp: Date.now(),
            source: 'fallback'
        };
    }

    /**
     * Set cache item with size management
     */
    _setCacheItem(key, value) {
        // Remove old item if exists
        if (this.cache.has(key)) {
            this.cache.delete(key);
            this.cacheSize--;
        }

        // Clean cache if at limit
        if (this.cacheSize >= this.maxCacheSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
            this.cacheSize--;
        }

        this.cache.set(key, value);
        this.cacheSize++;
    }

    /**
     * Clear fee estimation cache
     */
    clearCache() {
        this.cache.clear();
        this.cacheSize = 0;
    }
}

/**
 * Comprehensive UTXO manager with intelligent selection
 */
class UTXOManager {
    constructor(options = {}) {
        this.network = options.network || 'main';
        this.feeEstimationService = new FeeEstimationService(options.feeService);

        // UTXO storage
        this.utxos = new Map(); // txid:vout -> UTXO
        this.spentUtxos = new Set(); // Track spent UTXOs
        this.pendingUtxos = new Set(); // Track pending UTXOs

        // RBF tracking
        this.rbfTransactions = new Map(); // originalTxid -> rbfData

        // Selection preferences
        this.defaultStrategy = options.defaultStrategy || 'exactBiggest';
        this.privacyMode = options.privacyMode !== false; // Default true
        this.consolidationMode = options.consolidationMode || false;

        // Performance tracking
        this.selectionMetrics = {
            totalSelections: 0,
            averageTime: 0,
            successRate: 0,
            strategyUsage: {}
        };
    }

    /**
     * Add UTXOs to the manager
     * 
     * @param {UTXO[]} utxos - Array of UTXOs to add
     */
    addUtxos(utxos) {
        const startTime = Date.now();

        try {
            UTXOSecurityUtils.checkRateLimit('add-utxos');

            if (!Array.isArray(utxos)) {
                throw new UTXOManagerError(
                    'UTXOs must be provided as an array',
                    'INVALID_UTXOS_FORMAT'
                );
            }

            let addedCount = 0;
            let skippedCount = 0;

            for (const utxo of utxos) {
                try {
                    UTXOSecurityUtils.validateUTXO(utxo);

                    const utxoKey = `${utxo.txid}:${utxo.vout}`;

                    // Skip if already exists
                    if (this.utxos.has(utxoKey)) {
                        skippedCount++;
                        continue;
                    }

                    // Add metadata
                    const enhancedUtxo = {
                        ...utxo,
                        addedAt: Date.now(),
                        spent: false,
                        pending: false,
                        spendable: utxo.isSpendable !== false, // Default true
                        privacyScore: this._calculatePrivacyScore(utxo)
                    };

                    this.utxos.set(utxoKey, enhancedUtxo);
                    addedCount++;

                } catch (error) {
                    console.warn(`⚠️  Skipping invalid UTXO ${utxo.txid}:${utxo.vout}:`, error.message);
                    skippedCount++;
                }
            }

            UTXOSecurityUtils.validateSelectionTime(startTime, 'add UTXOs');

            console.log(`✅ Added ${addedCount} UTXOs, skipped ${skippedCount}`);

            return {
                added: addedCount,
                skipped: skippedCount,
                total: this.utxos.size
            };

        } catch (error) {
            if (error instanceof UTXOManagerError) {
                throw error;
            }
            throw new UTXOManagerError(
                `Failed to add UTXOs: ${error.message}`,
                'ADD_UTXOS_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Select UTXOs for a transaction with intelligent strategy selection
     * 
     * @param {number} targetValue - Target amount in satoshis
     * @param {Object} [options={}] - Selection options
     * @returns {Promise<SelectionResult>} Selection result with UTXOs and metadata
     */
    async selectUtxos(targetValue, options = {}) {
        const startTime = Date.now();

        try {
            UTXOSecurityUtils.checkRateLimit('select-utxos');

            // Validate target value
            const valueValidation = validateNumberRange(
                targetValue,
                UTXO_CONSTANTS.MIN_UTXO_VALUE,
                Number.MAX_SAFE_INTEGER,
                'target value'
            );
            assertValid(valueValidation);

            // Get available UTXOs
            const availableUtxos = this._getAvailableUtxos(options);

            if (availableUtxos.length === 0) {
                throw new UTXOManagerError(
                    'No spendable UTXOs available',
                    'NO_SPENDABLE_UTXOS'
                );
            }

            // Check if we have sufficient funds
            const totalAvailable = availableUtxos.reduce((sum, utxo) => sum + utxo.value, 0);
            if (totalAvailable < targetValue) {
                throw new UTXOManagerError(
                    `Insufficient funds: need ${targetValue}, have ${totalAvailable}`,
                    'INSUFFICIENT_FUNDS',
                    { needed: targetValue, available: totalAvailable, deficit: targetValue - totalAvailable }
                );
            }

            // Estimate fees for selection
            const inputTypes = availableUtxos.map(utxo => utxo.type);
            const estimatedFee = await this.feeEstimationService.estimateTransactionFee(
                5, // Estimate for average transaction
                2, // Typically 1 output + 1 change
                inputTypes.slice(0, 5),
                options.priority || 'normal'
            );

            // Select optimal strategy
            const strategy = this._selectOptimalStrategy(availableUtxos, targetValue, estimatedFee, options);

            // Attempt selection with chosen strategy
            const result = await this._executeSelection(
                strategy,
                availableUtxos,
                targetValue,
                estimatedFee,
                options
            );

            // Update metrics
            this._updateSelectionMetrics(strategy.name, startTime, true);

            UTXOSecurityUtils.validateSelectionTime(startTime, 'UTXO selection');

            return result;

        } catch (error) {
            this._updateSelectionMetrics('failed', startTime, false);

            if (error instanceof UTXOManagerError || error instanceof ValidationError) {
                throw error;
            }
            throw new UTXOManagerError(
                `UTXO selection failed: ${error.message}`,
                'SELECTION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Mark UTXOs as spent
     * 
     * @param {string[]} utxoKeys - Array of UTXO keys (txid:vout)
     */
    markUtxosSpent(utxoKeys) {
        try {
            UTXOSecurityUtils.checkRateLimit('mark-spent');

            if (!Array.isArray(utxoKeys)) {
                throw new UTXOManagerError(
                    'UTXO keys must be provided as an array',
                    'INVALID_UTXO_KEYS_FORMAT'
                );
            }

            let markedCount = 0;
            let notFoundCount = 0;

            for (const utxoKey of utxoKeys) {
                if (typeof utxoKey !== 'string' || !utxoKey.includes(':')) {
                    console.warn(`⚠️  Invalid UTXO key format: ${utxoKey}`);
                    continue;
                }

                if (this.utxos.has(utxoKey)) {
                    const utxo = this.utxos.get(utxoKey);
                    utxo.spent = true;
                    utxo.spentAt = Date.now();
                    this.spentUtxos.add(utxoKey);
                    markedCount++;
                } else {
                    notFoundCount++;
                }
            }

            console.log(`✅ Marked ${markedCount} UTXOs as spent, ${notFoundCount} not found`);

            return {
                marked: markedCount,
                notFound: notFoundCount,
                totalSpent: this.spentUtxos.size
            };

        } catch (error) {
            if (error instanceof UTXOManagerError) {
                throw error;
            }
            throw new UTXOManagerError(
                `Failed to mark UTXOs as spent: ${error.message}`,
                'MARK_SPENT_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Mark UTXOs as pending (used in unconfirmed transactions)
     * 
     * @param {string[]} utxoKeys - Array of UTXO keys (txid:vout)
     */
    markUtxosPending(utxoKeys) {
        try {
            UTXOSecurityUtils.checkRateLimit('mark-pending');

            if (!Array.isArray(utxoKeys)) {
                throw new UTXOManagerError(
                    'UTXO keys must be provided as an array',
                    'INVALID_UTXO_KEYS_FORMAT'
                );
            }

            let markedCount = 0;

            for (const utxoKey of utxoKeys) {
                if (this.utxos.has(utxoKey)) {
                    const utxo = this.utxos.get(utxoKey);
                    utxo.pending = true;
                    utxo.pendingAt = Date.now();
                    this.pendingUtxos.add(utxoKey);
                    markedCount++;
                }
            }

            return {
                marked: markedCount,
                totalPending: this.pendingUtxos.size
            };

        } catch (error) {
            throw new UTXOManagerError(
                `Failed to mark UTXOs as pending: ${error.message}`,
                'MARK_PENDING_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Remove UTXOs from management
     * 
     * @param {string[]} utxoKeys - Array of UTXO keys to remove
     */
    removeUtxos(utxoKeys) {
        try {
            UTXOSecurityUtils.checkRateLimit('remove-utxos');

            let removedCount = 0;

            for (const utxoKey of utxoKeys) {
                if (this.utxos.has(utxoKey)) {
                    // Secure cleanup
                    const utxo = this.utxos.get(utxoKey);
                    UTXOSecurityUtils.secureClear(utxo);

                    this.utxos.delete(utxoKey);
                    this.spentUtxos.delete(utxoKey);
                    this.pendingUtxos.delete(utxoKey);
                    removedCount++;
                }
            }

            return {
                removed: removedCount,
                remaining: this.utxos.size
            };

        } catch (error) {
            throw new UTXOManagerError(
                `Failed to remove UTXOs: ${error.message}`,
                'REMOVE_UTXOS_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Create RBF (Replace-by-Fee) transaction
     * 
     * @param {string} originalTxid - Original transaction ID to replace
     * @param {number} newFeeRate - New fee rate (sat/vbyte)
     * @param {Object} [options={}] - RBF options
     * @returns {Promise<Object>} RBF transaction data
     */
    async createRBFTransaction(originalTxid, newFeeRate, options = {}) {
        const startTime = Date.now();

        try {
            UTXOSecurityUtils.checkRateLimit('create-rbf');

            // Validate inputs
            if (!originalTxid || typeof originalTxid !== 'string') {
                throw new UTXOManagerError(
                    'Original transaction ID is required',
                    'MISSING_ORIGINAL_TXID'
                );
            }

            const feeRateValidation = validateNumberRange(
                newFeeRate,
                UTXO_CONSTANTS.MIN_FEE_RATE,
                UTXO_CONSTANTS.MAX_FEE_RATE,
                'new fee rate'
            );
            assertValid(feeRateValidation);

            // Check if we have RBF data for this transaction
            const rbfData = this.rbfTransactions.get(originalTxid);
            if (!rbfData) {
                throw new UTXOManagerError(
                    `No RBF data found for transaction: ${originalTxid}`,
                    'RBF_DATA_NOT_FOUND'
                );
            }

            // Validate fee increase
            const feeIncrease = newFeeRate / rbfData.originalFeeRate;
            if (feeIncrease < UTXO_CONSTANTS.MIN_RBF_FEE_INCREASE) {
                throw new UTXOManagerError(
                    `Fee increase too small: ${feeIncrease.toFixed(2)}x, minimum ${UTXO_CONSTANTS.MIN_RBF_FEE_INCREASE}x`,
                    'INSUFFICIENT_FEE_INCREASE',
                    { currentIncrease: feeIncrease, minimumIncrease: UTXO_CONSTANTS.MIN_RBF_FEE_INCREASE }
                );
            }

            // Check RBF attempt limit
            if (rbfData.attempts >= UTXO_CONSTANTS.MAX_RBF_ATTEMPTS) {
                throw new UTXOManagerError(
                    `Maximum RBF attempts exceeded: ${rbfData.attempts}`,
                    'MAX_RBF_ATTEMPTS_EXCEEDED'
                );
            }

            // Calculate new fee
            const newFee = Math.ceil(rbfData.estimatedSize * newFeeRate);
            const additionalFee = newFee - rbfData.currentFee;

            // Create RBF transaction data
            const rbfTransaction = {
                originalTxid: originalTxid,
                rbfTxid: this._generateTxid(), // Placeholder
                newFeeRate: newFeeRate,
                newFee: newFee,
                additionalFee: additionalFee,
                attempt: rbfData.attempts + 1,
                createdAt: Date.now(),
                utxos: rbfData.utxos,
                outputs: rbfData.outputs,
                metadata: {
                    ...rbfData.metadata,
                    rbfHistory: [
                        ...(rbfData.metadata.rbfHistory || []),
                        {
                            attempt: rbfData.attempts + 1,
                            feeRate: newFeeRate,
                            fee: newFee,
                            timestamp: Date.now()
                        }
                    ]
                }
            };

            // Update RBF tracking
            this.rbfTransactions.set(originalTxid, {
                ...rbfData,
                attempts: rbfData.attempts + 1,
                currentFee: newFee,
                currentFeeRate: newFeeRate,
                lastRbfAt: Date.now()
            });

            UTXOSecurityUtils.validateSelectionTime(startTime, 'RBF transaction creation');

            return rbfTransaction;

        } catch (error) {
            if (error instanceof UTXOManagerError || error instanceof ValidationError) {
                throw error;
            }
            throw new UTXOManagerError(
                `RBF transaction creation failed: ${error.message}`,
                'RBF_CREATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Track transaction for RBF capabilities
     * 
     * @param {string} txid - Transaction ID
     * @param {Object} transactionData - Transaction data for RBF tracking
     */
    trackTransactionForRBF(txid, transactionData) {
        try {
            const rbfData = {
                txid: txid,
                utxos: transactionData.utxos || [],
                outputs: transactionData.outputs || [],
                originalFeeRate: transactionData.feeRate || TRANSACTION_CONSTANTS.DEFAULT_FEE_RATE,
                currentFee: transactionData.fee || 0,
                currentFeeRate: transactionData.feeRate || TRANSACTION_CONSTANTS.DEFAULT_FEE_RATE,
                estimatedSize: transactionData.estimatedSize || 0,
                attempts: 0,
                createdAt: Date.now(),
                lastRbfAt: null,
                metadata: transactionData.metadata || {}
            };

            this.rbfTransactions.set(txid, rbfData);

            return rbfData;

        } catch (error) {
            throw new UTXOManagerError(
                `Failed to track transaction for RBF: ${error.message}`,
                'RBF_TRACKING_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Get UTXO statistics and health metrics
     * 
     * @returns {Object} Comprehensive UTXO statistics
     */
    getStatistics() {
        try {
            const allUtxos = Array.from(this.utxos.values());
            const spendableUtxos = allUtxos.filter(utxo => utxo.spendable && !utxo.spent && !utxo.pending);
            const totalValue = spendableUtxos.reduce((sum, utxo) => sum + utxo.value, 0);

            // Value distribution
            const valueDistribution = this._calculateValueDistribution(spendableUtxos);

            // Address analysis
            const addressDistribution = this._calculateAddressDistribution(spendableUtxos);

            // Type distribution
            const typeDistribution = this._calculateTypeDistribution(spendableUtxos);

            // Privacy analysis
            const privacyAnalysis = this._calculatePrivacyAnalysis(spendableUtxos);

            return {
                summary: {
                    totalUtxos: this.utxos.size,
                    spendableUtxos: spendableUtxos.length,
                    spentUtxos: this.spentUtxos.size,
                    pendingUtxos: this.pendingUtxos.size,
                    totalValue: totalValue,
                    averageValue: spendableUtxos.length > 0 ? Math.round(totalValue / spendableUtxos.length) : 0
                },
                distribution: {
                    byValue: valueDistribution,
                    byAddress: addressDistribution,
                    byType: typeDistribution
                },
                privacy: privacyAnalysis,
                health: {
                    consolidationNeeded: spendableUtxos.length > UTXO_CONSTANTS.CONSOLIDATION_THRESHOLD,
                    dustUtxos: spendableUtxos.filter(utxo => utxo.value <= UTXO_CONSTANTS.MIN_UTXO_VALUE).length,
                    avgPrivacyScore: privacyAnalysis.averageScore,
                    addressReuseIssues: addressDistribution.reuseIssues
                },
                rbf: {
                    trackedTransactions: this.rbfTransactions.size,
                    totalAttempts: Array.from(this.rbfTransactions.values()).reduce((sum, rbf) => sum + rbf.attempts, 0)
                },
                performance: this.selectionMetrics
            };

        } catch (error) {
            throw new UTXOManagerError(
                `Failed to generate statistics: ${error.message}`,
                'STATISTICS_FAILED',
                { originalError: error.message }
            );
        }
    }

    // Private helper methods

    /**
     * Get available UTXOs for selection
     */
    _getAvailableUtxos(options = {}) {
        const allUtxos = Array.from(this.utxos.values());

        return allUtxos.filter(utxo => {
            // Basic spendability checks
            if (!utxo.spendable || utxo.spent || utxo.pending) {
                return false;
            }

            // Confirmation requirements
            const minConfirmations = options.minConfirmations || 0;
            if ((utxo.confirmations || 0) < minConfirmations) {
                return false;
            }

            // Type filtering
            if (options.allowedTypes && !options.allowedTypes.includes(utxo.type)) {
                return false;
            }

            // Privacy filtering
            if (this.privacyMode && utxo.privacyScore < UTXO_CONSTANTS.PRIVACY_SCORE_THRESHOLD) {
                return false;
            }

            // Value filtering
            if (options.minValue && utxo.value < options.minValue) {
                return false;
            }

            if (options.maxValue && utxo.value > options.maxValue) {
                return false;
            }

            return true;
        });
    }

    /**
     * Select optimal strategy based on context
     */
    _selectOptimalStrategy(utxos, targetValue, feeEstimate, options) {
        const strategies = [
            {
                name: 'exactBiggest',
                algorithm: UTXOSelectionStrategies.exactBiggest,
                privacyScore: 0.9,
                efficiencyScore: 0.8,
                suitable: utxos.some(utxo => utxo.value >= targetValue + feeEstimate)
            },
            {
                name: 'branchAndBound',
                algorithm: UTXOSelectionStrategies.branchAndBound,
                privacyScore: 0.95,
                efficiencyScore: 0.95,
                suitable: utxos.length <= 20 // Performance limit
            },
            {
                name: 'accumBiggest',
                algorithm: UTXOSelectionStrategies.accumBiggest,
                privacyScore: 0.6,
                efficiencyScore: 0.9,
                suitable: true
            },
            {
                name: 'randomSelection',
                algorithm: UTXOSelectionStrategies.randomSelection,
                privacyScore: 0.95,
                efficiencyScore: 0.5,
                suitable: this.privacyMode
            },
            {
                name: 'accumSmallest',
                algorithm: UTXOSelectionStrategies.accumSmallest,
                privacyScore: 0.4,
                efficiencyScore: 0.6,
                suitable: this.consolidationMode
            }
        ];

        // Filter suitable strategies
        const suitableStrategies = strategies.filter(s => s.suitable);

        // Use specified strategy if available and suitable
        if (options.strategy) {
            const specified = suitableStrategies.find(s => s.name === options.strategy);
            if (specified) {
                return specified;
            }
        }

        // Select based on mode and context
        if (this.privacyMode) {
            return suitableStrategies.sort((a, b) => b.privacyScore - a.privacyScore)[0];
        } else {
            return suitableStrategies.sort((a, b) => b.efficiencyScore - a.efficiencyScore)[0];
        }
    }

    /**
     * Execute selection with chosen strategy
     */
    async _executeSelection(strategy, utxos, targetValue, feeEstimate, options) {
        const selectionResult = strategy.algorithm(utxos, targetValue, feeEstimate);

        if (!selectionResult) {
            throw new UTXOManagerError(
                `Strategy '${strategy.name}' failed to find suitable UTXOs`,
                'STRATEGY_FAILED',
                { strategy: strategy.name, targetValue, feeEstimate }
            );
        }

        // Recalculate accurate fee with actual input count
        const inputTypes = selectionResult.utxos.map(utxo => utxo.type);
        const accurateFee = await this.feeEstimationService.estimateTransactionFee(
            selectionResult.utxos.length,
            2, // 1 output + 1 change
            inputTypes,
            options.priority || 'normal'
        );

        // Check if selection still covers accurate fee
        if (selectionResult.totalValue < targetValue + accurateFee) {
            // Try to add one more UTXO if available
            const remainingUtxos = utxos.filter(utxo =>
                !selectionResult.utxos.includes(utxo)
            );

            if (remainingUtxos.length > 0) {
                const additionalUtxo = remainingUtxos.sort((a, b) => a.value - b.value)[0];
                selectionResult.utxos.push(additionalUtxo);
                selectionResult.totalValue += additionalUtxo.value;
            } else {
                throw new UTXOManagerError(
                    'Selected UTXOs insufficient to cover accurate fee estimation',
                    'INSUFFICIENT_FOR_ACCURATE_FEE'
                );
            }
        }

        const changeValue = selectionResult.totalValue - targetValue - accurateFee;
        const privacyScore = this._calculateSelectionPrivacyScore(selectionResult.utxos);

        return {
            selectedUtxos: selectionResult.utxos,
            totalValue: selectionResult.totalValue,
            changeValue: Math.max(0, changeValue),
            estimatedFee: accurateFee,
            strategy: strategy.name,
            metrics: {
                selectionTime: Date.now() - this.selectionMetrics.lastStartTime,
                efficiency: selectionResult.efficiency || 0.5,
                utxoCount: selectionResult.utxos.length,
                averageUtxoValue: Math.round(selectionResult.totalValue / selectionResult.utxos.length)
            },
            privacyScore: privacyScore
        };
    }

    /**
     * Calculate privacy score for a UTXO
     */
    _calculatePrivacyScore(utxo) {
        let score = 1.0;

        // Address reuse penalty
        const addressUtxos = Array.from(this.utxos.values()).filter(u => u.address === utxo.address);
        if (addressUtxos.length > UTXO_CONSTANTS.MAX_ADDRESS_REUSE) {
            score -= 0.3;
        }

        // Value-based privacy (round numbers are less private)
        if (utxo.value % 100000 === 0) { // 0.001 BTC multiples
            score -= 0.2;
        } else if (utxo.value % 10000 === 0) { // 0.0001 BTC multiples
            score -= 0.1;
        }

        // Age-based privacy (older UTXOs may be more private)
        const age = Date.now() - (utxo.addedAt || Date.now());
        const daysSinceAdded = age / (1000 * 60 * 60 * 24);
        if (daysSinceAdded > 30) {
            score += 0.1;
        }

        return Math.max(0, Math.min(1, score));
    }

    /**
     * Calculate privacy score for a selection
     */
    _calculateSelectionPrivacyScore(utxos) {
        if (utxos.length === 0) return 0;

        const baseScore = utxos.reduce((sum, utxo) => sum + utxo.privacyScore, 0) / utxos.length;

        // Penalty for multiple inputs (reduces privacy)
        const multiInputPenalty = Math.max(0, (utxos.length - 1) * 0.1);

        // Bonus for diverse address types
        const uniqueTypes = new Set(utxos.map(utxo => utxo.type)).size;
        const diversityBonus = (uniqueTypes - 1) * 0.05;

        return Math.max(0, Math.min(1, baseScore - multiInputPenalty + diversityBonus));
    }

    /**
     * Update selection performance metrics
     */
    _updateSelectionMetrics(strategy, startTime, success) {
        const elapsedTime = Date.now() - startTime;

        this.selectionMetrics.totalSelections++;
        this.selectionMetrics.averageTime =
            (this.selectionMetrics.averageTime * (this.selectionMetrics.totalSelections - 1) + elapsedTime) /
            this.selectionMetrics.totalSelections;

        if (success) {
            this.selectionMetrics.successRate =
                (this.selectionMetrics.successRate * (this.selectionMetrics.totalSelections - 1) + 1) /
                this.selectionMetrics.totalSelections;
        } else {
            this.selectionMetrics.successRate =
                (this.selectionMetrics.successRate * (this.selectionMetrics.totalSelections - 1)) /
                this.selectionMetrics.totalSelections;
        }

        if (!this.selectionMetrics.strategyUsage[strategy]) {
            this.selectionMetrics.strategyUsage[strategy] = 0;
        }
        this.selectionMetrics.strategyUsage[strategy]++;

        this.selectionMetrics.lastStartTime = startTime;
    }

    /**
     * Calculate value distribution statistics
     */
    _calculateValueDistribution(utxos) {
        if (utxos.length === 0) return {};

        const values = utxos.map(utxo => utxo.value).sort((a, b) => a - b);
        const total = values.reduce((sum, value) => sum + value, 0);

        return {
            min: values[0],
            max: values[values.length - 1],
            median: values[Math.floor(values.length / 2)],
            average: Math.round(total / values.length),
            total: total,
            dustCount: values.filter(v => v <= UTXO_CONSTANTS.MIN_UTXO_VALUE).length,
            largeCount: values.filter(v => v >= 100000000).length, // >= 1 BTC
            distribution: {
                dust: values.filter(v => v <= UTXO_CONSTANTS.MIN_UTXO_VALUE).length,
                small: values.filter(v => v > UTXO_CONSTANTS.MIN_UTXO_VALUE && v <= 100000).length,
                medium: values.filter(v => v > 100000 && v <= 10000000).length,
                large: values.filter(v => v > 10000000).length
            }
        };
    }

    /**
     * Calculate address distribution and reuse analysis
     */
    _calculateAddressDistribution(utxos) {
        const addressCounts = {};
        let reuseIssues = 0;

        for (const utxo of utxos) {
            addressCounts[utxo.address] = (addressCounts[utxo.address] || 0) + 1;
            if (addressCounts[utxo.address] > UTXO_CONSTANTS.MAX_ADDRESS_REUSE) {
                reuseIssues++;
            }
        }

        const uniqueAddresses = Object.keys(addressCounts).length;
        const maxReuse = Math.max(...Object.values(addressCounts));
        const avgUtxosPerAddress = utxos.length / uniqueAddresses;

        return {
            uniqueAddresses,
            totalUtxos: utxos.length,
            averageUtxosPerAddress: avgUtxosPerAddress,
            maxReuseCount: maxReuse,
            reuseIssues,
            distribution: addressCounts
        };
    }

    /**
     * Calculate type distribution
     */
    _calculateTypeDistribution(utxos) {
        const typeCounts = {};

        for (const utxo of utxos) {
            typeCounts[utxo.type] = (typeCounts[utxo.type] || 0) + 1;
        }

        return typeCounts;
    }

    /**
     * Calculate privacy analysis
     */
    _calculatePrivacyAnalysis(utxos) {
        if (utxos.length === 0) {
            return {
                averageScore: 0,
                distribution: {},
                issues: []
            };
        }

        const scores = utxos.map(utxo => utxo.privacyScore);
        const averageScore = scores.reduce((sum, score) => sum + score, 0) / scores.length;

        const distribution = {
            excellent: scores.filter(s => s >= 0.9).length,
            good: scores.filter(s => s >= 0.7 && s < 0.9).length,
            fair: scores.filter(s => s >= 0.5 && s < 0.7).length,
            poor: scores.filter(s => s < 0.5).length
        };

        const issues = [];
        if (distribution.poor > 0) {
            issues.push(`${distribution.poor} UTXOs with poor privacy scores`);
        }

        const addressReuse = this._calculateAddressDistribution(utxos);
        if (addressReuse.reuseIssues > 0) {
            issues.push(`${addressReuse.reuseIssues} address reuse issues detected`);
        }

        return {
            averageScore,
            distribution,
            issues
        };
    }

    /**
     * Generate placeholder transaction ID
     */
    _generateTxid() {
        return randomBytes(32).toString('hex');
    }

    /**
     * Clear all UTXOs and reset state
     */
    destroy() {
        try {
            console.warn('⚠️  Destroying UTXO manager - clearing all data');

            // Secure cleanup of UTXOs
            for (const utxo of this.utxos.values()) {
                UTXOSecurityUtils.secureClear(utxo);
            }

            // Clear all data structures
            this.utxos.clear();
            this.spentUtxos.clear();
            this.pendingUtxos.clear();
            this.rbfTransactions.clear();

            // Clear fee estimation cache
            this.feeEstimationService.clearCache();

            // Reset metrics
            this.selectionMetrics = {
                totalSelections: 0,
                averageTime: 0,
                successRate: 0,
                strategyUsage: {}
            };

            console.log('✅ UTXO manager destroyed securely');

        } catch (error) {
            console.error('❌ UTXO manager destruction failed:', error.message);
        }
    }
}

export {
    UTXOManagerError,
    UTXOSecurityUtils,
    UTXOSelectionStrategies,
    FeeEstimationService,
    UTXOManager,
    UTXO_CONSTANTS
};