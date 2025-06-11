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
     * Validate UTXO structure and security
     */
    static validateUTXO(utxo) {
        if (!utxo || typeof utxo !== 'object') {
            throw new UTXOManagerError(
                'UTXO must be a valid object',
                'INVALID_UTXO_OBJECT'
            );
        }

        if (!utxo.txid || typeof utxo.txid !== 'string' || utxo.txid.length !== 64) {
            throw new UTXOManagerError(
                'UTXO must have valid txid',
                'INVALID_UTXO_TXID'
            );
        }

        if (typeof utxo.vout !== 'number' || utxo.vout < 0 || utxo.vout > 0xffffffff) {
            throw new UTXOManagerError(
                'UTXO must have valid vout',
                'INVALID_UTXO_VOUT'
            );
        }

        if (typeof utxo.value !== 'number' || utxo.value < 0 || utxo.value > 21000000 * 100000000) {
            throw new UTXOManagerError(
                'UTXO must have valid value',
                'INVALID_UTXO_VALUE'
            );
        }

        if (utxo.address) {
            try {
                assertValid(validateAddress(utxo.address));
            } catch (error) {
                throw new UTXOManagerError(
                    `UTXO has invalid address: ${error.message}`,
                    'INVALID_UTXO_ADDRESS'
                );
            }
        }
    }

    /**
     * Validate selection timing to prevent DoS
     */
    static validateSelectionTime(startTime, operation) {
        const elapsed = Date.now() - startTime;
        if (elapsed > UTXO_CONSTANTS.MAX_SELECTION_TIME_MS) {
            throw new UTXOManagerError(
                `${operation} took too long: ${elapsed}ms`,
                'OPERATION_TIMEOUT',
                { elapsed, maxAllowed: UTXO_CONSTANTS.MAX_SELECTION_TIME_MS }
            );
        }
    }

    /**
     * Secure cleanup of sensitive UTXO data
     */
    static secureClear(utxo) {
        if (utxo && typeof utxo === 'object') {
            // Clear sensitive fields
            if (utxo.scriptPubKey && Buffer.isBuffer(utxo.scriptPubKey)) {
                utxo.scriptPubKey.fill(0);
            }
            if (utxo.derivationPath) {
                utxo.derivationPath = null;
            }
            if (utxo.metadata) {
                utxo.metadata = null;
            }
        }
    }
}

/**
 * UTXO selection strategies implementation
 */
class UTXOSelectionStrategies {
    /**
     * Exact biggest: Try to find single UTXO that matches target
     */
    static exactBiggest(utxos, targetValue) {
        const sorted = [...utxos].sort((a, b) => b.value - a.value);

        // Try to find exact match first
        for (const utxo of sorted) {
            if (utxo.value === targetValue) {
                return {
                    selectedUtxos: [utxo],
                    totalValue: utxo.value,
                    changeValue: 0
                };
            }
        }

        // Find smallest UTXO that covers target
        for (const utxo of sorted.reverse()) {
            if (utxo.value >= targetValue) {
                return {
                    selectedUtxos: [utxo],
                    totalValue: utxo.value,
                    changeValue: utxo.value - targetValue
                };
            }
        }

        return null;
    }

    /**
     * Accumulate smallest: Start with smallest UTXOs
     */
    static accumSmallest(utxos, targetValue) {
        const sorted = [...utxos].sort((a, b) => a.value - b.value);
        const selected = [];
        let totalValue = 0;

        for (const utxo of sorted) {
            selected.push(utxo);
            totalValue += utxo.value;

            if (totalValue >= targetValue) {
                return {
                    selectedUtxos: selected,
                    totalValue,
                    changeValue: totalValue - targetValue
                };
            }
        }

        return null;
    }

    /**
     * Branch and bound algorithm for optimal selection
     */
    static branchAndBound(utxos, targetValue, maxAttempts = 1000) {
        if (utxos.length === 0) return null;

        let bestSelection = null;
        let bestWaste = Infinity;
        let attempts = 0;

        const search = (index, current, currentValue) => {
            if (attempts++ > maxAttempts) return;

            if (currentValue >= targetValue) {
                const waste = currentValue - targetValue;
                if (waste < bestWaste) {
                    bestWaste = waste;
                    bestSelection = [...current];
                }
                return;
            }

            if (index >= utxos.length) return;

            // Include current UTXO
            current.push(utxos[index]);
            search(index + 1, current, currentValue + utxos[index].value);
            current.pop();

            // Exclude current UTXO
            search(index + 1, current, currentValue);
        };

        search(0, [], 0);

        if (bestSelection) {
            const totalValue = bestSelection.reduce((sum, utxo) => sum + utxo.value, 0);
            return {
                selectedUtxos: bestSelection,
                totalValue,
                changeValue: totalValue - targetValue
            };
        }

        return null;
    }

    /**
     * Privacy-focused selection to avoid address reuse
     */
    static privacyAware(utxos, targetValue) {
        // Prefer UTXOs with higher privacy scores
        const sorted = [...utxos].sort((a, b) => {
            const scoreDiff = (b.privacyScore || 0) - (a.privacyScore || 0);
            if (scoreDiff !== 0) return scoreDiff;
            return a.value - b.value; // Then by value ascending
        });

        const selected = [];
        let totalValue = 0;
        const usedAddresses = new Set();

        for (const utxo of sorted) {
            // Skip if address already used (unless necessary)
            if (usedAddresses.has(utxo.address) && totalValue >= targetValue) {
                continue;
            }

            selected.push(utxo);
            totalValue += utxo.value;
            usedAddresses.add(utxo.address);

            if (totalValue >= targetValue) {
                return {
                    selectedUtxos: selected,
                    totalValue,
                    changeValue: totalValue - targetValue
                };
            }
        }

        return null;
    }
}

/**
 * Fee estimation service with mempool integration
 */
class FeeEstimationService {
    constructor(options = {}) {
        this.apiUrl = options.apiUrl || UTXO_CONSTANTS.DEFAULT_MEMPOOL_API;
        this.timeout = options.timeout || UTXO_CONSTANTS.FEE_ESTIMATION_TIMEOUT;
        this.cache = new Map();
        this.cacheSize = 0;
    }

    /**
     * Estimate transaction fee based on current network conditions
     */
    async estimateTransactionFee(inputs, outputs, inputTypes = [], priority = 'normal') {
        try {
            const feeRates = await this.getCurrentFeeRates();
            const feeRate = feeRates[priority + 'Fee'] || feeRates.normalFee;

            // Estimate transaction size
            const estimatedSize = this._estimateTransactionSize(inputs, outputs, inputTypes);

            return Math.ceil(estimatedSize * feeRate);

        } catch (error) {
            console.warn('⚠️  Fee estimation failed, using default:', error.message);
            const defaultFeeRate = TRANSACTION_CONSTANTS.DEFAULT_FEE_RATE;
            const estimatedSize = this._estimateTransactionSize(inputs, outputs, inputTypes);
            return Math.ceil(estimatedSize * defaultFeeRate);
        }
    }

    /**
     * Get current fee rates from mempool API
     */
    async getCurrentFeeRates() {
        const cacheKey = 'current-fees';
        const cached = this.cache.get(cacheKey);

        if (cached && Date.now() - cached.timestamp < UTXO_CONSTANTS.FEE_CACHE_DURATION) {
            return cached.data;
        }

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);

            const response = await fetch(this.apiUrl, {
                signal: controller.signal,
                headers: { 'Accept': 'application/json' }
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();

            // Validate and normalize fee data
            const normalizedData = {
                economyFee: Math.max(data.hourFee || UTXO_CONSTANTS.MIN_FEE_RATE, UTXO_CONSTANTS.MIN_FEE_RATE),
                normalFee: Math.max(data.halfHourFee || UTXO_CONSTANTS.MIN_FEE_RATE, UTXO_CONSTANTS.MIN_FEE_RATE),
                priorityFee: Math.max(data.fastestFee || UTXO_CONSTANTS.MIN_FEE_RATE, UTXO_CONSTANTS.MIN_FEE_RATE),
                timestamp: Date.now(),
                source: 'mempool-api'
            };

            this._updateCache(cacheKey, normalizedData);
            return normalizedData;

        } catch (error) {
            console.warn('⚠️  Failed to fetch fee rates:', error.message);

            // Return fallback fees
            return {
                economyFee: UTXO_CONSTANTS.MIN_FEE_RATE,
                normalFee: TRANSACTION_CONSTANTS.DEFAULT_FEE_RATE,
                priorityFee: TRANSACTION_CONSTANTS.DEFAULT_FEE_RATE * 2,
                timestamp: Date.now(),
                source: 'fallback'
            };
        }
    }

    /**
     * Estimate transaction size in virtual bytes
     */
    _estimateTransactionSize(inputs, outputs, inputTypes = []) {
        let size = 10; // Base transaction overhead

        // Estimate input sizes
        for (let i = 0; i < inputs; i++) {
            const inputType = inputTypes[i] || 'p2wpkh';
            switch (inputType) {
                case 'p2pkh':
                    size += 148; // Legacy input
                    break;
                case 'p2wpkh':
                    size += 68; // Witness input
                    break;
                case 'p2tr':
                    size += 64; // Taproot input
                    break;
                default:
                    size += 68; // Default to witness
            }
        }

        // Estimate output sizes
        size += outputs * 34; // Average output size

        return Math.ceil(size);
    }

    /**
     * Update cache with size limit
     */
    _updateCache(key, data) {
        if (this.cacheSize >= UTXO_CONSTANTS.CACHE_SIZE_LIMIT) {
            // Remove oldest entry
            const oldestKey = this.cache.keys().next().value;
            this.cache.delete(oldestKey);
            this.cacheSize--;
        }

        this.cache.set(key, data);
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
                    'INSUFFICIENT_FEE_INCREASE'
                );
            }

            // Calculate new transaction fee
            const newFee = Math.ceil(rbfData.estimatedSize * newFeeRate);

            // Update RBF tracking
            rbfData.attempts++;
            rbfData.currentFeeRate = newFeeRate;
            rbfData.currentFee = newFee;
            rbfData.lastRbfAt = Date.now();

            if (rbfData.attempts > UTXO_CONSTANTS.MAX_RBF_ATTEMPTS) {
                throw new UTXOManagerError(
                    `Maximum RBF attempts exceeded: ${rbfData.attempts}`,
                    'MAX_RBF_ATTEMPTS_EXCEEDED'
                );
            }

            UTXOSecurityUtils.validateSelectionTime(startTime, 'RBF creation');

            return {
                txid: this._generateTxid(),
                originalTxid,
                newFeeRate,
                newFee,
                feeIncrease,
                attempts: rbfData.attempts,
                utxos: rbfData.utxos,
                outputs: rbfData.outputs,
                metadata: rbfData.metadata
            };

        } catch (error) {
            if (error instanceof UTXOManagerError || error instanceof ValidationError) {
                throw error;
            }
            throw new UTXOManagerError(
                `Failed to create RBF transaction: ${error.message}`,
                'RBF_CREATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Track transaction for future RBF operations
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
                    averageValue: spendableUtxos.length > 0 ? Math.round(totalValue / spendableUtxos.length) : 0,
                    medianValue: this._calculateMedian(spendableUtxos.map(u => u.value))
                },
                distribution: {
                    byValue: valueDistribution,
                    byAddress: addressDistribution,
                    byType: typeDistribution
                },
                privacy: privacyAnalysis,
                performance: this.selectionMetrics,
                health: {
                    consolidationNeeded: spendableUtxos.length > UTXO_CONSTANTS.CONSOLIDATION_THRESHOLD,
                    dustUtxos: spendableUtxos.filter(u => u.value <= UTXO_CONSTANTS.MIN_UTXO_VALUE).length,
                    largeUtxos: spendableUtxos.filter(u => u.value > 1000000).length // > 0.01 BTC
                }
            };

        } catch (error) {
            throw new UTXOManagerError(
                `Failed to generate statistics: ${error.message}`,
                'STATISTICS_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Get available UTXOs for selection
     */
    _getAvailableUtxos(options = {}) {
        const utxos = Array.from(this.utxos.values()).filter(utxo => {
            // Basic spendability check
            if (!utxo.spendable || utxo.spent || utxo.pending) {
                return false;
            }

            // Minimum confirmation check
            const minConfirmations = options.minConfirmations || 0;
            if (utxo.confirmations < minConfirmations) {
                return false;
            }

            // Dust limit check
            if (utxo.value <= UTXO_CONSTANTS.MIN_UTXO_VALUE) {
                return false;
            }

            // Address filter
            if (options.excludeAddresses && options.excludeAddresses.includes(utxo.address)) {
                return false;
            }

            // Type filter
            if (options.includeTypes && !options.includeTypes.includes(utxo.type)) {
                return false;
            }

            return true;
        });

        // Apply maximum UTXO limit
        if (utxos.length > UTXO_CONSTANTS.MAX_UTXOS_PER_TRANSACTION) {
            // Sort by value descending and take top UTXOs
            utxos.sort((a, b) => b.value - a.value);
            return utxos.slice(0, UTXO_CONSTANTS.MAX_UTXOS_PER_TRANSACTION);
        }

        return utxos;
    }

    /**
     * Select optimal strategy based on context
     */
    _selectOptimalStrategy(utxos, targetValue, estimatedFee, options) {
        const strategies = [
            { name: 'exactBiggest', algorithm: UTXOSelectionStrategies.exactBiggest, privacyScore: 0.9, efficiencyScore: 1.0 },
            { name: 'accumSmallest', algorithm: UTXOSelectionStrategies.accumSmallest, privacyScore: 0.6, efficiencyScore: 0.7 },
            { name: 'branchAndBound', algorithm: UTXOSelectionStrategies.branchAndBound, privacyScore: 0.8, efficiencyScore: 0.9 },
            { name: 'privacyAware', algorithm: UTXOSelectionStrategies.privacyAware, privacyScore: 1.0, efficiencyScore: 0.6 }
        ];

        // Override with user preference
        if (options.strategy) {
            const strategy = strategies.find(s => s.name === options.strategy);
            if (strategy) return strategy;
        }

        // Privacy mode preference
        if (this.privacyMode && !options.ignorePrivacy) {
            return strategies.find(s => s.name === 'privacyAware');
        }

        // Consolidation mode preference
        if (this.consolidationMode) {
            return strategies.find(s => s.name === 'accumSmallest');
        }

        // Default strategy
        return strategies.find(s => s.name === this.defaultStrategy) || strategies[0];
    }

    /**
     * Execute UTXO selection with fallback strategies
     */
    async _executeSelection(strategy, utxos, targetValue, estimatedFee, options) {
        const totalTarget = targetValue + estimatedFee;

        try {
            // Try primary strategy
            let result = strategy.algorithm(utxos, totalTarget);

            if (!result) {
                // Try fallback strategies
                const fallbackStrategies = [
                    UTXOSelectionStrategies.branchAndBound,
                    UTXOSelectionStrategies.accumSmallest
                ];

                for (const fallback of fallbackStrategies) {
                    result = fallback(utxos, totalTarget);
                    if (result) {
                        strategy.name += '-fallback';
                        break;
                    }
                }
            }

            if (!result) {
                throw new UTXOManagerError(
                    `No suitable UTXO combination found for target: ${totalTarget}`,
                    'NO_SUITABLE_COMBINATION'
                );
            }

            // Calculate final metrics
            const privacyScore = this._calculateSelectionPrivacyScore(result.selectedUtxos);
            const efficiencyScore = this._calculateEfficiencyScore(result, targetValue, estimatedFee);

            return {
                selectedUtxos: result.selectedUtxos,
                totalValue: result.totalValue,
                changeValue: result.changeValue,
                estimatedFee,
                strategy: strategy.name,
                metrics: {
                    utxoCount: result.selectedUtxos.length,
                    privacyScore,
                    efficiencyScore,
                    waste: result.changeValue
                },
                privacyScore
            };

        } catch (error) {
            throw new UTXOManagerError(
                `Selection execution failed: ${error.message}`,
                'SELECTION_EXECUTION_FAILED',
                { strategy: strategy.name, originalError: error.message }
            );
        }
    }

    /**
     * Calculate privacy score for a UTXO
     */
    _calculatePrivacyScore(utxo) {
        let score = 1.0;

        // Address reuse penalty
        const addressUsage = this._getAddressUsageCount(utxo.address);
        if (addressUsage > 1) {
            score -= Math.min(0.3, (addressUsage - 1) * 0.1);
        }

        // Age bonus (older UTXOs generally better for privacy)
        const age = Date.now() - (utxo.addedAt || Date.now());
        const ageDays = age / (1000 * 60 * 60 * 24);
        if (ageDays > 7) {
            score += Math.min(0.1, ageDays / 100);
        }

        // Common value penalty (round numbers are less private)
        if (this._isCommonValue(utxo.value)) {
            score -= 0.1;
        }

        return Math.max(0, Math.min(1, score));
    }

    /**
     * Calculate selection privacy score
     */
    _calculateSelectionPrivacyScore(selectedUtxos) {
        if (selectedUtxos.length === 0) return 0;

        const scores = selectedUtxos.map(utxo => utxo.privacyScore || this._calculatePrivacyScore(utxo));
        const averageScore = scores.reduce((sum, score) => sum + score, 0) / scores.length;

        // Penalty for using multiple UTXOs from same address
        const addresses = new Set(selectedUtxos.map(utxo => utxo.address));
        const addressReuseRatio = addresses.size / selectedUtxos.length;

        return averageScore * addressReuseRatio;
    }

    /**
     * Calculate efficiency score
     */
    _calculateEfficiencyScore(result, targetValue, estimatedFee) {
        const totalCost = targetValue + estimatedFee;
        const waste = result.changeValue;
        const efficiency = 1 - (waste / totalCost);

        return Math.max(0, Math.min(1, efficiency));
    }

    /**
     * Update selection metrics
     */
    _updateSelectionMetrics(strategy, startTime, success) {
        const duration = Date.now() - startTime;

        this.selectionMetrics.totalSelections++;
        this.selectionMetrics.averageTime =
            (this.selectionMetrics.averageTime * (this.selectionMetrics.totalSelections - 1) + duration)
            / this.selectionMetrics.totalSelections;

        if (success) {
            this.selectionMetrics.successRate =
                (this.selectionMetrics.successRate * (this.selectionMetrics.totalSelections - 1) + 1)
                / this.selectionMetrics.totalSelections;
        }

        this.selectionMetrics.strategyUsage[strategy] =
            (this.selectionMetrics.strategyUsage[strategy] || 0) + 1;
    }

    /**
     * Get address usage count
     */
    _getAddressUsageCount(address) {
        let count = 0;
        for (const utxo of this.utxos.values()) {
            if (utxo.address === address) count++;
        }
        return count;
    }

    /**
     * Check if value is commonly used (round numbers)
     */
    _isCommonValue(value) {
        const roundValues = [
            100000,    // 0.001 BTC
            1000000,   // 0.01 BTC
            10000000,  // 0.1 BTC
            100000000  // 1 BTC
        ];
        return roundValues.includes(value) || value % 1000000 === 0;
    }

    /**
     * Calculate value distribution
     */
    _calculateValueDistribution(utxos) {
        const distribution = {
            dust: 0,      // <= 546 sats
            small: 0,     // 547 - 10,000 sats
            medium: 0,    // 10,001 - 100,000 sats
            large: 0,     // 100,001 - 1,000,000 sats
            xlarge: 0     // > 1,000,000 sats
        };

        for (const utxo of utxos) {
            if (utxo.value <= 546) distribution.dust++;
            else if (utxo.value <= 10000) distribution.small++;
            else if (utxo.value <= 100000) distribution.medium++;
            else if (utxo.value <= 1000000) distribution.large++;
            else distribution.xlarge++;
        }

        return distribution;
    }

    /**
     * Calculate address distribution
     */
    _calculateAddressDistribution(utxos) {
        const addressCounts = new Map();
        let reuseIssues = 0;

        for (const utxo of utxos) {
            const count = addressCounts.get(utxo.address) || 0;
            addressCounts.set(utxo.address, count + 1);

            if (count + 1 > UTXO_CONSTANTS.MAX_ADDRESS_REUSE) {
                reuseIssues++;
            }
        }

        return {
            uniqueAddresses: addressCounts.size,
            totalUtxos: utxos.length,
            reuseRatio: utxos.length > 0 ? addressCounts.size / utxos.length : 0,
            reuseIssues
        };
    }

    /**
     * Calculate type distribution
     */
    _calculateTypeDistribution(utxos) {
        const distribution = {};

        for (const utxo of utxos) {
            const type = utxo.type || 'unknown';
            distribution[type] = (distribution[type] || 0) + 1;
        }

        return distribution;
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
     * Calculate median value
     */
    _calculateMedian(values) {
        if (values.length === 0) return 0;

        const sorted = [...values].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);

        if (sorted.length % 2 === 0) {
            return Math.round((sorted[mid - 1] + sorted[mid]) / 2);
        } else {
            return sorted[mid];
        }
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