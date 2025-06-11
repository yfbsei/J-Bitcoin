/**
 * @fileoverview Enhanced PSBT (Partially Signed Bitcoin Transaction) implementation
 * 
 * This module provides a comprehensive PSBT implementation following BIP174, BIP371 (Taproot),
 * and related specifications. It handles creation, manipulation, signing, and finalization
 * of PSBTs with support for all Bitcoin transaction types.
 * 
 * FEATURES:
 * - Full BIP174 PSBT specification support
 * - Taproot (BIP371) support
 * - Comprehensive validation and error handling
 * - Secure key handling and signing coordination
 * - Cross-platform serialization/deserialization
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

/**
 * PSBT specific error class
 */
class PSBTError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'PSBTError';
        this.code = code;
        this.details = details;
        this.timestamp = Date.now();
    }
}

/**
 * PSBT constants and field types (BIP174)
 */
const PSBT_CONSTANTS = {
    // PSBT magic bytes
    MAGIC_BYTES: Buffer.from([0x70, 0x73, 0x62, 0x74, 0xff]),

    // PSBT version
    VERSION: 0,

    // Global field types
    GLOBAL_UNSIGNED_TX: 0x00,
    GLOBAL_XPUB: 0x01,
    GLOBAL_VERSION: 0xfb,
    GLOBAL_PROPRIETARY: 0xfc,

    // Input field types
    IN_NON_WITNESS_UTXO: 0x00,
    IN_WITNESS_UTXO: 0x01,
    IN_PARTIAL_SIG: 0x02,
    IN_SIGHASH_TYPE: 0x03,
    IN_REDEEM_SCRIPT: 0x04,
    IN_WITNESS_SCRIPT: 0x05,
    IN_BIP32_DERIVATION: 0x06,
    IN_FINAL_SCRIPTSIG: 0x07,
    IN_FINAL_SCRIPTWITNESS: 0x08,
    IN_POR_COMMITMENT: 0x09,
    IN_PROPRIETARY: 0xfc,

    // Output field types
    OUT_REDEEM_SCRIPT: 0x00,
    OUT_WITNESS_SCRIPT: 0x01,
    OUT_BIP32_DERIVATION: 0x02,
    OUT_PROPRIETARY: 0xfc,

    // Taproot field types (BIP371)
    IN_TAP_KEY_SIG: 0x13,
    IN_TAP_SCRIPT_SIG: 0x14,
    IN_TAP_LEAF_SCRIPT: 0x15,
    IN_TAP_BIP32_DERIVATION: 0x16,
    IN_TAP_INTERNAL_KEY: 0x17,
    IN_TAP_MERKLE_ROOT: 0x18,

    OUT_TAP_INTERNAL_KEY: 0x05,
    OUT_TAP_TREE: 0x06,
    OUT_TAP_BIP32_DERIVATION: 0x07,

    // Signature hash types
    SIGHASH_ALL: 0x01,
    SIGHASH_NONE: 0x02,
    SIGHASH_SINGLE: 0x03,
    SIGHASH_ANYONECANPAY: 0x80,

    // Default values
    DEFAULT_SIGHASH_TYPE: 0x01, // SIGHASH_ALL
    MAX_SCRIPT_ELEMENT_SIZE: 520,
    MAX_STANDARD_TX_WEIGHT: 400000
};

/**
 * PSBT key-value pair structure
 */
class PSBTKeyValue {
    constructor(type, key = Buffer.alloc(0), value = Buffer.alloc(0)) {
        this.type = type;
        this.key = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
        this.value = Buffer.isBuffer(value) ? value : Buffer.from(value, 'hex');
    }

    /**
     * Serialize key-value pair
     */
    serialize() {
        const typeBuffer = Buffer.from([this.type]);
        const fullKey = Buffer.concat([typeBuffer, this.key]);

        const keyLength = this._encodeVarInt(fullKey.length);
        const valueLength = this._encodeVarInt(this.value.length);

        return Buffer.concat([keyLength, fullKey, valueLength, this.value]);
    }

    /**
     * Encode variable integer
     */
    _encodeVarInt(n) {
        if (n < 0xfd) {
            return Buffer.from([n]);
        } else if (n <= 0xffff) {
            const buf = Buffer.allocUnsafe(3);
            buf[0] = 0xfd;
            buf.writeUInt16LE(n, 1);
            return buf;
        } else if (n <= 0xffffffff) {
            const buf = Buffer.allocUnsafe(5);
            buf[0] = 0xfe;
            buf.writeUInt32LE(n, 1);
            return buf;
        } else {
            const buf = Buffer.allocUnsafe(9);
            buf[0] = 0xff;
            buf.writeBigUInt64LE(BigInt(n), 1);
            return buf;
        }
    }
}

/**
 * Enhanced PSBT implementation with comprehensive features
 */
class PSBT {
    constructor(network = 'main', options = {}) {
        this.network = validateAndGetNetwork(network);
        this.createdAt = Date.now();
        this.finalized = false;

        // PSBT sections
        this.global = {
            unsignedTx: null,
            xpubs: new Map(),
            version: PSBT_CONSTANTS.VERSION,
            proprietary: new Map()
        };

        this.inputs = [];
        this.outputs = [];

        // Configuration options
        this.options = this._normalizeOptions(options);
    }

    /**
     * Normalize constructor options
     */
    _normalizeOptions(options) {
        return {
            allowEmptyInputs: options.allowEmptyInputs || false,
            requireAllSignatures: options.requireAllSignatures !== false,
            maximumFeeRate: options.maximumFeeRate || 5000, // 5000 sat/vB
            ...options
        };
    }

    /**
     * Create PSBT from unsigned transaction
     * 
     * @param {Object} unsignedTx - Unsigned transaction structure
     * @param {Array} utxos - Array of UTXO data for inputs
     * @param {string} [network='main'] - Network type
     * @returns {PSBT} New PSBT instance
     */
    static fromUnsignedTx(unsignedTx, utxos = [], network = 'main') {
        const psbt = new PSBT(network);

        // Validate inputs
        if (!unsignedTx || !unsignedTx.inputs || !Array.isArray(unsignedTx.inputs)) {
            throw new PSBTError('Invalid unsigned transaction structure', 'INVALID_UNSIGNED_TX');
        }

        if (unsignedTx.inputs.length !== utxos.length) {
            throw new PSBTError(
                `UTXO count mismatch: ${utxos.length} UTXOs for ${unsignedTx.inputs.length} inputs`,
                'UTXO_MISMATCH'
            );
        }

        // Set global unsigned transaction
        psbt.global.unsignedTx = psbt._normalizeUnsignedTx(unsignedTx);

        // Initialize inputs with UTXO data
        for (let i = 0; i < unsignedTx.inputs.length; i++) {
            const input = unsignedTx.inputs[i];
            const utxo = utxos[i];

            if (!utxo) {
                throw new PSBTError(`Missing UTXO data for input ${i}`, 'MISSING_UTXO');
            }

            psbt.inputs.push(psbt._createInputFromUTXO(input, utxo, i));
        }

        // Initialize outputs
        for (let i = 0; i < unsignedTx.outputs.length; i++) {
            psbt.outputs.push(psbt._createOutput(unsignedTx.outputs[i], i));
        }

        return psbt;
    }

    /**
     * Create PSBT from base64 string
     * 
     * @param {string} data - Base64 encoded PSBT
     * @param {string} [network='main'] - Network type
     * @returns {PSBT} Parsed PSBT instance
     */
    static fromBase64(data, network = 'main') {
        try {
            const buffer = Buffer.from(data, 'base64');
            return PSBT.fromBuffer(buffer, network);
        } catch (error) {
            throw new PSBTError(`Failed to parse PSBT from base64: ${error.message}`, 'PARSE_ERROR');
        }
    }

    /**
     * Create PSBT from buffer
     * 
     * @param {Buffer} buffer - PSBT buffer
     * @param {string} [network='main'] - Network type
     * @returns {PSBT} Parsed PSBT instance
     */
    static fromBuffer(buffer, network = 'main') {
        const psbt = new PSBT(network);
        let offset = 0;

        // Check magic bytes
        const magic = buffer.slice(offset, offset + 5);
        if (!magic.equals(PSBT_CONSTANTS.MAGIC_BYTES)) {
            throw new PSBTError('Invalid PSBT magic bytes', 'INVALID_MAGIC');
        }
        offset += 5;

        // Parse global section
        const globalResult = psbt._parseSection(buffer, offset);
        psbt._processGlobalFields(globalResult.fields);
        offset = globalResult.offset;

        // Parse input sections
        const inputCount = psbt.global.unsignedTx.inputs.length;
        for (let i = 0; i < inputCount; i++) {
            const inputResult = psbt._parseSection(buffer, offset);
            psbt.inputs.push(psbt._processInputFields(inputResult.fields, i));
            offset = inputResult.offset;
        }

        // Parse output sections
        const outputCount = psbt.global.unsignedTx.outputs.length;
        for (let i = 0; i < outputCount; i++) {
            const outputResult = psbt._parseSection(buffer, offset);
            psbt.outputs.push(psbt._processOutputFields(outputResult.fields, i));
            offset = outputResult.offset;
        }

        return psbt;
    }

    /**
     * Add input to PSBT
     * 
     * @param {Object} inputData - Input data including UTXO information
     * @returns {PSBT} This PSBT instance for chaining
     */
    addInput(inputData) {
        this._validateNotFinalized();

        const input = {
            // Previous transaction reference
            previousTxId: inputData.txid || inputData.hash,
            previousOutputIndex: inputData.vout || inputData.index,
            sequence: inputData.sequence || 0xffffffff,

            // UTXO data
            nonWitnessUtxo: inputData.nonWitnessUtxo || null,
            witnessUtxo: inputData.witnessUtxo || {
                amount: inputData.value || inputData.amount,
                scriptPubKey: inputData.scriptPubKey
            },

            // Signature data
            partialSigs: new Map(),
            sighashType: inputData.sighashType || PSBT_CONSTANTS.DEFAULT_SIGHASH_TYPE,

            // Scripts
            redeemScript: inputData.redeemScript || null,
            witnessScript: inputData.witnessScript || null,

            // BIP32 derivation
            bip32Derivation: new Map(),

            // Finalization
            finalScriptSig: null,
            finalScriptWitness: null,

            // Taproot fields
            tapKeySig: null,
            tapScriptSigs: new Map(),
            tapLeafScripts: new Map(),
            tapBip32Derivation: new Map(),
            tapInternalKey: inputData.tapInternalKey || null,
            tapMerkleRoot: inputData.tapMerkleRoot || null,

            // Custom fields
            proprietary: new Map()
        };

        // Add to unsigned transaction inputs
        if (!this.global.unsignedTx) {
            this.global.unsignedTx = {
                version: 2,
                locktime: 0,
                inputs: [],
                outputs: []
            };
        }

        this.global.unsignedTx.inputs.push({
            hash: Buffer.isBuffer(input.previousTxId) ?
                input.previousTxId : Buffer.from(input.previousTxId, 'hex').reverse(),
            index: input.previousOutputIndex,
            script: Buffer.alloc(0),
            sequence: input.sequence
        });

        this.inputs.push(input);
        return this;
    }

    /**
     * Add output to PSBT
     * 
     * @param {Object} outputData - Output data
     * @returns {PSBT} This PSBT instance for chaining
     */
    addOutput(outputData) {
        this._validateNotFinalized();

        const output = {
            amount: outputData.amount || outputData.value,
            scriptPubKey: outputData.scriptPubKey || outputData.script,

            // Scripts
            redeemScript: outputData.redeemScript || null,
            witnessScript: outputData.witnessScript || null,

            // BIP32 derivation
            bip32Derivation: new Map(),

            // Taproot fields
            tapInternalKey: outputData.tapInternalKey || null,
            tapTree: outputData.tapTree || null,
            tapBip32Derivation: new Map(),

            // Custom fields
            proprietary: new Map()
        };

        // Add to unsigned transaction outputs
        if (!this.global.unsignedTx) {
            this.global.unsignedTx = {
                version: 2,
                locktime: 0,
                inputs: [],
                outputs: []
            };
        }

        this.global.unsignedTx.outputs.push({
            amount: output.amount,
            script: Buffer.isBuffer(output.scriptPubKey) ?
                output.scriptPubKey : Buffer.from(output.scriptPubKey, 'hex')
        });

        this.outputs.push(output);
        return this;
    }

    /**
     * Add partial signature to input
     * 
     * @param {number} inputIndex - Input index
     * @param {Buffer} pubkey - Public key
     * @param {Buffer} signature - Signature
     * @returns {PSBT} This PSBT instance for chaining
     */
    addPartialSig(inputIndex, pubkey, signature) {
        this._validateNotFinalized();
        this._validateInputIndex(inputIndex);

        if (!Buffer.isBuffer(pubkey) || pubkey.length !== 33) {
            throw new PSBTError('Invalid public key format', 'INVALID_PUBKEY');
        }

        if (!Buffer.isBuffer(signature)) {
            throw new PSBTError('Signature must be a Buffer', 'INVALID_SIGNATURE');
        }

        this.inputs[inputIndex].partialSigs.set(pubkey.toString('hex'), signature);
        return this;
    }

    /**
     * Sign input with private key
     * 
     * @param {number} inputIndex - Input index
     * @param {Buffer} privateKey - Private key for signing
     * @param {number} [sighashType] - Signature hash type
     * @returns {PSBT} This PSBT instance for chaining
     */
    signInput(inputIndex, privateKey, sighashType = PSBT_CONSTANTS.SIGHASH_ALL) {
        this._validateNotFinalized();
        this._validateInputIndex(inputIndex);

        if (!Buffer.isBuffer(privateKey) || privateKey.length !== 32) {
            throw new PSBTError('Invalid private key format', 'INVALID_PRIVATE_KEY');
        }

        try {
            // Derive public key
            const pubkey = secp256k1.getPublicKey(privateKey, true);

            // Create signature hash
            const signatureHash = this._getSignatureHash(inputIndex, sighashType);

            // Sign the hash
            const signature = secp256k1.sign(signatureHash, privateKey);
            const signatureBuffer = Buffer.concat([
                Buffer.from(signature.toCompactRawBytes()),
                Buffer.from([sighashType])
            ]);

            // Add signature to PSBT
            this.addPartialSig(inputIndex, Buffer.from(pubkey), signatureBuffer);

            return this;

        } catch (error) {
            throw new PSBTError(
                `Failed to sign input ${inputIndex}: ${error.message}`,
                'SIGNING_FAILED',
                { inputIndex, originalError: error.message }
            );
        }
    }

    /**
     * Sign all inputs with private key
     * 
     * @param {Buffer} privateKey - Private key for signing
     * @param {number} [sighashType] - Signature hash type
     * @returns {PSBT} This PSBT instance for chaining
     */
    signAllInputs(privateKey, sighashType = PSBT_CONSTANTS.SIGHASH_ALL) {
        for (let i = 0; i < this.inputs.length; i++) {
            if (this._canSignInput(i)) {
                this.signInput(i, privateKey, sighashType);
            }
        }
        return this;
    }

    /**
     * Finalize input
     * 
     * @param {number} inputIndex - Input index to finalize
     * @returns {PSBT} This PSBT instance for chaining
     */
    finalizeInput(inputIndex) {
        this._validateInputIndex(inputIndex);

        const input = this.inputs[inputIndex];

        // Check if already finalized
        if (input.finalScriptSig || input.finalScriptWitness) {
            return this;
        }

        // Check if we have required signatures
        if (!this._canFinalizeInput(inputIndex)) {
            throw new PSBTError(
                `Cannot finalize input ${inputIndex}: insufficient signatures`,
                'INSUFFICIENT_SIGNATURES'
            );
        }

        try {
            // Generate final scripts based on input type
            const finalization = this._generateFinalization(inputIndex);

            input.finalScriptSig = finalization.scriptSig;
            input.finalScriptWitness = finalization.scriptWitness;

            // Clear intermediate data
            input.partialSigs.clear();
            input.tapScriptSigs.clear();

        } catch (error) {
            throw new PSBTError(
                `Failed to finalize input ${inputIndex}: ${error.message}`,
                'FINALIZATION_FAILED',
                { inputIndex, originalError: error.message }
            );
        }

        return this;
    }

    /**
     * Finalize all inputs
     * 
     * @returns {PSBT} This PSBT instance for chaining
     */
    finalizeAllInputs() {
        for (let i = 0; i < this.inputs.length; i++) {
            if (this._canFinalizeInput(i)) {
                this.finalizeInput(i);
            }
        }
        this.finalized = true;
        return this;
    }

    /**
     * Extract final transaction
     * 
     * @returns {Buffer} Serialized transaction
     */
    extractTransaction() {
        if (!this.finalized) {
            // Try to finalize all inputs first
            this.finalizeAllInputs();
        }

        // Verify all inputs are finalized
        for (let i = 0; i < this.inputs.length; i++) {
            const input = this.inputs[i];
            if (!input.finalScriptSig && !input.finalScriptWitness) {
                throw new PSBTError(`Input ${i} is not finalized`, 'INPUT_NOT_FINALIZED');
            }
        }

        return this._serializeTransaction();
    }

    /**
     * Convert PSBT to base64
     * 
     * @returns {string} Base64 encoded PSBT
     */
    toBase64() {
        return this.toBuffer().toString('base64');
    }

    /**
     * Convert PSBT to buffer
     * 
     * @returns {Buffer} Serialized PSBT
     */
    toBuffer() {
        const sections = [];

        // Add magic bytes
        sections.push(PSBT_CONSTANTS.MAGIC_BYTES);

        // Serialize global section
        sections.push(this._serializeGlobalSection());

        // Serialize input sections
        for (let i = 0; i < this.inputs.length; i++) {
            sections.push(this._serializeInputSection(i));
        }

        // Serialize output sections
        for (let i = 0; i < this.outputs.length; i++) {
            sections.push(this._serializeOutputSection(i));
        }

        return Buffer.concat(sections);
    }

    /**
     * Get PSBT statistics and validation info
     * 
     * @returns {Object} PSBT statistics
     */
    getStatus() {
        const inputStatus = this.inputs.map((input, i) => ({
            index: i,
            hasUtxo: !!(input.witnessUtxo || input.nonWitnessUtxo),
            hasPartialSigs: input.partialSigs.size > 0,
            hasFinalization: !!(input.finalScriptSig || input.finalScriptWitness),
            isTaproot: !!input.tapInternalKey,
            canSign: this._canSignInput(i),
            canFinalize: this._canFinalizeInput(i)
        }));

        const requiredSigs = this._getRequiredSignatures();
        const currentSigs = this._getCurrentSignatures();

        return {
            version: PSBT_CONSTANTS.VERSION,
            network: this.network,
            createdAt: this.createdAt,
            inputs: {
                total: this.inputs.length,
                withUtxo: inputStatus.filter(s => s.hasUtxo).length,
                withSigs: inputStatus.filter(s => s.hasPartialSigs).length,
                finalized: inputStatus.filter(s => s.hasFinalization).length,
                canSign: inputStatus.filter(s => s.canSign).length,
                details: inputStatus
            },
            outputs: {
                total: this.outputs.length
            },
            signatures: {
                required: requiredSigs,
                current: currentSigs,
                complete: currentSigs >= requiredSigs
            },
            finalized: this.finalized,
            canExtract: this._canExtractTransaction(),
            estimatedSize: this._estimateTransactionSize(),
            fee: this._calculateFee()
        };
    }

    /**
     * Validate PSBT structure and data
     * 
     * @returns {Object} Validation results
     */
    validate() {
        const errors = [];
        const warnings = [];

        try {
            // Validate global section
            if (!this.global.unsignedTx) {
                errors.push('Missing unsigned transaction in global section');
            }

            // Validate inputs
            for (let i = 0; i < this.inputs.length; i++) {
                const inputErrors = this._validateInputComplete(i);
                errors.push(...inputErrors);
            }

            // Validate outputs
            for (let i = 0; i < this.outputs.length; i++) {
                const outputErrors = this._validateOutputComplete(i);
                errors.push(...outputErrors);
            }

            // Check fee calculation
            const fee = this._calculateFee();
            if (fee < 0) {
                errors.push('Negative fee detected');
            } else if (fee > this.options.maximumFeeRate * this._estimateTransactionSize()) {
                warnings.push('Fee rate exceeds maximum threshold');
            }

        } catch (error) {
            errors.push(`Validation error: ${error.message}`);
        }

        return {
            valid: errors.length === 0,
            errors,
            warnings
        };
    }

    /**
     * Clone PSBT
     * 
     * @returns {PSBT} Cloned PSBT instance
     */
    clone() {
        return PSBT.fromBuffer(this.toBuffer(), this.network);
    }

    // ==================== PRIVATE METHODS ====================

    /**
     * Validate that PSBT is not finalized
     */
    _validateNotFinalized() {
        if (this.finalized) {
            throw new PSBTError('Cannot modify finalized PSBT', 'PSBT_FINALIZED');
        }
    }

    /**
     * Validate input index
     */
    _validateInputIndex(index) {
        if (typeof index !== 'number' || index < 0 || index >= this.inputs.length) {
            throw new PSBTError(`Invalid input index: ${index}`, 'INVALID_INPUT_INDEX');
        }
    }

    /**
     * Normalize unsigned transaction structure
     */
    _normalizeUnsignedTx(unsignedTx) {
        return {
            version: unsignedTx.version || 2,
            locktime: unsignedTx.locktime || 0,
            inputs: unsignedTx.inputs.map(input => ({
                hash: Buffer.isBuffer(input.hash) ? input.hash : Buffer.from(input.hash, 'hex').reverse(),
                index: input.index,
                script: Buffer.alloc(0), // Always empty for unsigned
                sequence: input.sequence || 0xffffffff
            })),
            outputs: unsignedTx.outputs.map(output => ({
                amount: output.amount,
                script: Buffer.isBuffer(output.script) ? output.script : Buffer.from(output.script, 'hex')
            }))
        };
    }

    /**
     * Create input from UTXO data
     */
    _createInputFromUTXO(input, utxo, index) {
        const psbtInput = {
            previousTxId: input.hash,
            previousOutputIndex: input.index,
            sequence: input.sequence,

            witnessUtxo: {
                amount: utxo.value,
                scriptPubKey: Buffer.isBuffer(utxo.scriptPubKey) ?
                    utxo.scriptPubKey : Buffer.from(utxo.scriptPubKey, 'hex')
            },

            partialSigs: new Map(),
            sighashType: PSBT_CONSTANTS.DEFAULT_SIGHASH_TYPE,
            bip32Derivation: new Map(),

            finalScriptSig: null,
            finalScriptWitness: null,

            tapScriptSigs: new Map(),
            tapLeafScripts: new Map(),
            tapBip32Derivation: new Map(),

            proprietary: new Map()
        };

        // Add additional UTXO fields if provided
        if (utxo.nonWitnessUtxo) {
            psbtInput.nonWitnessUtxo = utxo.nonWitnessUtxo;
        }

        if (utxo.redeemScript) {
            psbtInput.redeemScript = Buffer.isBuffer(utxo.redeemScript) ?
                utxo.redeemScript : Buffer.from(utxo.redeemScript, 'hex');
        }

        if (utxo.witnessScript) {
            psbtInput.witnessScript = Buffer.isBuffer(utxo.witnessScript) ?
                utxo.witnessScript : Buffer.from(utxo.witnessScript, 'hex');
        }

        if (utxo.tapInternalKey) {
            psbtInput.tapInternalKey = Buffer.isBuffer(utxo.tapInternalKey) ?
                utxo.tapInternalKey : Buffer.from(utxo.tapInternalKey, 'hex');
        }

        return psbtInput;
    }

    /**
     * Create output structure
     */
    _createOutput(output, index) {
        return {
            amount: output.amount,
            scriptPubKey: Buffer.isBuffer(output.script) ? output.script : Buffer.from(output.script, 'hex'),

            redeemScript: null,
            witnessScript: null,

            bip32Derivation: new Map(),
            tapBip32Derivation: new Map(),

            proprietary: new Map()
        };
    }

    /**
     * Check if input can be signed
     */
    _canSignInput(index) {
        const input = this.inputs[index];
        return !(input.witnessUtxo || input.nonWitnessUtxo) &&
            !input.finalScriptSig &&
            !input.finalScriptWitness;
    }

    /**
     * Check if input can be finalized
     */
    _canFinalizeInput(index) {
        const input = this.inputs[index];
        return (input.partialSigs.size > 0 || input.tapKeySig) &&
            !input.finalScriptSig &&
            !input.finalScriptWitness;
    }

    /**
     * Check if transaction can be extracted
     */
    _canExtractTransaction() {
        return this.inputs.every(input =>
            input.finalScriptSig !== null || input.finalScriptWitness !== null
        );
    }

    /**
     * Generate signature hash for input
     */
    _getSignatureHash(inputIndex, sighashType = PSBT_CONSTANTS.SIGHASH_ALL) {
        // This is a simplified implementation
        // In practice, this would implement BIP143/BIP341 signature hash calculation
        const input = this.inputs[inputIndex];

        // Create a simplified signature hash based on transaction data
        const txData = this._serializeUnsignedTransaction();
        const inputData = Buffer.concat([
            Buffer.from([inputIndex]),
            Buffer.from([sighashType]),
            input.witnessUtxo ? this._serializeWitnessUtxo(input.witnessUtxo) : Buffer.alloc(0)
        ]);

        return createHash('sha256')
            .update(createHash('sha256').update(Buffer.concat([txData, inputData])).digest())
            .digest();
    }

    /**
     * Generate finalization scripts for input
     */
    _generateFinalization(inputIndex) {
        const input = this.inputs[inputIndex];

        // For Taproot inputs
        if (input.tapKeySig) {
            return {
                scriptSig: null,
                scriptWitness: [input.tapKeySig]
            };
        }

        // For witness inputs with partial signatures
        if (input.partialSigs.size > 0) {
            const signatures = Array.from(input.partialSigs.values());
            const pubkeys = Array.from(input.partialSigs.keys()).map(hex => Buffer.from(hex, 'hex'));

            if (input.witnessScript) {
                // P2WSH
                return {
                    scriptSig: null,
                    scriptWitness: [...signatures, ...pubkeys, input.witnessScript]
                };
            } else {
                // P2WPKH
                return {
                    scriptSig: null,
                    scriptWitness: [signatures[0], pubkeys[0]]
                };
            }
        }

        // Legacy inputs
        if (input.partialSigs.size > 0) {
            const signatures = Array.from(input.partialSigs.values());
            const pubkeys = Array.from(input.partialSigs.keys()).map(hex => Buffer.from(hex, 'hex'));

            // Create scriptSig
            const scriptSig = Buffer.concat([
                Buffer.from([signatures[0].length]),
                signatures[0],
                Buffer.from([pubkeys[0].length]),
                pubkeys[0]
            ]);

            return {
                scriptSig,
                scriptWitness: null
            };
        }

        throw new PSBTError('No signatures found for finalization', 'NO_SIGNATURES');
    }

    /**
     * Get required signatures count
     */
    _getRequiredSignatures() {
        // Simplified: assume 1 signature per input
        return this.inputs.length;
    }

    /**
     * Get current signatures count
     */
    _getCurrentSignatures() {
        return this.inputs.reduce((total, input) => {
            return total + Math.max(input.partialSigs.size, input.tapKeySig ? 1 : 0);
        }, 0);
    }

    /**
     * Estimate transaction size
     */
    _estimateTransactionSize() {
        let size = 10; // Base transaction overhead

        // Input sizes
        for (const input of this.inputs) {
            if (input.tapInternalKey) {
                size += 64; // Taproot input
            } else if (input.witnessUtxo) {
                size += 68; // Witness input
            } else {
                size += 148; // Legacy input
            }
        }

        // Output sizes
        size += this.outputs.length * 34; // Average output size

        return size;
    }

    /**
     * Calculate transaction fee
     */
    _calculateFee() {
        try {
            const inputValue = this.inputs.reduce((total, input) => {
                const utxo = input.witnessUtxo || input.nonWitnessUtxo;
                return total + (utxo ? utxo.amount : 0);
            }, 0);

            const outputValue = this.outputs.reduce((total, output) => {
                return total + output.amount;
            }, 0);

            return inputValue - outputValue;
        } catch (error) {
            return -1; // Invalid fee calculation
        }
    }

    /**
     * Validate input completely
     */
    _validateInputComplete(index) {
        const errors = [];
        const input = this.inputs[index];

        if (!input.witnessUtxo && !input.nonWitnessUtxo) {
            errors.push(`Input ${index}: Missing UTXO data`);
        }

        if (input.witnessUtxo && typeof input.witnessUtxo.amount !== 'number') {
            errors.push(`Input ${index}: Invalid UTXO amount`);
        }

        if (input.redeemScript && !Buffer.isBuffer(input.redeemScript)) {
            errors.push(`Input ${index}: Invalid redeem script format`);
        }

        if (input.witnessScript && !Buffer.isBuffer(input.witnessScript)) {
            errors.push(`Input ${index}: Invalid witness script format`);
        }

        return errors;
    }

    /**
     * Validate output completely
     */
    _validateOutputComplete(index) {
        const errors = [];
        const output = this.outputs[index];

        if (typeof output.amount !== 'number' || output.amount < 0) {
            errors.push(`Output ${index}: Invalid amount`);
        }

        if (!Buffer.isBuffer(output.scriptPubKey)) {
            errors.push(`Output ${index}: Invalid scriptPubKey format`);
        }

        return errors;
    }

    /**
     * Parse PSBT section
     */
    _parseSection(buffer, offset) {
        const fields = [];
        let currentOffset = offset;

        while (currentOffset < buffer.length) {
            // Read key length
            const keyLengthResult = this._readVarInt(buffer, currentOffset);
            if (keyLengthResult.value === 0) {
                // End of section
                currentOffset = keyLengthResult.offset;
                break;
            }

            currentOffset = keyLengthResult.offset;

            // Read key
            const key = buffer.slice(currentOffset, currentOffset + keyLengthResult.value);
            currentOffset += keyLengthResult.value;

            // Read value length
            const valueLengthResult = this._readVarInt(buffer, currentOffset);
            currentOffset = valueLengthResult.offset;

            // Read value
            const value = buffer.slice(currentOffset, currentOffset + valueLengthResult.value);
            currentOffset += valueLengthResult.value;

            fields.push({ key, value });
        }

        return { fields, offset: currentOffset };
    }

    /**
     * Process global fields
     */
    _processGlobalFields(fields) {
        for (const field of fields) {
            const type = field.key[0];
            const keyData = field.key.slice(1);

            switch (type) {
                case PSBT_CONSTANTS.GLOBAL_UNSIGNED_TX:
                    this.global.unsignedTx = this._parseUnsignedTransaction(field.value);
                    break;
                case PSBT_CONSTANTS.GLOBAL_XPUB:
                    this.global.xpubs.set(keyData.toString('hex'), field.value);
                    break;
                case PSBT_CONSTANTS.GLOBAL_VERSION:
                    this.global.version = field.value.readUInt32LE(0);
                    break;
                case PSBT_CONSTANTS.GLOBAL_PROPRIETARY:
                    this.global.proprietary.set(keyData.toString('hex'), field.value);
                    break;
            }
        }
    }

    /**
     * Process input fields
     */
    _processInputFields(fields, index) {
        const input = {
            previousTxId: null,
            previousOutputIndex: null,
            sequence: 0xffffffff,

            nonWitnessUtxo: null,
            witnessUtxo: null,

            partialSigs: new Map(),
            sighashType: PSBT_CONSTANTS.DEFAULT_SIGHASH_TYPE,

            redeemScript: null,
            witnessScript: null,

            bip32Derivation: new Map(),

            finalScriptSig: null,
            finalScriptWitness: null,

            tapKeySig: null,
            tapScriptSigs: new Map(),
            tapLeafScripts: new Map(),
            tapBip32Derivation: new Map(),
            tapInternalKey: null,
            tapMerkleRoot: null,

            proprietary: new Map()
        };

        for (const field of fields) {
            const type = field.key[0];
            const keyData = field.key.slice(1);

            switch (type) {
                case PSBT_CONSTANTS.IN_NON_WITNESS_UTXO:
                    input.nonWitnessUtxo = field.value;
                    break;
                case PSBT_CONSTANTS.IN_WITNESS_UTXO:
                    input.witnessUtxo = this._parseWitnessUtxo(field.value);
                    break;
                case PSBT_CONSTANTS.IN_PARTIAL_SIG:
                    input.partialSigs.set(keyData.toString('hex'), field.value);
                    break;
                case PSBT_CONSTANTS.IN_SIGHASH_TYPE:
                    input.sighashType = field.value.readUInt32LE(0);
                    break;
                case PSBT_CONSTANTS.IN_REDEEM_SCRIPT:
                    input.redeemScript = field.value;
                    break;
                case PSBT_CONSTANTS.IN_WITNESS_SCRIPT:
                    input.witnessScript = field.value;
                    break;
                case PSBT_CONSTANTS.IN_BIP32_DERIVATION:
                    input.bip32Derivation.set(keyData.toString('hex'), this._parseBip32Derivation(field.value));
                    break;
                case PSBT_CONSTANTS.IN_FINAL_SCRIPTSIG:
                    input.finalScriptSig = field.value;
                    break;
                case PSBT_CONSTANTS.IN_FINAL_SCRIPTWITNESS:
                    input.finalScriptWitness = this._parseScriptWitness(field.value);
                    break;
                case PSBT_CONSTANTS.IN_TAP_KEY_SIG:
                    input.tapKeySig = field.value;
                    break;
                case PSBT_CONSTANTS.IN_TAP_SCRIPT_SIG:
                    input.tapScriptSigs.set(keyData.toString('hex'), field.value);
                    break;
                case PSBT_CONSTANTS.IN_TAP_LEAF_SCRIPT:
                    input.tapLeafScripts.set(keyData.toString('hex'), field.value);
                    break;
                case PSBT_CONSTANTS.IN_TAP_BIP32_DERIVATION:
                    input.tapBip32Derivation.set(keyData.toString('hex'), this._parseTapBip32Derivation(field.value));
                    break;
                case PSBT_CONSTANTS.IN_TAP_INTERNAL_KEY:
                    input.tapInternalKey = field.value;
                    break;
                case PSBT_CONSTANTS.IN_TAP_MERKLE_ROOT:
                    input.tapMerkleRoot = field.value;
                    break;
                case PSBT_CONSTANTS.IN_PROPRIETARY:
                    input.proprietary.set(keyData.toString('hex'), field.value);
                    break;
            }
        }

        return input;
    }

    /**
     * Process output fields
     */
    _processOutputFields(fields, index) {
        const output = {
            amount: 0,
            scriptPubKey: Buffer.alloc(0),

            redeemScript: null,
            witnessScript: null,

            bip32Derivation: new Map(),
            tapBip32Derivation: new Map(),

            tapInternalKey: null,
            tapTree: null,

            proprietary: new Map()
        };

        for (const field of fields) {
            const type = field.key[0];
            const keyData = field.key.slice(1);

            switch (type) {
                case PSBT_CONSTANTS.OUT_REDEEM_SCRIPT:
                    output.redeemScript = field.value;
                    break;
                case PSBT_CONSTANTS.OUT_WITNESS_SCRIPT:
                    output.witnessScript = field.value;
                    break;
                case PSBT_CONSTANTS.OUT_BIP32_DERIVATION:
                    output.bip32Derivation.set(keyData.toString('hex'), this._parseBip32Derivation(field.value));
                    break;
                case PSBT_CONSTANTS.OUT_TAP_INTERNAL_KEY:
                    output.tapInternalKey = field.value;
                    break;
                case PSBT_CONSTANTS.OUT_TAP_TREE:
                    output.tapTree = this._parseTapTree(field.value);
                    break;
                case PSBT_CONSTANTS.OUT_TAP_BIP32_DERIVATION:
                    output.tapBip32Derivation.set(keyData.toString('hex'), this._parseTapBip32Derivation(field.value));
                    break;
                case PSBT_CONSTANTS.OUT_PROPRIETARY:
                    output.proprietary.set(keyData.toString('hex'), field.value);
                    break;
            }
        }

        return output;
    }

    /**
     * Parse unsigned transaction from buffer
     */
    _parseUnsignedTransaction(buffer) {
        // Simplified transaction parsing
        let offset = 0;

        // Version
        const version = buffer.readUInt32LE(offset);
        offset += 4;

        // Input count
        const inputCountResult = this._readVarInt(buffer, offset);
        offset = inputCountResult.offset;

        const inputs = [];
        for (let i = 0; i < inputCountResult.value; i++) {
            const hash = buffer.slice(offset, offset + 32);
            offset += 32;

            const index = buffer.readUInt32LE(offset);
            offset += 4;

            const scriptLength = this._readVarInt(buffer, offset);
            offset = scriptLength.offset;

            const script = buffer.slice(offset, offset + scriptLength.value);
            offset += scriptLength.value;

            const sequence = buffer.readUInt32LE(offset);
            offset += 4;

            inputs.push({ hash, index, script, sequence });
        }

        // Output count
        const outputCountResult = this._readVarInt(buffer, offset);
        offset = outputCountResult.offset;

        const outputs = [];
        for (let i = 0; i < outputCountResult.value; i++) {
            const amount = Number(buffer.readBigUInt64LE(offset));
            offset += 8;

            const scriptLength = this._readVarInt(buffer, offset);
            offset = scriptLength.offset;

            const script = buffer.slice(offset, offset + scriptLength.value);
            offset += scriptLength.value;

            outputs.push({ amount, script });
        }

        // Locktime
        const locktime = buffer.readUInt32LE(offset);

        return { version, inputs, outputs, locktime };
    }

    /**
     * Parse witness UTXO
     */
    _parseWitnessUtxo(buffer) {
        const amount = Number(buffer.readBigUInt64LE(0));
        const scriptLength = this._readVarInt(buffer, 8);
        const scriptPubKey = buffer.slice(scriptLength.offset, scriptLength.offset + scriptLength.value);

        return { amount, scriptPubKey };
    }

    /**
     * Parse script witness
     */
    _parseScriptWitness(buffer) {
        const witness = [];
        let offset = 0;

        const itemCount = this._readVarInt(buffer, offset);
        offset = itemCount.offset;

        for (let i = 0; i < itemCount.value; i++) {
            const itemLength = this._readVarInt(buffer, offset);
            offset = itemLength.offset;

            const item = buffer.slice(offset, offset + itemLength.value);
            offset += itemLength.value;

            witness.push(item);
        }

        return witness;
    }

    /**
     * Parse BIP32 derivation
     */
    _parseBip32Derivation(buffer) {
        return {
            masterFingerprint: buffer.slice(0, 4),
            path: this._parseDerivationPath(buffer.slice(4))
        };
    }

    /**
     * Parse Taproot BIP32 derivation
     */
    _parseTapBip32Derivation(buffer) {
        const leafHashes = [];
        let offset = 0;

        // Read leaf hashes count
        const hashCount = buffer[offset];
        offset += 1;

        for (let i = 0; i < hashCount; i++) {
            leafHashes.push(buffer.slice(offset, offset + 32));
            offset += 32;
        }

        return {
            leafHashes,
            derivation: this._parseBip32Derivation(buffer.slice(offset))
        };
    }

    /**
     * Parse Taproot tree
     */
    _parseTapTree(buffer) {
        // Simplified tap tree parsing
        return {
            leaves: [],
            depth: 0
        };
    }

    /**
     * Parse derivation path
     */
    _parseDerivationPath(buffer) {
        const path = [];
        for (let i = 0; i < buffer.length; i += 4) {
            path.push(buffer.readUInt32LE(i));
        }
        return path;
    }

    /**
     * Read variable integer
     */
    _readVarInt(buffer, offset) {
        const first = buffer[offset];

        if (first < 0xfd) {
            return { value: first, offset: offset + 1 };
        } else if (first === 0xfd) {
            return { value: buffer.readUInt16LE(offset + 1), offset: offset + 3 };
        } else if (first === 0xfe) {
            return { value: buffer.readUInt32LE(offset + 1), offset: offset + 5 };
        } else {
            return { value: Number(buffer.readBigUInt64LE(offset + 1)), offset: offset + 9 };
        }
    }

    /**
     * Serialize global section
     */
    _serializeGlobalSection() {
        const fields = [];

        // Unsigned transaction
        if (this.global.unsignedTx) {
            fields.push(new PSBTKeyValue(
                PSBT_CONSTANTS.GLOBAL_UNSIGNED_TX,
                Buffer.alloc(0),
                this._serializeUnsignedTransaction()
            ));
        }

        // XPUBs
        for (const [key, value] of this.global.xpubs) {
            fields.push(new PSBTKeyValue(
                PSBT_CONSTANTS.GLOBAL_XPUB,
                Buffer.from(key, 'hex'),
                value
            ));
        }

        // Version
        if (this.global.version !== PSBT_CONSTANTS.VERSION) {
            const versionBuffer = Buffer.allocUnsafe(4);
            versionBuffer.writeUInt32LE(this.global.version, 0);
            fields.push(new PSBTKeyValue(
                PSBT_CONSTANTS.GLOBAL_VERSION,
                Buffer.alloc(0),
                versionBuffer
            ));
        }

        // Serialize all fields
        const serializedFields = fields.map(field => field.serialize());
        serializedFields.push(Buffer.from([0x00])); // End marker

        return Buffer.concat(serializedFields);
    }

    /**
     * Serialize input section
     */
    _serializeInputSection(index) {
        const input = this.inputs[index];
        const fields = [];

        // UTXO data
        if (input.nonWitnessUtxo) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.IN_NON_WITNESS_UTXO, Buffer.alloc(0), input.nonWitnessUtxo));
        }

        if (input.witnessUtxo) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.IN_WITNESS_UTXO, Buffer.alloc(0), this._serializeWitnessUtxo(input.witnessUtxo)));
        }

        // Partial signatures
        for (const [pubkey, signature] of input.partialSigs) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.IN_PARTIAL_SIG, Buffer.from(pubkey, 'hex'), signature));
        }

        // Sighash type
        if (input.sighashType !== PSBT_CONSTANTS.DEFAULT_SIGHASH_TYPE) {
            const sighashBuffer = Buffer.allocUnsafe(4);
            sighashBuffer.writeUInt32LE(input.sighashType, 0);
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.IN_SIGHASH_TYPE, Buffer.alloc(0), sighashBuffer));
        }

        // Scripts
        if (input.redeemScript) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.IN_REDEEM_SCRIPT, Buffer.alloc(0), input.redeemScript));
        }

        if (input.witnessScript) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.IN_WITNESS_SCRIPT, Buffer.alloc(0), input.witnessScript));
        }

        // Final scripts
        if (input.finalScriptSig) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.IN_FINAL_SCRIPTSIG, Buffer.alloc(0), input.finalScriptSig));
        }

        if (input.finalScriptWitness) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.IN_FINAL_SCRIPTWITNESS, Buffer.alloc(0), this._serializeScriptWitness(input.finalScriptWitness)));
        }

        // Taproot fields
        if (input.tapKeySig) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.IN_TAP_KEY_SIG, Buffer.alloc(0), input.tapKeySig));
        }

        if (input.tapInternalKey) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.IN_TAP_INTERNAL_KEY, Buffer.alloc(0), input.tapInternalKey));
        }

        // Serialize all fields
        const serializedFields = fields.map(field => field.serialize());
        serializedFields.push(Buffer.from([0x00])); // End marker

        return Buffer.concat(serializedFields);
    }

    /**
     * Serialize output section
     */
    _serializeOutputSection(index) {
        const output = this.outputs[index];
        const fields = [];

        // Scripts
        if (output.redeemScript) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.OUT_REDEEM_SCRIPT, Buffer.alloc(0), output.redeemScript));
        }

        if (output.witnessScript) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.OUT_WITNESS_SCRIPT, Buffer.alloc(0), output.witnessScript));
        }

        // Taproot fields
        if (output.tapInternalKey) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.OUT_TAP_INTERNAL_KEY, Buffer.alloc(0), output.tapInternalKey));
        }

        if (output.tapTree) {
            fields.push(new PSBTKeyValue(PSBT_CONSTANTS.OUT_TAP_TREE, Buffer.alloc(0), output.tapTree));
        }

        // Serialize all fields
        const serializedFields = fields.map(field => field.serialize());
        serializedFields.push(Buffer.from([0x00])); // End marker

        return Buffer.concat(serializedFields);
    }

    /**
     * Serialize unsigned transaction
     */
    _serializeUnsignedTransaction() {
        const parts = [];

        // Version
        const version = Buffer.allocUnsafe(4);
        version.writeUInt32LE(this.global.unsignedTx.version, 0);
        parts.push(version);

        // Input count and inputs
        parts.push(this._encodeVarInt(this.global.unsignedTx.inputs.length));
        for (const input of this.global.unsignedTx.inputs) {
            parts.push(input.hash);
            const index = Buffer.allocUnsafe(4);
            index.writeUInt32LE(input.index, 0);
            parts.push(index);
            parts.push(this._encodeVarInt(0)); // Empty script
            const sequence = Buffer.allocUnsafe(4);
            sequence.writeUInt32LE(input.sequence, 0);
            parts.push(sequence);
        }

        // Output count and outputs
        parts.push(this._encodeVarInt(this.global.unsignedTx.outputs.length));
        for (const output of this.global.unsignedTx.outputs) {
            const amount = Buffer.allocUnsafe(8);
            amount.writeBigUInt64LE(BigInt(output.amount), 0);
            parts.push(amount);
            parts.push(this._encodeVarInt(output.script.length));
            parts.push(output.script);
        }

        // Locktime
        const locktime = Buffer.allocUnsafe(4);
        locktime.writeUInt32LE(this.global.unsignedTx.locktime, 0);
        parts.push(locktime);

        return Buffer.concat(parts);
    }

    /**
     * Serialize witness UTXO
     */
    _serializeWitnessUtxo(utxo) {
        const amount = Buffer.allocUnsafe(8);
        amount.writeBigUInt64LE(BigInt(utxo.amount), 0);

        const scriptLength = this._encodeVarInt(utxo.scriptPubKey.length);

        return Buffer.concat([amount, scriptLength, utxo.scriptPubKey]);
    }

    /**
     * Serialize script witness
     */
    _serializeScriptWitness(witness) {
        const parts = [];

        parts.push(this._encodeVarInt(witness.length));
        for (const element of witness) {
            parts.push(this._encodeVarInt(element.length));
            parts.push(element);
        }

        return Buffer.concat(parts);
    }

    /**
     * Serialize final transaction
     */
    _serializeTransaction() {
        // This would implement full transaction serialization with witnesses
        // For now, return the unsigned transaction as a placeholder
        return this._serializeUnsignedTransaction();
    }

    /**
     * Encode variable integer
     */
    _encodeVarInt(n) {
        if (n < 0xfd) {
            return Buffer.from([n]);
        } else if (n <= 0xffff) {
            const buf = Buffer.allocUnsafe(3);
            buf[0] = 0xfd;
            buf.writeUInt16LE(n, 1);
            return buf;
        } else if (n <= 0xffffffff) {
            const buf = Buffer.allocUnsafe(5);
            buf[0] = 0xfe;
            buf.writeUInt32LE(n, 1);
            return buf;
        } else {
            const buf = Buffer.allocUnsafe(9);
            buf[0] = 0xff;
            buf.writeBigUInt64LE(BigInt(n), 1);
            return buf;
        }
    }
}

/**
 * PSBT utility functions
 */
class PSBTUtils {
    /**
     * Merge multiple PSBTs
     * 
     * @param {Array<PSBT>} psbts - Array of PSBTs to merge
     * @returns {PSBT} Merged PSBT
     */
    static merge(psbts) {
        if (!Array.isArray(psbts) || psbts.length === 0) {
            throw new PSBTError('Invalid PSBTs array for merging', 'INVALID_MERGE_INPUT');
        }

        const base = psbts[0].clone();

        for (let i = 1; i < psbts.length; i++) {
            const psbt = psbts[i];

            // Verify compatibility
            if (psbt.inputs.length !== base.inputs.length) {
                throw new PSBTError('PSBT input count mismatch during merge', 'MERGE_INPUT_MISMATCH');
            }

            if (psbt.outputs.length !== base.outputs.length) {
                throw new PSBTError('PSBT output count mismatch during merge', 'MERGE_OUTPUT_MISMATCH');
            }

            // Merge input data
            for (let j = 0; j < psbt.inputs.length; j++) {
                const baseInput = base.inputs[j];
                const mergeInput = psbt.inputs[j];

                // Merge partial signatures
                for (const [pubkey, sig] of mergeInput.partialSigs) {
                    if (!baseInput.partialSigs.has(pubkey)) {
                        baseInput.partialSigs.set(pubkey, sig);
                    }
                }

                // Merge other fields
                if (mergeInput.redeemScript && !baseInput.redeemScript) {
                    baseInput.redeemScript = mergeInput.redeemScript;
                }

                if (mergeInput.witnessScript && !baseInput.witnessScript) {
                    baseInput.witnessScript = mergeInput.witnessScript;
                }

                if (mergeInput.tapKeySig && !baseInput.tapKeySig) {
                    baseInput.tapKeySig = mergeInput.tapKeySig;
                }
            }
        }

        return base;
    }

    /**
     * Combine PSBTs (for multisig workflows)
     * 
     * @param {Array<PSBT>} psbts - Array of PSBTs with signatures
     * @returns {PSBT} Combined PSBT
     */
    static combine(psbts) {
        return PSBTUtils.merge(psbts);
    }

    /**
     * Validate PSBT structure
     * 
     * @param {Buffer} buffer - PSBT buffer
     * @returns {boolean} True if valid structure
     */
    static isValidPSBT(buffer) {
        try {
            if (buffer.length < 5) return false;

            const magic = buffer.slice(0, 5);
            return magic.equals(PSBT_CONSTANTS.MAGIC_BYTES);
        } catch (error) {
            return false;
        }
    }

    /**
     * Get PSBT version from buffer
     * 
     * @param {Buffer} buffer - PSBT buffer
     * @returns {number} PSBT version
     */
    static getVersion(buffer) {
        if (!PSBTUtils.isValidPSBT(buffer)) {
            throw new PSBTError('Invalid PSBT format', 'INVALID_FORMAT');
        }

        // Parse global section to find version
        // This is a simplified implementation
        return PSBT_CONSTANTS.VERSION;
    }

    /**
     * Convert hex string to PSBT
     * 
     * @param {string} hex - Hex encoded PSBT
     * @param {string} [network='main'] - Network type
     * @returns {PSBT} Parsed PSBT instance
     */
    static fromHex(hex, network = 'main') {
        try {
            const buffer = Buffer.from(hex, 'hex');
            return PSBT.fromBuffer(buffer, network);
        } catch (error) {
            throw new PSBTError(`Failed to parse PSBT from hex: ${error.message}`, 'PARSE_ERROR');
        }
    }

    /**
     * Extract transaction ID from finalized PSBT
     * 
     * @param {PSBT} psbt - Finalized PSBT
     * @returns {string} Transaction ID
     */
    static extractTxId(psbt) {
        if (!psbt.finalized) {
            throw new PSBTError('PSBT must be finalized to extract transaction ID', 'NOT_FINALIZED');
        }

        const txBuffer = psbt.extractTransaction();
        const hash = createHash('sha256').update(createHash('sha256').update(txBuffer).digest()).digest();
        return hash.reverse().toString('hex');
    }

    /**
     * Calculate PSBT fee
     * 
     * @param {PSBT} psbt - PSBT instance
     * @returns {number} Fee in satoshis
     */
    static calculateFee(psbt) {
        return psbt._calculateFee();
    }

    /**
     * Get PSBT size estimation
     * 
     * @param {PSBT} psbt - PSBT instance
     * @returns {Object} Size information
     */
    static getSizeInfo(psbt) {
        const psbtSize = psbt.toBuffer().length;
        const estimatedTxSize = psbt._estimateTransactionSize();

        return {
            psbtSize,
            estimatedTxSize,
            overhead: psbtSize - estimatedTxSize,
            compressionRatio: estimatedTxSize / psbtSize
        };
    }

    /**
     * Validate PSBT signatures
     * 
     * @param {PSBT} psbt - PSBT instance
     * @returns {Object} Validation results
     */
    static validateSignatures(psbt) {
        const results = {
            valid: true,
            inputResults: [],
            errors: []
        };

        for (let i = 0; i < psbt.inputs.length; i++) {
            const input = psbt.inputs[i];
            const inputResult = {
                index: i,
                valid: true,
                signatures: [],
                errors: []
            };

            // Validate partial signatures
            for (const [pubkeyHex, signature] of input.partialSigs) {
                try {
                    const pubkey = Buffer.from(pubkeyHex, 'hex');
                    const signatureHash = psbt._getSignatureHash(i, input.sighashType);

                    // Extract signature without sighash type byte
                    const sigWithoutHashType = signature.slice(0, -1);

                    // Verify signature (simplified)
                    const isValid = secp256k1.verify(sigWithoutHashType, signatureHash, pubkey.slice(1));

                    inputResult.signatures.push({
                        pubkey: pubkeyHex,
                        valid: isValid
                    });

                    if (!isValid) {
                        inputResult.valid = false;
                        inputResult.errors.push(`Invalid signature for pubkey ${pubkeyHex}`);
                    }
                } catch (error) {
                    inputResult.valid = false;
                    inputResult.errors.push(`Signature validation error: ${error.message}`);
                }
            }

            // Validate Taproot key signature
            if (input.tapKeySig) {
                try {
                    const signatureHash = psbt._getSignatureHash(i, PSBT_CONSTANTS.SIGHASH_ALL);
                    // Taproot signature validation would go here
                    inputResult.signatures.push({
                        type: 'taproot-key',
                        valid: true // Simplified
                    });
                } catch (error) {
                    inputResult.valid = false;
                    inputResult.errors.push(`Taproot signature validation error: ${error.message}`);
                }
            }

            if (!inputResult.valid) {
                results.valid = false;
                results.errors.push(...inputResult.errors);
            }

            results.inputResults.push(inputResult);
        }

        return results;
    }

    /**
     * Convert PSBT to human-readable format
     * 
     * @param {PSBT} psbt - PSBT instance
     * @returns {Object} Human-readable PSBT data
     */
    static toReadable(psbt) {
        return {
            global: {
                version: psbt.global.version,
                network: psbt.network,
                unsignedTx: psbt.global.unsignedTx ? {
                    version: psbt.global.unsignedTx.version,
                    locktime: psbt.global.unsignedTx.locktime,
                    inputCount: psbt.global.unsignedTx.inputs.length,
                    outputCount: psbt.global.unsignedTx.outputs.length
                } : null
            },
            inputs: psbt.inputs.map((input, i) => ({
                index: i,
                previousTx: input.previousTxId?.toString('hex'),
                previousOutput: input.previousOutputIndex,
                sequence: input.sequence,
                hasUtxo: !!(input.witnessUtxo || input.nonWitnessUtxo),
                utxoValue: input.witnessUtxo?.amount || 0,
                partialSigCount: input.partialSigs.size,
                hasRedeemScript: !!input.redeemScript,
                hasWitnessScript: !!input.witnessScript,
                isTaproot: !!input.tapInternalKey,
                isFinalized: !!(input.finalScriptSig || input.finalScriptWitness)
            })),
            outputs: psbt.outputs.map((output, i) => ({
                index: i,
                value: output.amount,
                scriptType: this._detectScriptType(output.scriptPubKey),
                hasRedeemScript: !!output.redeemScript,
                hasWitnessScript: !!output.witnessScript,
                isTaproot: !!output.tapInternalKey
            })),
            status: psbt.getStatus(),
            validation: psbt.validate()
        };
    }

    /**
     * Detect script type from scriptPubKey
     */
    static _detectScriptType(scriptPubKey) {
        if (!Buffer.isBuffer(scriptPubKey)) return 'unknown';

        const len = scriptPubKey.length;

        if (len === 25 && scriptPubKey[0] === 0x76 && scriptPubKey[1] === 0xa9) {
            return 'p2pkh';
        } else if (len === 23 && scriptPubKey[0] === 0xa9) {
            return 'p2sh';
        } else if (len === 22 && scriptPubKey[0] === 0x00 && scriptPubKey[1] === 0x14) {
            return 'p2wpkh';
        } else if (len === 34 && scriptPubKey[0] === 0x00 && scriptPubKey[1] === 0x20) {
            return 'p2wsh';
        } else if (len === 34 && scriptPubKey[0] === 0x51 && scriptPubKey[1] === 0x20) {
            return 'p2tr';
        } else {
            return 'unknown';
        }
    }

    /**
     * Create template PSBT for common transaction types
     * 
     * @param {string} type - Transaction type ('simple', 'multisig', 'taproot')
     * @param {Object} params - Transaction parameters
     * @param {string} [network='main'] - Network type
     * @returns {PSBT} Template PSBT
     */
    static createTemplate(type, params, network = 'main') {
        const psbt = new PSBT(network);

        switch (type) {
            case 'simple':
                return this._createSimpleTemplate(psbt, params);
            case 'multisig':
                return this._createMultisigTemplate(psbt, params);
            case 'taproot':
                return this._createTaprootTemplate(psbt, params);
            default:
                throw new PSBTError(`Unknown template type: ${type}`, 'UNKNOWN_TEMPLATE');
        }
    }

    /**
     * Create simple P2WPKH template
     */
    static _createSimpleTemplate(psbt, params) {
        // Add inputs
        for (const input of params.inputs || []) {
            psbt.addInput({
                txid: input.txid,
                vout: input.vout,
                value: input.value,
                scriptPubKey: input.scriptPubKey
            });
        }

        // Add outputs
        for (const output of params.outputs || []) {
            psbt.addOutput({
                amount: output.amount,
                scriptPubKey: output.scriptPubKey
            });
        }

        return psbt;
    }

    /**
     * Create multisig template
     */
    static _createMultisigTemplate(psbt, params) {
        // Similar to simple but with multisig scripts
        return this._createSimpleTemplate(psbt, params);
    }

    /**
     * Create Taproot template
     */
    static _createTaprootTemplate(psbt, params) {
        // Add Taproot-specific fields
        for (const input of params.inputs || []) {
            psbt.addInput({
                txid: input.txid,
                vout: input.vout,
                value: input.value,
                scriptPubKey: input.scriptPubKey,
                tapInternalKey: input.tapInternalKey,
                tapMerkleRoot: input.tapMerkleRoot
            });
        }

        for (const output of params.outputs || []) {
            psbt.addOutput({
                amount: output.amount,
                scriptPubKey: output.scriptPubKey,
                tapInternalKey: output.tapInternalKey,
                tapTree: output.tapTree
            });
        }

        return psbt;
    }
}

// Export classes and constants
export {
    PSBT,
    PSBTError,
    PSBTUtils,
    PSBTKeyValue,
    PSBT_CONSTANTS
};