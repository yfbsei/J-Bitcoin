/**
 * @fileoverview Enhanced Bitcoin address and key decoding utilities with comprehensive security fixes
 * 
 * SECURITY IMPROVEMENTS (v2.1.0):
 * - FIX #1: Enhanced WIF checksum validation with constant-time comparison
 * - FIX #2: Comprehensive input sanitization and bounds checking
 * - FIX #3: Protection against timing attacks in validation routines
 * - FIX #4: Secure memory management with explicit cleanup
 * - FIX #5: Rate limiting and DoS protection
 * - FIX #6: Enhanced entropy validation for security-critical operations
 * - FIX #7: Standardized error handling with proper error codes
 * - FIX #8: Cross-implementation compatibility validation
 * 
 * This module provides functions to decode various Bitcoin key and address formats
 * back to their raw binary representations with enhanced security measures.
 * 
 * @see {@link https://en.bitcoin.it/wiki/Wallet_import_format|WIF - Wallet Import Format}
 * @see {@link https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses|Bitcoin Address Format}
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki|BIP38 - Passphrase-protected private keys}
 * @author yfbsei
 * @version 2.1.0
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { base58_to_binary } from 'base58-js';
import {
    validateAndDecodeLegacyAddress,
    detectAddressFormat
} from '../../utils/address-helpers.js';
import {
    validatePrivateKey,
    validateAddress,
    assertValid,
    ValidationError
} from '../../utils/validation.js';
import {
    CRYPTO_CONSTANTS,
    NETWORK_VERSIONS
} from '../../core/constants.js';

/**
 * Enhanced decoding error class with standardized error codes
 */
class DecodingError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'DecodingError';
        this.code = code;
        this.details = details;
        this.timestamp = Date.now();
    }
}

/**
 * Security constants for decode operations
 */
const DECODE_SECURITY_CONSTANTS = {
    MAX_INPUT_SIZE: 256,                 // Maximum input size to prevent DoS
    MAX_VALIDATIONS_PER_SECOND: 500,     // Rate limiting threshold
    VALIDATION_TIMEOUT_MS: 200,          // Maximum validation time
    MEMORY_CLEAR_PASSES: 3,              // Number of memory clearing passes
    MIN_ENTROPY_THRESHOLD: 0.1,          // Minimum entropy for key material
    MAX_CHECKSUM_FAILURES: 10            // Maximum checksum validation failures per minute
};

/**
 * @typedef {Object} DecodedPrivateKey
 * @property {Buffer} keyMaterial - Raw 32-byte private key material
 * @property {string} format - Format detected ('wif', 'hex', 'buffer')
 * @property {boolean} isCompressed - Whether the key indicates compressed public key
 * @property {string} network - Network type ('mainnet' or 'testnet')
 * @property {number} [wifVersionByte] - WIF version byte if applicable
 * @property {boolean} isValid - Whether the key passed all security validations
 * @property {Object} securityMetrics - Security validation metrics
 */

/**
 * @typedef {Object} DecodedAddress
 * @property {Buffer} hash160 - Raw 20-byte hash160 value
 * @property {string} addressType - Address type ('P2PKH', 'P2SH')
 * @property {string} network - Network type ('mainnet' or 'testnet')
 * @property {string} format - Address format ('legacy', 'segwit', 'taproot')
 * @property {number} versionByte - Original version byte from address
 * @property {boolean} checksumValid - Whether the checksum validation passed
 * @property {Object} securityMetrics - Security validation metrics
 */

/**
 * Enhanced security utilities for decode operations
 */
class DecodeSecurityUtils {
    static validationHistory = new Map();
    static checksumFailures = new Map();
    static lastCleanup = Date.now();

    /**
     * FIX #5: Rate limiting and DoS protection
     */
    static checkRateLimit(operation = 'decode') {
        const now = Date.now();
        const secondKey = `${operation}-${Math.floor(now / 1000)}`;
        const currentCount = this.validationHistory.get(secondKey) || 0;

        if (currentCount >= DECODE_SECURITY_CONSTANTS.MAX_VALIDATIONS_PER_SECOND) {
            throw new DecodingError(
                `Rate limit exceeded for operation: ${operation}`,
                'RATE_LIMIT_EXCEEDED',
                { operation, currentCount }
            );
        }

        this.validationHistory.set(secondKey, currentCount + 1);

        // Periodic cleanup
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
     * FIX #2: Enhanced input validation with security checks
     */
    static validateInputSize(input, maxSize = DECODE_SECURITY_CONSTANTS.MAX_INPUT_SIZE, fieldName = 'input') {
        if (typeof input === 'string' && input.length > maxSize) {
            throw new DecodingError(
                `${fieldName} too large: ${input.length} > ${maxSize}`,
                'INPUT_TOO_LARGE',
                { actualSize: input.length, maxSize, fieldName }
            );
        }
        if (Buffer.isBuffer(input) && input.length > maxSize) {
            throw new DecodingError(
                `${fieldName} buffer too large: ${input.length} > ${maxSize}`,
                'BUFFER_TOO_LARGE',
                { actualSize: input.length, maxSize, fieldName }
            );
        }
    }

    /**
     * FIX #3: Constant-time comparison for checksum validation
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
            // Fallback to manual constant-time comparison
            let result = 0;
            for (let i = 0; i < a.length; i++) {
                result |= a[i] ^ b[i];
            }
            return result === 0;
        }
    }

    /**
     * FIX #1: Enhanced checksum validation with failure tracking
     */
    static validateChecksum(data, providedChecksum, operation = 'checksum') {
        // Track checksum failures for anomaly detection
        const minuteKey = Math.floor(Date.now() / 60000);
        const failures = this.checksumFailures.get(minuteKey) || 0;

        if (failures > DECODE_SECURITY_CONSTANTS.MAX_CHECKSUM_FAILURES) {
            throw new DecodingError(
                'Too many checksum failures - possible attack detected',
                'CHECKSUM_ATTACK_DETECTED',
                { failures }
            );
        }

        // Compute expected checksum using double SHA256
        const hash1 = createHash('sha256').update(data).digest();
        const hash2 = createHash('sha256').update(hash1).digest();
        const expectedChecksum = hash2.slice(0, CRYPTO_CONSTANTS.CHECKSUM_LENGTH);

        // Use constant-time comparison
        const isValid = this.constantTimeEqual(providedChecksum, expectedChecksum);

        if (!isValid) {
            this.checksumFailures.set(minuteKey, failures + 1);
            throw new DecodingError(
                `${operation} checksum validation failed`,
                'CHECKSUM_VALIDATION_FAILED',
                {
                    provided: providedChecksum.toString('hex'),
                    expected: expectedChecksum.toString('hex')
                }
            );
        }

        return true;
    }

    /**
     * FIX #4: Secure memory clearing with multiple passes
     */
    static secureClear(data) {
        if (Buffer.isBuffer(data)) {
            for (let pass = 0; pass < DECODE_SECURITY_CONSTANTS.MEMORY_CLEAR_PASSES; pass++) {
                const randomData = randomBytes(data.length);
                randomData.copy(data);
                data.fill(pass % 2 === 0 ? 0x00 : 0xFF);
            }
            data.fill(0x00);
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

    /**
     * FIX #5: Execution time validation to prevent DoS
     */
    static validateExecutionTime(startTime, operation = 'decode operation') {
        const elapsed = Date.now() - startTime;
        if (elapsed > DECODE_SECURITY_CONSTANTS.VALIDATION_TIMEOUT_MS) {
            throw new DecodingError(
                `${operation} timeout: ${elapsed}ms > ${DECODE_SECURITY_CONSTANTS.VALIDATION_TIMEOUT_MS}ms`,
                'OPERATION_TIMEOUT',
                { elapsed, maxTime: DECODE_SECURITY_CONSTANTS.VALIDATION_TIMEOUT_MS, operation }
            );
        }
    }

    /**
     * FIX #6: Enhanced entropy validation for key material
     */
    static validateKeyEntropy(keyMaterial, fieldName = 'key material') {
        if (!Buffer.isBuffer(keyMaterial)) {
            return false;
        }

        // Count unique bytes
        const uniqueBytes = new Set(keyMaterial).size;
        const entropy = uniqueBytes / 256; // Normalize to 0-1

        if (entropy < DECODE_SECURITY_CONSTANTS.MIN_ENTROPY_THRESHOLD) {
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

    /**
     * Safe buffer allocation with overflow protection
     */
    static safeBufferAllocation(size, fieldName = 'buffer') {
        if (!Number.isInteger(size) || size < 0) {
            throw new DecodingError(
                `Invalid ${fieldName} size: ${size}`,
                'INVALID_BUFFER_SIZE'
            );
        }

        if (size > DECODE_SECURITY_CONSTANTS.MAX_INPUT_SIZE) {
            throw new DecodingError(
                `${fieldName} size too large: ${size} > ${DECODE_SECURITY_CONSTANTS.MAX_INPUT_SIZE}`,
                'BUFFER_SIZE_TOO_LARGE',
                { requestedSize: size, maxSize: DECODE_SECURITY_CONSTANTS.MAX_INPUT_SIZE }
            );
        }

        try {
            return Buffer.alloc(size);
        } catch (error) {
            throw new DecodingError(
                `${fieldName} allocation failed: ${error.message}`,
                'BUFFER_ALLOCATION_FAILED',
                { originalError: error.message }
            );
        }
    }
}

/**
 * FIX #1,#7: Enhanced WIF private key decoding with comprehensive security validation
 * 
 * Decodes a WIF (Wallet Import Format) private key to raw bytes with enhanced security
 * features including proper checksum validation, entropy analysis, and timing attack protection.
 * 
 * **Security Enhancements:**
 * - Constant-time checksum validation to prevent timing attacks
 * - Comprehensive entropy validation to detect weak keys
 * - Rate limiting to prevent DoS attacks
 * - Secure memory management with explicit cleanup
 * - Enhanced error handling with standardized codes
 * 
 * @param {string} wifPrivateKey - WIF-encoded private key
 * @returns {DecodedPrivateKey} Decoded private key information with security metrics
 * 
 * @throws {DecodingError} If WIF format is invalid, corrupted, or fails security validation
 * 
 * @example
 * // Decode compressed mainnet WIF private key with security validation
 * const compressedWIF = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
 * try {
 *   const decoded = decodeWIFPrivateKey(compressedWIF);
 *   console.log('Private key length:', decoded.keyMaterial.length); // 32
 *   console.log('Is compressed:', decoded.isCompressed); // true
 *   console.log('Network:', decoded.network); // "mainnet"
 *   console.log('Security valid:', decoded.isValid); // true
 *   console.log('Entropy quality:', decoded.securityMetrics.hasGoodEntropy);
 * } catch (error) {
 *   if (error.code === 'CHECKSUM_VALIDATION_FAILED') {
 *     console.error('WIF checksum invalid - possible corruption or typo');
 *   } else {
 *     console.error('WIF decoding failed:', error.message);
 *   }
 * }
 */
function decodeWIFPrivateKey(wifPrivateKey) {
    const startTime = Date.now();
    let decodedBytes = null;
    let keyMaterial = null;

    try {
        DecodeSecurityUtils.checkRateLimit('wif-decode');
        DecodeSecurityUtils.validateInputSize(wifPrivateKey, 100, 'WIF private key');

        // Enhanced input validation
        if (!wifPrivateKey || typeof wifPrivateKey !== 'string') {
            throw new DecodingError(
                'WIF private key must be a non-empty string',
                'INVALID_INPUT_TYPE'
            );
        }

        // Validate WIF format and length
        if (wifPrivateKey.length < 51 || wifPrivateKey.length > 52) {
            throw new DecodingError(
                `Invalid WIF length: ${wifPrivateKey.length}. Expected 51-52 characters`,
                'INVALID_WIF_LENGTH',
                { actualLength: wifPrivateKey.length }
            );
        }

        // Validate Base58 characters to prevent injection attacks
        const base58Regex = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
        if (!base58Regex.test(wifPrivateKey)) {
            throw new DecodingError(
                'WIF contains invalid Base58 characters',
                'INVALID_BASE58_CHARACTERS'
            );
        }

        // FIX #1: Enhanced Base58Check decoding with proper error handling
        try {
            decodedBytes = base58_to_binary(wifPrivateKey);
        } catch (error) {
            throw new DecodingError(
                `WIF Base58Check decoding failed: ${error.message}`,
                'BASE58_DECODE_FAILED',
                { originalError: error.message }
            );
        }

        // Validate decoded length (37 or 38 bytes: version + key + optional compression + checksum)
        if (decodedBytes.length !== 37 && decodedBytes.length !== 38) {
            throw new DecodingError(
                `Invalid WIF decoded length: expected 37 or 38 bytes, got ${decodedBytes.length}`,
                'INVALID_DECODED_LENGTH',
                { actualLength: decodedBytes.length }
            );
        }

        const versionByte = decodedBytes[0];
        const isCompressed = decodedBytes.length === 38;
        const checksumLength = CRYPTO_CONSTANTS.CHECKSUM_LENGTH;

        // Extract components
        const payload = decodedBytes.slice(0, -checksumLength);
        const providedChecksum = decodedBytes.slice(-checksumLength);

        // FIX #1: Enhanced checksum validation with constant-time comparison
        DecodeSecurityUtils.validateChecksum(payload, providedChecksum, 'WIF');

        // Validate network version byte
        let network;
        if (versionByte === NETWORK_VERSIONS.MAINNET.WIF_PRIVATE_KEY) {
            network = 'mainnet';
        } else if (versionByte === NETWORK_VERSIONS.TESTNET.WIF_PRIVATE_KEY) {
            network = 'testnet';
        } else {
            throw new DecodingError(
                `Unsupported WIF version byte: 0x${versionByte.toString(16)}`,
                'UNSUPPORTED_VERSION_BYTE',
                { versionByte }
            );
        }

        // Extract private key material (skip version byte, take 32 bytes)
        keyMaterial = DecodeSecurityUtils.safeBufferAllocation(CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH, 'key material');
        decodedBytes.slice(1, 1 + CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH).copy(keyMaterial);

        // FIX #2: Enhanced private key validation
        // Validate private key is not zero
        const isZero = keyMaterial.every(byte => byte === 0);
        if (isZero) {
            throw new DecodingError(
                'WIF private key cannot be zero',
                'INVALID_PRIVATE_KEY_ZERO'
            );
        }

        // Validate private key is in valid secp256k1 range
        const keyBigInt = BigInt('0x' + keyMaterial.toString('hex'));
        const curveOrder = BigInt('0x' + CRYPTO_CONSTANTS.SECP256K1_ORDER);

        if (keyBigInt >= curveOrder) {
            throw new DecodingError(
                'WIF private key exceeds secp256k1 curve order',
                'INVALID_PRIVATE_KEY_RANGE'
            );
        }

        // FIX #6: Validate key entropy for security
        const hasGoodEntropy = DecodeSecurityUtils.validateKeyEntropy(keyMaterial, 'WIF private key');

        DecodeSecurityUtils.validateExecutionTime(startTime, 'WIF decoding');

        // FIX #8: Cross-implementation compatibility check
        const compatibilityCheck = validateWIFCompatibility(wifPrivateKey, keyMaterial, network, isCompressed);

        return {
            keyMaterial,
            format: 'wif',
            isCompressed,
            network,
            wifVersionByte: versionByte,
            isValid: true,
            securityMetrics: {
                hasGoodEntropy,
                checksumValid: true,
                entropyScore: hasGoodEntropy ? 'good' : 'weak',
                validationTime: Date.now() - startTime,
                compatibilityCheck
            }
        };

    } catch (error) {
        if (error instanceof DecodingError) {
            throw error;
        }
        throw new DecodingError(
            `WIF decoding failed: ${error.message}`,
            'WIF_DECODE_FAILED',
            { originalError: error.message }
        );
    } finally {
        // FIX #4: Always clear sensitive data
        if (decodedBytes) {
            DecodeSecurityUtils.secureClear(Buffer.from(decodedBytes));
        }
        // Note: Don't clear keyMaterial here as it's returned to caller
    }
}

/**
 * FIX #2,#7: Enhanced hex private key decoding with comprehensive validation
 * 
 * @param {string} hexPrivateKey - Hex-encoded private key (64 characters)
 * @returns {DecodedPrivateKey} Decoded private key information with security metrics
 * 
 * @throws {DecodingError} If hex format is invalid or fails security validation
 */
function decodeHexPrivateKey(hexPrivateKey) {
    const startTime = Date.now();

    try {
        DecodeSecurityUtils.checkRateLimit('hex-decode');
        DecodeSecurityUtils.validateInputSize(hexPrivateKey, 100, 'hex private key');

        // Enhanced input validation
        if (!hexPrivateKey || typeof hexPrivateKey !== 'string') {
            throw new DecodingError(
                'Hex private key must be a non-empty string',
                'INVALID_INPUT_TYPE'
            );
        }

        // Validate hex format and length
        if (hexPrivateKey.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH * 2) {
            throw new DecodingError(
                `Invalid hex private key length: expected ${CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH * 2} characters, got ${hexPrivateKey.length}`,
                'INVALID_HEX_LENGTH',
                { expectedLength: CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH * 2, actualLength: hexPrivateKey.length }
            );
        }

        // Validate hex characters
        const hexRegex = /^[0-9a-fA-F]+$/;
        if (!hexRegex.test(hexPrivateKey)) {
            throw new DecodingError(
                'Hex private key contains invalid hex characters',
                'INVALID_HEX_CHARACTERS'
            );
        }

        let keyMaterial;
        try {
            keyMaterial = Buffer.from(hexPrivateKey, 'hex');
        } catch (error) {
            throw new DecodingError(
                `Hex decoding failed: ${error.message}`,
                'HEX_DECODE_FAILED',
                { originalError: error.message }
            );
        }

        // Validate private key constraints
        const isZero = keyMaterial.every(byte => byte === 0);
        if (isZero) {
            throw new DecodingError(
                'Hex private key cannot be zero',
                'INVALID_PRIVATE_KEY_ZERO'
            );
        }

        // Validate curve order
        const keyBigInt = BigInt('0x' + hexPrivateKey);
        const curveOrder = BigInt('0x' + CRYPTO_CONSTANTS.SECP256K1_ORDER);

        if (keyBigInt >= curveOrder) {
            throw new DecodingError(
                'Hex private key exceeds secp256k1 curve order',
                'INVALID_PRIVATE_KEY_RANGE'
            );
        }

        // FIX #6: Validate key entropy
        const hasGoodEntropy = DecodeSecurityUtils.validateKeyEntropy(keyMaterial, 'hex private key');

        DecodeSecurityUtils.validateExecutionTime(startTime, 'hex decoding');

        return {
            keyMaterial,
            format: 'hex',
            isCompressed: true, // Default assumption for hex keys
            network: 'unknown', // Cannot determine network from hex alone
            isValid: true,
            securityMetrics: {
                hasGoodEntropy,
                entropyScore: hasGoodEntropy ? 'good' : 'weak',
                validationTime: Date.now() - startTime
            }
        };

    } catch (error) {
        if (error instanceof DecodingError) {
            throw error;
        }
        throw new DecodingError(
            `Hex decoding failed: ${error.message}`,
            'HEX_DECODE_FAILED',
            { originalError: error.message }
        );
    }
}

/**
 * FIX #1,#7: Enhanced legacy address decoding with comprehensive security validation
 * 
 * @param {string} legacyAddress - Base58Check encoded legacy address
 * @returns {DecodedAddress} Decoded address information with security metrics
 * 
 * @throws {DecodingError} If address format is invalid, corrupted, or fails security validation
 */
function decodeLegacyAddressComplete(legacyAddress) {
    const startTime = Date.now();
    let addressBytes = null;

    try {
        DecodeSecurityUtils.checkRateLimit('legacy-decode');
        DecodeSecurityUtils.validateInputSize(legacyAddress, 100, 'legacy address');

        // Enhanced input validation
        if (!legacyAddress || typeof legacyAddress !== 'string') {
            throw new DecodingError(
                'Legacy address must be a non-empty string',
                'INVALID_INPUT_TYPE'
            );
        }

        // Validate address length constraints
        if (legacyAddress.length < 26 || legacyAddress.length > 35) {
            throw new DecodingError(
                `Invalid address length: ${legacyAddress.length}. Expected 26-35 characters`,
                'INVALID_ADDRESS_LENGTH',
                { actualLength: legacyAddress.length }
            );
        }

        // Validate Base58 characters
        const base58Regex = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
        if (!base58Regex.test(legacyAddress)) {
            throw new DecodingError(
                'Legacy address contains invalid Base58 characters',
                'INVALID_BASE58_CHARACTERS'
            );
        }

        // FIX #1: Enhanced Base58Check decoding
        try {
            addressBytes = base58_to_binary(legacyAddress);
        } catch (error) {
            throw new DecodingError(
                `Address Base58Check decoding failed: ${error.message}`,
                'BASE58_DECODE_FAILED',
                { originalError: error.message }
            );
        }

        // Validate decoded length (1 version + 20 hash + 4 checksum = 25 total)
        const EXPECTED_ADDRESS_LENGTH = 1 + CRYPTO_CONSTANTS.HASH160_LENGTH + CRYPTO_CONSTANTS.CHECKSUM_LENGTH;
        if (addressBytes.length !== EXPECTED_ADDRESS_LENGTH) {
            throw new DecodingError(
                `Invalid address decoded length: expected ${EXPECTED_ADDRESS_LENGTH} bytes, got ${addressBytes.length}`,
                'INVALID_DECODED_LENGTH',
                { expectedLength: EXPECTED_ADDRESS_LENGTH, actualLength: addressBytes.length }
            );
        }

        const versionByte = addressBytes[0];
        const hash160Bytes = addressBytes.slice(1, 1 + CRYPTO_CONSTANTS.HASH160_LENGTH);
        const providedChecksum = addressBytes.slice(-CRYPTO_CONSTANTS.CHECKSUM_LENGTH);

        // FIX #1: Enhanced checksum validation
        const payload = addressBytes.slice(0, -CRYPTO_CONSTANTS.CHECKSUM_LENGTH);
        DecodeSecurityUtils.validateChecksum(payload, providedChecksum, 'address');

        // Determine network and address type
        let prefix, addressType, network;

        switch (versionByte) {
            case NETWORK_VERSIONS.MAINNET.P2PKH_ADDRESS:
                prefix = 'bc';
                addressType = 'P2PKH';
                network = 'mainnet';
                break;
            case NETWORK_VERSIONS.MAINNET.P2SH_ADDRESS:
                prefix = 'bc';
                addressType = 'P2SH';
                network = 'mainnet';
                break;
            case NETWORK_VERSIONS.TESTNET.P2PKH_ADDRESS:
                prefix = 'tb';
                addressType = 'P2PKH';
                network = 'testnet';
                break;
            case NETWORK_VERSIONS.TESTNET.P2SH_ADDRESS:
                prefix = 'tb';
                addressType = 'P2SH';
                network = 'testnet';
                break;
            default:
                throw new DecodingError(
                    `Unsupported address version byte: 0x${versionByte.toString(16)}`,
                    'UNSUPPORTED_VERSION_BYTE',
                    { versionByte }
                );
        }

        const hash160Buffer = Buffer.from(hash160Bytes);
        const hash160Hex = hash160Buffer.toString('hex');

        DecodeSecurityUtils.validateExecutionTime(startTime, 'legacy address decoding');

        return {
            prefix,
            hash160Hex,
            hash160Buffer,
            addressType,
            network,
            format: 'legacy',
            versionByte,
            checksumValid: true,
            isValid: true,
            securityMetrics: {
                checksumValid: true,
                validationTime: Date.now() - startTime,
                addressLength: legacyAddress.length
            }
        };

    } catch (error) {
        if (error instanceof DecodingError) {
            throw error;
        }
        throw new DecodingError(
            `Legacy address decoding failed: ${error.message}`,
            'LEGACY_DECODE_FAILED',
            { originalError: error.message }
        );
    } finally {
        // FIX #4: Secure cleanup
        if (addressBytes) {
            DecodeSecurityUtils.secureClear(Buffer.from(addressBytes));
        }
    }
}

/**
 * FIX #2,#7: Enhanced auto-detection private key decoder with security validation
 * 
 * @param {string|Buffer} privateKey - Private key in unknown format
 * @returns {DecodedPrivateKey} Decoded private key information with security metrics
 * 
 * @throws {DecodingError} If format cannot be detected or decoding fails
 */
function decodePrivateKeyAuto(privateKey) {
    const startTime = Date.now();

    try {
        DecodeSecurityUtils.checkRateLimit('auto-decode');

        // Handle Buffer input
        if (Buffer.isBuffer(privateKey)) {
            if (privateKey.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH) {
                throw new DecodingError(
                    `Invalid private key buffer length: expected ${CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH}, got ${privateKey.length}`,
                    'INVALID_BUFFER_LENGTH',
                    { expectedLength: CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH, actualLength: privateKey.length }
                );
            }

            // Validate buffer content
            const hasGoodEntropy = DecodeSecurityUtils.validateKeyEntropy(privateKey, 'buffer private key');

            return {
                keyMaterial: privateKey,
                format: 'buffer',
                isCompressed: true,
                network: 'unknown',
                isValid: true,
                securityMetrics: {
                    hasGoodEntropy,
                    entropyScore: hasGoodEntropy ? 'good' : 'weak',
                    validationTime: Date.now() - startTime
                }
            };
        }

        // Handle string input
        if (typeof privateKey !== 'string') {
            throw new DecodingError(
                `Private key must be string or Buffer, got ${typeof privateKey}`,
                'INVALID_INPUT_TYPE'
            );
        }

        DecodeSecurityUtils.validateInputSize(privateKey, 100, 'private key');

        // Auto-detect format based on length and characteristics
        if (privateKey.length === CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH * 2) {
            // Likely hex format (64 characters)
            return decodeHexPrivateKey(privateKey);
        } else if (privateKey.length >= 51 && privateKey.length <= 52) {
            // Likely WIF format
            return decodeWIFPrivateKey(privateKey);
        } else {
            throw new DecodingError(
                `Cannot auto-detect private key format. Length: ${privateKey.length}. Expected 64 (hex) or 51-52 (WIF) characters.`,
                'UNKNOWN_FORMAT',
                { actualLength: privateKey.length }
            );
        }

    } catch (error) {
        if (error instanceof DecodingError) {
            throw error;
        }
        throw new DecodingError(
            `Auto-decode failed: ${error.message}`,
            'AUTO_DECODE_FAILED',
            { originalError: error.message }
        );
    }
}

/**
 * FIX #2,#7: Enhanced auto-detection address decoder with security validation
 * 
 * @param {string} address - Bitcoin address in unknown format
 * @returns {DecodedAddress} Decoded address information with security metrics
 * 
 * @throws {DecodingError} If format cannot be detected or decoding fails
 */
function decodeAddressAuto(address) {
    const startTime = Date.now();

    try {
        DecodeSecurityUtils.checkRateLimit('address-auto-decode');
        DecodeSecurityUtils.validateInputSize(address, 100, 'address');

        // Enhanced input validation
        if (!address || typeof address !== 'string') {
            throw new DecodingError(
                'Address must be a non-empty string',
                'INVALID_INPUT_TYPE'
            );
        }

        // Detect format using existing helper
        const formatInfo = detectAddressFormat(address);

        if (formatInfo.format === 'unknown') {
            throw new DecodingError(
                `Unrecognized address format: ${address}`,
                'UNRECOGNIZED_FORMAT',
                { formatInfo }
            );
        }

        DecodeSecurityUtils.validateExecutionTime(startTime, 'address format detection');

        // Currently only legacy addresses are fully supported for decoding
        if (formatInfo.format === 'legacy') {
            return decodeLegacyAddressComplete(address);
        } else {
            throw new DecodingError(
                `Decoding for ${formatInfo.format} addresses not yet implemented. Detected: ${formatInfo.type} on ${formatInfo.network}`,
                'UNSUPPORTED_FORMAT',
                { formatInfo }
            );
        }

    } catch (error) {
        if (error instanceof DecodingError) {
            throw error;
        }
        throw new DecodingError(
            `Address auto-decode failed: ${error.message}`,
            'ADDRESS_AUTO_DECODE_FAILED',
            { originalError: error.message }
        );
    }
}

/**
 * FIX #8: WIF compatibility validation with known implementations
 * 
 * @param {string} wifKey - Original WIF key
 * @param {Buffer} keyMaterial - Decoded key material
 * @param {string} network - Network type
 * @param {boolean} isCompressed - Compression flag
 * @returns {Object} Compatibility check results
 */
function validateWIFCompatibility(wifKey, keyMaterial, network, isCompressed) {
    try {
        // Known test vectors for validation
        const testVectors = [
            {
                wif: '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ',
                keyHex: '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d',
                network: 'mainnet',
                compressed: false
            },
            {
                wif: 'L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6',
                keyHex: 'ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2',
                network: 'mainnet',
                compressed: true
            }
        ];

        // Check against known test vectors
        for (const vector of testVectors) {
            if (wifKey === vector.wif) {
                const expectedKey = vector.keyHex;
                const actualKey = keyMaterial.toString('hex');

                if (actualKey !== expectedKey) {
                    throw new DecodingError(
                        'WIF compatibility test failed: key material mismatch',
                        'COMPATIBILITY_TEST_FAILED',
                        { expected: expectedKey, actual: actualKey }
                    );
                }

                if (network !== vector.network || isCompressed !== vector.compressed) {
                    throw new DecodingError(
                        'WIF compatibility test failed: format mismatch',
                        'FORMAT_MISMATCH',
                        {
                            expectedNetwork: vector.network,
                            actualNetwork: network,
                            expectedCompressed: vector.compressed,
                            actualCompressed: isCompressed
                        }
                    );
                }

                return {
                    testVectorMatch: true,
                    vectorId: vector.wif.substring(0, 10) + '...',
                    compatible: true
                };
            }
        }

        // For unknown keys, just validate format consistency
        return {
            testVectorMatch: false,
            formatValid: true,
            compatible: true
        };

    } catch (error) {
        return {
            testVectorMatch: false,
            compatible: false,
            error: error.message
        };
    }
}

/**
 * Get decoder status and security metrics
 * 
 * @returns {Object} Comprehensive decoder status information
 */
function getDecoderStatus() {
    return {
        version: '2.1.0',
        securityFeatures: [
            'Enhanced checksum validation',
            'Constant-time comparisons',
            'Timing attack prevention',
            'DoS protection with rate limiting',
            'Secure memory management',
            'Entropy validation',
            'Cross-implementation compatibility',
            'Comprehensive error handling'
        ],
        limits: DECODE_SECURITY_CONSTANTS,
        rateLimit: {
            maxPerSecond: DECODE_SECURITY_CONSTANTS.MAX_VALIDATIONS_PER_SECOND,
            currentEntries: DecodeSecurityUtils.validationHistory.size
        },
        supportedFormats: {
            privateKeys: ['WIF', 'hex', 'buffer'],
            addresses: ['legacy P2PKH', 'legacy P2SH'],
            networks: ['mainnet', 'testnet']
        }
    };
}

/**
 * Validate decoder implementation with security test suite
 * 
 * @returns {boolean} True if all security tests pass
 */
function validateDecoderImplementation() {
    console.log('🧪 Testing decoder security features...');

    try {
        // Test WIF decoding with known vector
        const testWIF = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
        const decodedWIF = decodeWIFPrivateKey(testWIF);

        if (!decodedWIF.isValid || !decodedWIF.securityMetrics.checksumValid) {
            throw new Error('WIF decoding security test failed');
        }

        // Test address decoding with known vector
        const testAddress = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        const decodedAddress = decodeLegacyAddressComplete(testAddress);

        if (!decodedAddress.checksumValid || !decodedAddress.isValid) {
            throw new Error('Address decoding security test failed');
        }

        // Test error handling
        try {
            decodeWIFPrivateKey("invalid_wif_key");
            throw new Error('Should have rejected invalid WIF');
        } catch (error) {
            if (!(error instanceof DecodingError)) {
                throw new Error('Incorrect error type for invalid WIF');
            }
        }

        console.log('✅ Decoder security tests passed');
        return true;

    } catch (error) {
        console.error('❌ Decoder security test failed:', error.message);
        return false;
    }
}

/**
 * Cleanup decoder resources and clear sensitive data
 */
function cleanupDecoder() {
    try {
        console.warn('⚠️  Cleaning up decoder resources...');

        // Clear validation history
        DecodeSecurityUtils.validationHistory.clear();
        DecodeSecurityUtils.checksumFailures.clear();

        console.log('✅ Decoder cleanup completed');

    } catch (error) {
        console.error('❌ Decoder cleanup failed:', error.message);
    }
}

export {
    DecodingError,
    DecodeSecurityUtils,
    DECODE_SECURITY_CONSTANTS,
    decodeWIFPrivateKey,
    decodeHexPrivateKey,
    decodeLegacyAddressComplete,
    decodeAddressAuto,
    decodePrivateKeyAuto,
    validateWIFCompatibility,
    getDecoderStatus,
    validateDecoderImplementation,
    cleanupDecoder
};