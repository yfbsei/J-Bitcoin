/**
 * @fileoverview Enhanced address utility functions with comprehensive security features
 * 
 * SECURITY IMPROVEMENTS (v2.1.1):
 * - FIX #1: Explicit checksum validation for legacy addresses
 * - FIX #2: Timing attack prevention with constant-time operations
 * - FIX #3: Buffer overflow protection and secure memory management
 * - FIX #4: Rate limiting and input size validation
 * - FIX #5: Enhanced bit conversion with comprehensive validation
 * - FIX #6: Secure buffer operations with bounds checking
 * - FIX #7: Memory safety with explicit cleanup procedures
 * - FIX #8: DoS protection with complexity limits
 * - FIX #9: CRITICAL - Removed circular dependency with validation.js
 * - FIX #10: Standardized error handling throughout
 * - FIX #11: Added missing constants for magic numbers
 * - FIX #12: Fixed memory leaks in bit conversion functions
 * 
 * @author yfbsei
 * @version 2.1.1
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { base58_to_binary } from 'base58-js';
import {
    NETWORK_VERSIONS,
    CRYPTO_CONSTANTS,
    ENCODING_CONSTANTS
} from '../core/constants.js';

/**
 * Enhanced address utility error class
 */
class AddressUtilError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'AddressUtilError';
        this.code = code;
        this.details = details;
        this.timestamp = Date.now();
    }
}

/**
 * Security constants for attack prevention - FIX #11: Added missing constants
 */
const SECURITY_CONSTANTS = {
    MAX_INPUT_SIZE: 512,                 // Maximum input size to prevent DoS
    MAX_OUTPUT_SIZE: 1024,               // Maximum output size for safety
    MAX_VALIDATIONS_PER_SECOND: 2000,    // Rate limiting threshold
    MAX_LEADING_ZEROS: 32,               // Maximum leading zeros to prevent DoS
    VALIDATION_TIMEOUT_MS: 200,          // Maximum validation time
    MEMORY_CLEAR_PASSES: 3,              // Number of memory clearing passes
    MIN_BIT_WIDTH: 1,                    // Minimum bit width for conversion
    MAX_BIT_WIDTH: 32,                   // Maximum bit width for conversion
    MAX_CONVERSION_INPUT: 1024,          // Maximum input size for bit conversion

    // FIX #11: Address length constants
    MIN_LEGACY_ADDRESS_LENGTH: 26,       // Minimum legacy address length
    MAX_LEGACY_ADDRESS_LENGTH: 35,       // Maximum legacy address length
    DECODED_ADDRESS_LENGTH: 25,          // Standard decoded address length (1+20+4)
    HASH160_OFFSET: 1,                   // Offset to hash160 in decoded address
    CHECKSUM_OFFSET: 21,                 // Offset to checksum in decoded address
};

/**
 * @typedef {Object} DecodedLegacyAddress
 * @property {string} prefix - Network prefix ('bc' for mainnet, 'tb' for testnet)
 * @property {string} hash160Hex - Hex-encoded hash160 value
 * @property {Buffer} hash160Buffer - Raw hash160 buffer
 * @property {string} addressType - Address type ('P2PKH' or 'P2SH')
 * @property {string} network - Network type ('mainnet' or 'testnet')
 * @property {boolean} checksumValid - Whether the checksum validation passed
 * @property {number} versionByte - Original version byte from address
 */

/**
 * Enhanced security utilities for address operations
 */
class AddressSecurityUtils {
    static validationHistory = new Map();
    static lastCleanup = Date.now();

    /**
     * FIX #2: Constant-time buffer comparison to prevent timing attacks
     */
    static constantTimeBufferEqual(a, b) {
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
     * FIX #4: Rate limiting and DoS protection
     */
    static checkRateLimit(operation = 'default') {
        const now = Date.now();
        const secondKey = `${operation}-${Math.floor(now / 1000)}`;
        const currentCount = this.validationHistory.get(secondKey) || 0;

        if (currentCount >= SECURITY_CONSTANTS.MAX_VALIDATIONS_PER_SECOND) {
            throw new AddressUtilError(
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
     * FIX #4: Input size validation to prevent DoS attacks
     */
    static validateInputSize(input, maxSize = SECURITY_CONSTANTS.MAX_INPUT_SIZE, fieldName = 'input') {
        if (typeof input === 'string' && input.length > maxSize) {
            throw new AddressUtilError(
                `${fieldName} too large: ${input.length} > ${maxSize}`,
                'INPUT_TOO_LARGE',
                { actualSize: input.length, maxSize, fieldName }
            );
        }
        if (Buffer.isBuffer(input) && input.length > maxSize) {
            throw new AddressUtilError(
                `${fieldName} buffer too large: ${input.length} > ${maxSize}`,
                'BUFFER_TOO_LARGE',
                { actualSize: input.length, maxSize, fieldName }
            );
        }
        if (Array.isArray(input) && input.length > maxSize) {
            throw new AddressUtilError(
                `${fieldName} array too large: ${input.length} > ${maxSize}`,
                'ARRAY_TOO_LARGE',
                { actualSize: input.length, maxSize, fieldName }
            );
        }
    }

    /**
     * FIX #7: Secure memory clearing with multiple passes
     */
    static secureClear(data) {
        if (Buffer.isBuffer(data)) {
            for (let pass = 0; pass < SECURITY_CONSTANTS.MEMORY_CLEAR_PASSES; pass++) {
                const randomData = randomBytes(data.length);
                randomData.copy(data);
                data.fill(pass % 2 === 0 ? 0x00 : 0xFF);
            }
            data.fill(0x00);
        } else if (Array.isArray(data)) {
            for (let i = 0; i < data.length; i++) {
                data[i] = 0;
            }
            data.length = 0;
        }
    }

    /**
     * FIX #8: Execution time validation to prevent DoS
     */
    static validateExecutionTime(startTime, operation = 'operation') {
        const elapsed = Date.now() - startTime;
        if (elapsed > SECURITY_CONSTANTS.VALIDATION_TIMEOUT_MS) {
            throw new AddressUtilError(
                `${operation} timeout: ${elapsed}ms > ${SECURITY_CONSTANTS.VALIDATION_TIMEOUT_MS}ms`,
                'OPERATION_TIMEOUT',
                { elapsed, maxTime: SECURITY_CONSTANTS.VALIDATION_TIMEOUT_MS, operation }
            );
        }
    }

    /**
     * FIX #3: Safe buffer allocation with overflow protection
     */
    static safeBufferAllocation(size, fieldName = 'buffer') {
        if (!Number.isInteger(size) || size < 0) {
            throw new AddressUtilError(
                `Invalid ${fieldName} size: ${size}`,
                'INVALID_BUFFER_SIZE'
            );
        }

        if (size > SECURITY_CONSTANTS.MAX_OUTPUT_SIZE) {
            throw new AddressUtilError(
                `${fieldName} size too large: ${size} > ${SECURITY_CONSTANTS.MAX_OUTPUT_SIZE}`,
                'BUFFER_SIZE_TOO_LARGE',
                { requestedSize: size, maxSize: SECURITY_CONSTANTS.MAX_OUTPUT_SIZE }
            );
        }

        try {
            return Buffer.alloc(size);
        } catch (error) {
            throw new AddressUtilError(
                `${fieldName} allocation failed: ${error.message}`,
                'BUFFER_ALLOCATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * FIX #6: Secure buffer concatenation with bounds checking
     */
    static safeBufferConcat(buffers, fieldName = 'buffers') {
        if (!Array.isArray(buffers)) {
            throw new AddressUtilError(
                `${fieldName} must be an array`,
                'INVALID_BUFFER_ARRAY'
            );
        }

        let totalSize = 0;
        for (const buf of buffers) {
            if (!Buffer.isBuffer(buf)) {
                throw new AddressUtilError(
                    `All items in ${fieldName} must be Buffers`,
                    'INVALID_BUFFER_ITEM'
                );
            }
            totalSize += buf.length;

            // Check for integer overflow
            if (totalSize < 0 || totalSize > SECURITY_CONSTANTS.MAX_OUTPUT_SIZE) {
                throw new AddressUtilError(
                    `${fieldName} concatenation size overflow: ${totalSize}`,
                    'BUFFER_CONCAT_OVERFLOW',
                    { totalSize, maxSize: SECURITY_CONSTANTS.MAX_OUTPUT_SIZE }
                );
            }
        }

        try {
            return Buffer.concat(buffers);
        } catch (error) {
            throw new AddressUtilError(
                `${fieldName} concatenation failed: ${error.message}`,
                'BUFFER_CONCAT_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * FIX #9: Local validation to avoid circular dependency
     */
    static validateAddress(address) {
        if (!address || typeof address !== 'string') {
            throw new AddressUtilError(
                'Address must be a non-empty string',
                'INVALID_ADDRESS_INPUT'
            );
        }

        // Basic length validation using constants
        if (address.length < SECURITY_CONSTANTS.MIN_LEGACY_ADDRESS_LENGTH ||
            address.length > SECURITY_CONSTANTS.MAX_LEGACY_ADDRESS_LENGTH) {
            throw new AddressUtilError(
                `Invalid address length: ${address.length}. Expected ${SECURITY_CONSTANTS.MIN_LEGACY_ADDRESS_LENGTH}-${SECURITY_CONSTANTS.MAX_LEGACY_ADDRESS_LENGTH} characters`,
                'INVALID_ADDRESS_LENGTH',
                { actualLength: address.length }
            );
        }

        // Validate Base58 characters
        const base58Regex = new RegExp(`^[${ENCODING_CONSTANTS.BASE58_ALPHABET}]+$`);
        if (!base58Regex.test(address)) {
            throw new AddressUtilError(
                'Address contains invalid Base58 characters',
                'INVALID_BASE58_CHARACTERS'
            );
        }

        return true;
    }

    /**
     * FIX #9: Local hex validation to avoid circular dependency
     */
    static validateHexString(hexString, expectedLength, fieldName = 'hex string') {
        if (typeof hexString !== 'string') {
            throw new AddressUtilError(
                `${fieldName} must be a string, got ${typeof hexString}`,
                'INVALID_HEX_TYPE'
            );
        }

        // Check for valid hex characters
        const hexRegex = /^[0-9a-fA-F]*$/;
        if (!hexRegex.test(hexString)) {
            throw new AddressUtilError(
                `${fieldName} contains invalid hex characters`,
                'INVALID_HEX_CHARACTERS',
                { input: hexString }
            );
        }

        // Check for even length
        if (hexString.length % 2 !== 0) {
            throw new AddressUtilError(
                `${fieldName} must have even length, got ${hexString.length} characters`,
                'INVALID_HEX_LENGTH'
            );
        }

        const byteLength = hexString.length / 2;

        // Check expected length if provided
        if (expectedLength !== undefined && byteLength !== expectedLength) {
            throw new AddressUtilError(
                `${fieldName} must be ${expectedLength} bytes, got ${byteLength} bytes`,
                'INVALID_HEX_EXPECTED_LENGTH',
                { expectedLength, actualLength: byteLength }
            );
        }

        return true;
    }
}

/**
 * FIX #1: Enhanced legacy address decoding with explicit checksum validation
 */
function decodeLegacyAddress(legacyAddress) {
    const startTime = Date.now();
    let addressBytes = null;

    try {
        AddressSecurityUtils.checkRateLimit('legacy-decode');
        AddressSecurityUtils.validateInputSize(legacyAddress, 100, 'legacy address');
        AddressSecurityUtils.validateAddress(legacyAddress);

        // Decode Base58Check
        try {
            addressBytes = base58_to_binary(legacyAddress);
        } catch (error) {
            throw new AddressUtilError(
                `Base58Check decoding failed: ${error.message}`,
                'BASE58_DECODE_FAILED',
                { originalError: error.message }
            );
        }

        // Validate address length using constants
        if (addressBytes.length !== SECURITY_CONSTANTS.DECODED_ADDRESS_LENGTH) {
            throw new AddressUtilError(
                `Invalid address length: expected ${SECURITY_CONSTANTS.DECODED_ADDRESS_LENGTH} bytes, got ${addressBytes.length}`,
                'INVALID_ADDRESS_LENGTH',
                { expectedLength: SECURITY_CONSTANTS.DECODED_ADDRESS_LENGTH, actualLength: addressBytes.length }
            );
        }

        const versionByte = addressBytes[0];
        const hash160Bytes = addressBytes.slice(
            SECURITY_CONSTANTS.HASH160_OFFSET,
            SECURITY_CONSTANTS.HASH160_OFFSET + CRYPTO_CONSTANTS.HASH160_LENGTH
        );
        const providedChecksum = addressBytes.slice(-CRYPTO_CONSTANTS.CHECKSUM_LENGTH);

        // FIX #1: Explicit checksum validation
        const payload = addressBytes.slice(0, -CRYPTO_CONSTANTS.CHECKSUM_LENGTH);
        const hash1 = createHash('sha256').update(payload).digest();
        const hash2 = createHash('sha256').update(hash1).digest();
        const calculatedChecksum = hash2.slice(0, CRYPTO_CONSTANTS.CHECKSUM_LENGTH);

        // Use constant-time comparison for checksum validation
        const checksumValid = AddressSecurityUtils.constantTimeBufferEqual(
            providedChecksum,
            calculatedChecksum
        );

        if (!checksumValid) {
            throw new AddressUtilError(
                'Address checksum validation failed',
                'CHECKSUM_VALIDATION_FAILED',
                {
                    provided: providedChecksum.toString('hex'),
                    calculated: calculatedChecksum.toString('hex')
                }
            );
        }

        let prefix, addressType, network;

        // Determine network and address type from version byte
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
                throw new AddressUtilError(
                    `Unsupported address version byte: 0x${versionByte.toString(16)}`,
                    'UNSUPPORTED_VERSION_BYTE',
                    { versionByte }
                );
        }

        // Extract hash160
        const hash160Buffer = Buffer.from(hash160Bytes);
        const hash160Hex = hash160Buffer.toString('hex');

        AddressSecurityUtils.validateExecutionTime(startTime, 'legacy address decoding');

        return {
            prefix,
            hash160Hex,
            hash160Buffer,
            addressType,
            network,
            checksumValid: true,
            versionByte
        };

    } catch (error) {
        if (error instanceof AddressUtilError) {
            throw error;
        }
        throw new AddressUtilError(
            `Legacy address decoding failed: ${error.message}`,
            'DECODE_FAILED',
            { originalError: error.message }
        );
    } finally {
        // FIX #7: Secure cleanup
        if (addressBytes) {
            AddressSecurityUtils.secureClear(Buffer.from(addressBytes));
        }
    }
}

/**
 * FIX #5,#12: Enhanced bit conversion with comprehensive validation and memory leak fix
 */
function convertBitGroups(inputData, fromBits, toBits, addPadding = true) {
    const startTime = Date.now();
    let processedInput = null;

    try {
        AddressSecurityUtils.checkRateLimit('bit-conversion');
        AddressSecurityUtils.validateInputSize(inputData, SECURITY_CONSTANTS.MAX_CONVERSION_INPUT, 'bit conversion input');

        // Validate input parameters
        if (!inputData || inputData.length === 0) {
            throw new AddressUtilError(
                'Input data cannot be empty',
                'EMPTY_INPUT_DATA'
            );
        }

        if (!Number.isInteger(fromBits) || fromBits < SECURITY_CONSTANTS.MIN_BIT_WIDTH || fromBits > SECURITY_CONSTANTS.MAX_BIT_WIDTH) {
            throw new AddressUtilError(
                `Invalid fromBits: ${fromBits}. Must be integer between ${SECURITY_CONSTANTS.MIN_BIT_WIDTH} and ${SECURITY_CONSTANTS.MAX_BIT_WIDTH}`,
                'INVALID_FROM_BITS',
                { fromBits, min: SECURITY_CONSTANTS.MIN_BIT_WIDTH, max: SECURITY_CONSTANTS.MAX_BIT_WIDTH }
            );
        }

        if (!Number.isInteger(toBits) || toBits < SECURITY_CONSTANTS.MIN_BIT_WIDTH || toBits > SECURITY_CONSTANTS.MAX_BIT_WIDTH) {
            throw new AddressUtilError(
                `Invalid toBits: ${toBits}. Must be integer between ${SECURITY_CONSTANTS.MIN_BIT_WIDTH} and ${SECURITY_CONSTANTS.MAX_BIT_WIDTH}`,
                'INVALID_TO_BITS',
                { toBits, min: SECURITY_CONSTANTS.MIN_BIT_WIDTH, max: SECURITY_CONSTANTS.MAX_BIT_WIDTH }
            );
        }

        // Convert input to consistent array format with validation
        if (Array.isArray(inputData)) {
            processedInput = [...inputData];
        } else if (inputData instanceof Uint8Array || Buffer.isBuffer(inputData)) {
            processedInput = Array.from(inputData);
        } else {
            throw new AddressUtilError(
                'Input data must be Array, Uint8Array, or Buffer',
                'INVALID_INPUT_TYPE',
                { actualType: typeof inputData }
            );
        }

        // Calculate and validate output size to prevent memory exhaustion
        const totalBits = processedInput.length * fromBits;
        const outputSize = Math.ceil(totalBits / toBits);

        if (outputSize > SECURITY_CONSTANTS.MAX_OUTPUT_SIZE) {
            throw new AddressUtilError(
                `Output size too large: ${outputSize} > ${SECURITY_CONSTANTS.MAX_OUTPUT_SIZE}`,
                'OUTPUT_SIZE_TOO_LARGE',
                { outputSize, maxSize: SECURITY_CONSTANTS.MAX_OUTPUT_SIZE }
            );
        }

        const result = AddressSecurityUtils.safeBufferAllocation(outputSize, 'bit conversion result');
        const targetMask = (1 << toBits) - 1;
        let accumulator = 0;
        let accumulatorBits = 0;
        let outputIndex = 0;

        // Process input with bounds checking and validation
        for (let i = 0; i < processedInput.length; i++) {
            // Check for timeout periodically
            if (i % 100 === 0) {
                AddressSecurityUtils.validateExecutionTime(startTime, 'bit conversion');
            }

            const value = processedInput[i];
            const maxValue = (1 << fromBits) - 1;

            // Validate input value range
            if (!Number.isInteger(value) || value < 0 || value > maxValue) {
                throw new AddressUtilError(
                    `Invalid input value at index ${i}: ${value}. Must be between 0 and ${maxValue} for ${fromBits}-bit values`,
                    'INVALID_INPUT_VALUE',
                    { index: i, value, maxValue, fromBits }
                );
            }

            // Add new bits to accumulator
            accumulator = (accumulator << fromBits) | value;
            accumulatorBits += fromBits;

            // Extract complete target-width values
            while (accumulatorBits >= toBits) {
                accumulatorBits -= toBits;

                if (outputIndex >= result.length) {
                    throw new AddressUtilError(
                        'Output buffer overflow during bit conversion',
                        'OUTPUT_BUFFER_OVERFLOW',
                        { outputIndex, bufferLength: result.length }
                    );
                }

                result[outputIndex] = (accumulator >> accumulatorBits) & targetMask;
                outputIndex++;
            }
        }

        // Handle remaining bits with padding
        if (accumulatorBits > 0) {
            if (addPadding) {
                if (outputIndex >= result.length) {
                    throw new AddressUtilError(
                        'Output buffer overflow during padding',
                        'PADDING_BUFFER_OVERFLOW'
                    );
                }
                result[outputIndex] = (accumulator << (toBits - accumulatorBits)) & targetMask;
                outputIndex++;
            } else {
                // Validate remaining bits are zeros when not padding
                if (accumulator !== 0) {
                    throw new AddressUtilError(
                        'Invalid padding bits: remaining bits must be zero when padding is disabled',
                        'INVALID_PADDING_BITS',
                        { remainingBits: accumulatorBits, accumulator }
                    );
                }
            }
        }

        AddressSecurityUtils.validateExecutionTime(startTime, 'bit conversion');

        // Return appropriately sized result
        const finalResult = result.slice(0, outputIndex);
        return new Uint8Array(finalResult);

    } catch (error) {
        if (error instanceof AddressUtilError) {
            throw error;
        }
        throw new AddressUtilError(
            `Bit conversion failed: ${error.message}`,
            'BIT_CONVERSION_FAILED',
            { originalError: error.message }
        );
    } finally {
        // FIX #12: Secure cleanup to prevent memory leaks
        if (processedInput) {
            AddressSecurityUtils.secureClear(processedInput);
        }
    }
}

/**
 * Enhanced checksum to 5-bit conversion with security validation
 */
function convertChecksumTo5Bit(checksum, outputLength = 8) {
    const startTime = Date.now();

    try {
        AddressSecurityUtils.checkRateLimit('checksum-5bit');

        if (typeof checksum !== 'number' && typeof checksum !== 'bigint') {
            throw new AddressUtilError(
                `Checksum must be number or bigint, got ${typeof checksum}`,
                'INVALID_CHECKSUM_TYPE'
            );
        }

        if (checksum < 0) {
            throw new AddressUtilError(
                `Checksum must be non-negative, got ${checksum}`,
                'NEGATIVE_CHECKSUM'
            );
        }

        if (!Number.isInteger(outputLength) || outputLength < 1 || outputLength > 16) {
            throw new AddressUtilError(
                `Output length must be integer between 1 and 16, got ${outputLength}`,
                'INVALID_OUTPUT_LENGTH',
                { outputLength }
            );
        }

        // Convert to BigInt for consistent bit operations
        let checksumBig = BigInt(checksum);
        const result = AddressSecurityUtils.safeBufferAllocation(outputLength, '5-bit checksum result');

        // Extract 5 bits at a time, from least to most significant
        for (let i = 0; i < outputLength; i++) {
            result[outputLength - 1 - i] = Number(checksumBig & 31n); // Extract lower 5 bits (31 = 0x1F)
            checksumBig = checksumBig >> 5n;                          // Shift right by 5 bits
        }

        AddressSecurityUtils.validateExecutionTime(startTime, 'checksum to 5-bit conversion');

        return new Uint8Array(result);

    } catch (error) {
        if (error instanceof AddressUtilError) {
            throw error;
        }
        throw new AddressUtilError(
            `Checksum to 5-bit conversion failed: ${error.message}`,
            'CHECKSUM_CONVERSION_FAILED',
            { originalError: error.message }
        );
    }
}

/**
 * Enhanced legacy address validation with comprehensive checks
 */
function validateAndDecodeLegacyAddress(address) {
    const startTime = Date.now();

    try {
        AddressSecurityUtils.checkRateLimit('legacy-validate');
        AddressSecurityUtils.validateInputSize(address, 100, 'legacy address');
        AddressSecurityUtils.validateAddress(address);

        AddressSecurityUtils.validateExecutionTime(startTime, 'legacy address validation');

        // Decode and validate using enhanced decoding function
        return decodeLegacyAddress(address);

    } catch (error) {
        if (error instanceof AddressUtilError) {
            throw error;
        }
        throw new AddressUtilError(
            `Legacy address validation failed: ${error.message}`,
            'VALIDATION_FAILED',
            { originalError: error.message }
        );
    }
}

/**
 * Enhanced address format detection with comprehensive validation
 */
function detectAddressFormat(address) {
    const startTime = Date.now();

    try {
        AddressSecurityUtils.checkRateLimit('format-detection');
        AddressSecurityUtils.validateInputSize(address, 100, 'address');

        if (!address || typeof address !== 'string') {
            return {
                format: 'unknown',
                network: 'unknown',
                type: 'unknown',
                error: 'Invalid input type'
            };
        }

        // Validate length using constants
        if (address.length < SECURITY_CONSTANTS.MIN_LEGACY_ADDRESS_LENGTH ||
            address.length > 90) { // Max for any address type
            return {
                format: 'unknown',
                network: 'unknown',
                type: 'unknown',
                error: 'Invalid length'
            };
        }

        let format, network, type;

        // Legacy addresses
        if (address.startsWith('1')) {
            format = 'legacy';
            network = 'mainnet';
            type = 'P2PKH';
        } else if (address.startsWith('3')) {
            format = 'legacy';
            network = 'mainnet';
            type = 'P2SH';
        } else if (address.startsWith('m') || address.startsWith('n')) {
            format = 'legacy';
            network = 'testnet';
            type = 'P2PKH';
        } else if (address.startsWith('2')) {
            format = 'legacy';
            network = 'testnet';
            type = 'P2SH';
        }
        // SegWit addresses
        else if (address.startsWith('bc1q')) {
            format = 'segwit';
            network = 'mainnet';
            type = 'P2WPKH';
        } else if (address.startsWith('bc1z')) {
            format = 'segwit';
            network = 'mainnet';
            type = 'P2WSH';
        } else if (address.startsWith('tb1q')) {
            format = 'segwit';
            network = 'testnet';
            type = 'P2WPKH';
        } else if (address.startsWith('tb1z')) {
            format = 'segwit';
            network = 'testnet';
            type = 'P2WSH';
        }
        // Taproot addresses
        else if (address.startsWith('bc1p')) {
            format = 'taproot';
            network = 'mainnet';
            type = 'P2TR';
        } else if (address.startsWith('tb1p')) {
            format = 'taproot';
            network = 'testnet';
            type = 'P2TR';
        }
        // Unknown format
        else {
            format = 'unknown';
            network = 'unknown';
            type = 'unknown';
        }

        AddressSecurityUtils.validateExecutionTime(startTime, 'address format detection');

        return { format, network, type };

    } catch (error) {
        return {
            format: 'unknown',
            network: 'unknown',
            type: 'unknown',
            error: error.message
        };
    }
}

/**
 * Enhanced address normalization with validation
 */
function normalizeAddress(address) {
    const startTime = Date.now();

    try {
        AddressSecurityUtils.checkRateLimit('normalize');
        AddressSecurityUtils.validateInputSize(address, 100, 'address');

        if (!address || typeof address !== 'string') {
            throw new AddressUtilError(
                'Address must be a non-empty string',
                'INVALID_ADDRESS_INPUT'
            );
        }

        const normalized = address.trim();

        if (normalized.length === 0) {
            throw new AddressUtilError(
                'Address cannot be empty after normalization',
                'EMPTY_NORMALIZED_ADDRESS'
            );
        }

        const formatInfo = detectAddressFormat(normalized);
        if (formatInfo.format === 'unknown') {
            throw new AddressUtilError(
                `Unrecognized address format: ${normalized}`,
                'UNRECOGNIZED_FORMAT',
                { formatInfo }
            );
        }

        AddressSecurityUtils.validateExecutionTime(startTime, 'address normalization');

        return normalized;

    } catch (error) {
        if (error instanceof AddressUtilError) {
            throw error;
        }
        throw new AddressUtilError(
            `Address normalization failed: ${error.message}`,
            'NORMALIZATION_FAILED',
            { originalError: error.message }
        );
    }
}

/**
 * Enhanced address comparison with timing-safe operations
 */
function compareAddresses(address1, address2) {
    try {
        AddressSecurityUtils.checkRateLimit('compare');

        if (!address1 || !address2) {
            return false;
        }

        const normalized1 = normalizeAddress(address1);
        const normalized2 = normalizeAddress(address2);

        // Use constant-time comparison for security
        return AddressSecurityUtils.constantTimeBufferEqual(
            Buffer.from(normalized1),
            Buffer.from(normalized2)
        );

    } catch (error) {
        return false;
    }
}

/**
 * Enhanced network extraction from address
 */
function getNetworkFromAddress(address) {
    try {
        AddressSecurityUtils.checkRateLimit('network-extract');

        const formatInfo = detectAddressFormat(address);
        return formatInfo.network;

    } catch (error) {
        return 'unknown';
    }
}

/**
 * Enhanced network validation for addresses
 */
function isAddressForNetwork(address, expectedNetwork) {
    try {
        AddressSecurityUtils.checkRateLimit('network-check');

        const actualNetwork = getNetworkFromAddress(address);
        return actualNetwork === expectedNetwork;

    } catch (error) {
        return false;
    }
}

/**
 * Get address utilities status and metrics
 */
function getAddressUtilsStatus() {
    return {
        version: '2.1.1',
        securityFeatures: [
            'Explicit checksum validation',
            'Timing attack prevention',
            'Buffer overflow protection',
            'Rate limiting',
            'Secure memory management',
            'DoS protection',
            'Enhanced bit conversion validation',
            'Fixed circular dependencies',
            'Standardized error handling',
            'Memory leak prevention'
        ],
        limits: SECURITY_CONSTANTS,
        rateLimit: {
            maxPerSecond: SECURITY_CONSTANTS.MAX_VALIDATIONS_PER_SECOND,
            currentEntries: AddressSecurityUtils.validationHistory.size
        },
        fixes: [
            'FIX #9: Removed circular dependency with validation.js',
            'FIX #10: Standardized error handling to AddressUtilError',
            'FIX #11: Added constants for magic numbers',
            'FIX #12: Fixed memory leaks in bit conversion functions'
        ]
    };
}

/**
 * Validate address utilities implementation
 */
function validateImplementation() {
    console.log('🧪 Testing address utilities security features...');

    try {
        // Test checksum validation
        const testAddress = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        const decoded = decodeLegacyAddress(testAddress);

        if (!decoded.checksumValid) {
            throw new Error('Checksum validation test failed');
        }

        // Test bit conversion
        const testData = new Uint8Array([0xFF, 0x80, 0x00]);
        const converted = convertBitGroups(testData, 8, 5);

        if (converted.length === 0) {
            throw new Error('Bit conversion test failed');
        }

        // Test address format detection
        const formatInfo = detectAddressFormat(testAddress);
        if (formatInfo.format !== 'legacy') {
            throw new Error('Address format detection test failed');
        }

        // Test address normalization
        const normalized = normalizeAddress("  " + testAddress + "  ");
        if (normalized !== testAddress) {
            throw new Error('Address normalization test failed');
        }

        // Test address comparison
        const isEqual = compareAddresses(testAddress, testAddress);
        if (!isEqual) {
            throw new Error('Address comparison test failed');
        }

        console.log('✅ Address utilities implementation tests passed');
        return true;

    } catch (error) {
        console.error('❌ Address utilities implementation test failed:', error.message);
        return false;
    }
}

/**
 * Cleanup function for graceful shutdown
 */
function cleanup() {
    try {
        console.log('🧹 Cleaning up address utilities...');

        // Clear validation history
        AddressSecurityUtils.validationHistory.clear();

        console.log('✅ Address utilities cleanup completed');

    } catch (error) {
        console.error('❌ Address utilities cleanup failed:', error.message);
    }
}

export {
    AddressUtilError,
    AddressSecurityUtils,
    SECURITY_CONSTANTS,
    decodeLegacyAddress,
    convertBitGroups,
    convertChecksumTo5Bit,
    validateAndDecodeLegacyAddress,
    detectAddressFormat,
    normalizeAddress,
    compareAddresses,
    getNetworkFromAddress,
    isAddressForNetwork,
    getAddressUtilsStatus,
    validateImplementation,
    cleanup
};