/**
 * @fileoverview Input validation utilities for Bitcoin operations
 * 
 * This module provides comprehensive validation functions for Bitcoin-related
 * data types including addresses, keys, derivation paths, and network parameters.
 * All validators follow a consistent pattern and provide descriptive error messages.
 * 
 * @author yfbsei
 * @version 2.0.0
 */

import {
    BIP44_CONSTANTS,
    CRYPTO_CONSTANTS,
    BIP39_CONSTANTS,
    THRESHOLD_CONSTANTS,
    ENCODING_CONSTANTS,
    parseDerivationPath,
    isValidBitcoinPath
} from '../core/constants.js';

/**
 * @typedef {Object} ValidationResult
 * @property {boolean} isValid - Whether validation passed
 * @property {string} [error] - Error message if validation failed
 * @property {Object} [data] - Parsed/normalized data if validation passed
 */

/**
 * Validates a Bitcoin network parameter
 * 
 * @param {string} network - Network identifier to validate
 * @returns {ValidationResult} Validation result
 * 
 * @example
 * const result = validateNetwork('main');
 * if (result.isValid) {
 *   console.log('Valid network:', result.data.name);
 * } else {
 *   console.error('Invalid network:', result.error);
 * }
 */
export function validateNetwork(network) {
    if (typeof network !== 'string') {
        return {
            isValid: false,
            error: `Network must be a string, got ${typeof network}`
        };
    }

    const validNetworks = ['main', 'test'];
    if (!validNetworks.includes(network)) {
        return {
            isValid: false,
            error: `Invalid network: ${network}. Must be one of: ${validNetworks.join(', ')}`
        };
    }

    return {
        isValid: true,
        data: { network }
    };
}

/**
 * Validates a hex-encoded string
 * 
 * @param {string} hexString - Hex string to validate
 * @param {number} [expectedLength] - Expected byte length (optional)
 * @param {string} [fieldName='hex string'] - Field name for error messages
 * @returns {ValidationResult} Validation result
 * 
 * @example
 * const result = validateHexString('deadbeef', 4, 'test data');
 * if (result.isValid) {
 *   console.log('Valid hex:', result.data.buffer);
 * }
 */
export function validateHexString(hexString, expectedLength, fieldName = 'hex string') {
    if (typeof hexString !== 'string') {
        return {
            isValid: false,
            error: `${fieldName} must be a string, got ${typeof hexString}`
        };
    }

    // Check for valid hex characters
    const hexRegex = /^[0-9a-fA-F]*$/;
    if (!hexRegex.test(hexString)) {
        return {
            isValid: false,
            error: `${fieldName} contains invalid hex characters: ${hexString}`
        };
    }

    // Check for even length (hex strings must represent whole bytes)
    if (hexString.length % 2 !== 0) {
        return {
            isValid: false,
            error: `${fieldName} must have even length, got ${hexString.length} characters`
        };
    }

    const byteLength = hexString.length / 2;

    // Check expected length if provided
    if (expectedLength !== undefined && byteLength !== expectedLength) {
        return {
            isValid: false,
            error: `${fieldName} must be ${expectedLength} bytes, got ${byteLength} bytes`
        };
    }

    return {
        isValid: true,
        data: {
            hexString,
            buffer: Buffer.from(hexString, 'hex'),
            byteLength
        }
    };
}

/**
 * Validates a private key in various formats
 * 
 * @param {string|Buffer} privateKey - Private key to validate
 * @param {string} [format='auto'] - Expected format: 'hex', 'wif', 'buffer', or 'auto'
 * @returns {ValidationResult} Validation result
 * 
 * @example
 * const result = validatePrivateKey('L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS', 'wif');
 * if (result.isValid) {
 *   console.log('Private key format:', result.data.format);
 *   console.log('Raw bytes:', result.data.buffer);
 * }
 */
export function validatePrivateKey(privateKey, format = 'auto') {
    if (Buffer.isBuffer(privateKey)) {
        if (privateKey.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH) {
            return {
                isValid: false,
                error: `Private key buffer must be ${CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH} bytes, got ${privateKey.length}`
            };
        }

        return {
            isValid: true,
            data: {
                buffer: privateKey,
                format: 'buffer'
            }
        };
    }

    if (typeof privateKey !== 'string') {
        return {
            isValid: false,
            error: `Private key must be string or Buffer, got ${typeof privateKey}`
        };
    }

    // Auto-detect format
    if (format === 'auto') {
        if (privateKey.length === CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH * 2) {
            format = 'hex';
        } else if (privateKey.length >= 51 && privateKey.length <= 52) {
            format = 'wif';
        } else {
            return {
                isValid: false,
                error: `Cannot auto-detect private key format. Length: ${privateKey.length}`
            };
        }
    }

    // Validate hex format
    if (format === 'hex') {
        const hexResult = validateHexString(privateKey, CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH, 'private key');
        if (!hexResult.isValid) {
            return hexResult;
        }

        return {
            isValid: true,
            data: {
                buffer: hexResult.data.buffer,
                format: 'hex'
            }
        };
    }

    // Validate WIF format
    if (format === 'wif') {
        // Basic WIF validation (detailed validation would require Base58Check decoding)
        const wifRegex = /^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}$/;
        if (!wifRegex.test(privateKey)) {
            return {
                isValid: false,
                error: `Invalid WIF private key format: ${privateKey}`
            };
        }

        return {
            isValid: true,
            data: {
                wif: privateKey,
                format: 'wif'
            }
        };
    }

    return {
        isValid: false,
        error: `Unsupported private key format: ${format}`
    };
}

/**
 * Validates a BIP44 derivation path
 * 
 * @param {string} derivationPath - Derivation path to validate
 * @param {boolean} [bitcoinOnly=true] - Whether to restrict to Bitcoin coin types
 * @returns {ValidationResult} Validation result
 * 
 * @example
 * const result = validateDerivationPath("m/44'/0'/0'/0/0");
 * if (result.isValid) {
 *   console.log('Path components:', result.data.components);
 *   console.log('Is Bitcoin path:', result.data.isBitcoinPath);
 * }
 */
export function validateDerivationPath(derivationPath, bitcoinOnly = true) {
    if (typeof derivationPath !== 'string') {
        return {
            isValid: false,
            error: `Derivation path must be a string, got ${typeof derivationPath}`
        };
    }

    try {
        const components = parseDerivationPath(derivationPath);
        const isBitcoinPath = isValidBitcoinPath(derivationPath);

        if (bitcoinOnly && !isBitcoinPath) {
            return {
                isValid: false,
                error: `Path uses non-Bitcoin coin type: ${components.coinType}. Expected 0 (mainnet) or 1 (testnet)`
            };
        }

        return {
            isValid: true,
            data: {
                components,
                isBitcoinPath,
                derivationPath
            }
        };
    } catch (error) {
        return {
            isValid: false,
            error: `Invalid derivation path format: ${error.message}`
        };
    }
}

/**
 * Validates threshold signature scheme parameters
 * 
 * @param {number} participantCount - Total number of participants
 * @param {number} requiredSigners - Number of required signers (threshold)
 * @returns {ValidationResult} Validation result
 * 
 * @example
 * const result = validateThresholdParams(3, 2);
 * if (result.isValid) {
 *   console.log('Valid 2-of-3 threshold scheme');
 * }
 */
export function validateThresholdParams(participantCount, requiredSigners) {
    if (!Number.isInteger(participantCount) || participantCount < 0) {
        return {
            isValid: false,
            error: `Participant count must be a non-negative integer, got ${participantCount}`
        };
    }

    if (!Number.isInteger(requiredSigners) || requiredSigners < 0) {
        return {
            isValid: false,
            error: `Required signers must be a non-negative integer, got ${requiredSigners}`
        };
    }

    if (participantCount < THRESHOLD_CONSTANTS.MIN_PARTICIPANTS) {
        return {
            isValid: false,
            error: `Participant count too low: ${participantCount}. Minimum: ${THRESHOLD_CONSTANTS.MIN_PARTICIPANTS}`
        };
    }

    if (requiredSigners < THRESHOLD_CONSTANTS.MIN_THRESHOLD) {
        return {
            isValid: false,
            error: `Required signers too low: ${requiredSigners}. Minimum: ${THRESHOLD_CONSTANTS.MIN_THRESHOLD}`
        };
    }

    if (requiredSigners > participantCount) {
        return {
            isValid: false,
            error: `Required signers (${requiredSigners}) cannot exceed participant count (${participantCount})`
        };
    }

    if (participantCount > THRESHOLD_CONSTANTS.MAX_RECOMMENDED_PARTICIPANTS) {
        console.warn(
            `⚠️  Large participant count (${participantCount}) may impact performance. ` +
            `Recommended maximum: ${THRESHOLD_CONSTANTS.MAX_RECOMMENDED_PARTICIPANTS}`
        );
    }

    return {
        isValid: true,
        data: {
            participantCount,
            requiredSigners,
            scheme: `${requiredSigners}-of-${participantCount}`
        }
    };
}

/**
 * Validates a BIP39 mnemonic phrase
 * 
 * @param {string} mnemonic - Mnemonic phrase to validate
 * @param {string[]} [wordlist] - Custom wordlist (optional)
 * @returns {ValidationResult} Validation result
 * 
 * @example
 * const result = validateMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
 * if (result.isValid) {
 *   console.log('Valid mnemonic with', result.data.wordCount, 'words');
 * }
 */
export function validateMnemonic(mnemonic, wordlist) {
    if (typeof mnemonic !== 'string') {
        return {
            isValid: false,
            error: `Mnemonic must be a string, got ${typeof mnemonic}`
        };
    }

    const words = mnemonic.trim().split(/\s+/);

    if (words.length !== BIP39_CONSTANTS.WORD_COUNT) {
        return {
            isValid: false,
            error: `Invalid mnemonic length: expected ${BIP39_CONSTANTS.WORD_COUNT} words, got ${words.length}`
        };
    }

    // Basic word validation (detailed validation would require the actual wordlist)
    const hasEmptyWords = words.some(word => word.length === 0);
    if (hasEmptyWords) {
        return {
            isValid: false,
            error: 'Mnemonic contains empty words'
        };
    }

    return {
        isValid: true,
        data: {
            words,
            wordCount: words.length,
            mnemonic: mnemonic.trim()
        }
    };
}

/**
 * Validates a Bitcoin address format (basic validation)
 * 
 * @param {string} address - Bitcoin address to validate
 * @returns {ValidationResult} Validation result
 * 
 * @example
 * const result = validateAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
 * if (result.isValid) {
 *   console.log('Address type:', result.data.type);
 *   console.log('Network:', result.data.network);
 * }
 */
export function validateAddress(address) {
    if (typeof address !== 'string') {
        return {
            isValid: false,
            error: `Address must be a string, got ${typeof address}`
        };
    }

    if (address.length === 0) {
        return {
            isValid: false,
            error: 'Address cannot be empty'
        };
    }

    // Detect address type
    let addressType, network;

    if (address.startsWith('1')) {
        addressType = 'P2PKH';
        network = 'mainnet';
    } else if (address.startsWith('3')) {
        addressType = 'P2SH';
        network = 'mainnet';
    } else if (address.startsWith('bc1')) {
        addressType = 'Bech32';
        network = 'mainnet';
    } else if (address.startsWith('m') || address.startsWith('n')) {
        addressType = 'P2PKH';
        network = 'testnet';
    } else if (address.startsWith('2')) {
        addressType = 'P2SH';
        network = 'testnet';
    } else if (address.startsWith('tb1')) {
        addressType = 'Bech32';
        network = 'testnet';
    } else {
        return {
            isValid: false,
            error: `Unrecognized address format: ${address}`
        };
    }

    // Basic length validation
    if (address.length < 26 || address.length > 90) {
        return {
            isValid: false,
            error: `Invalid address length: ${address.length}. Expected 26-90 characters`
        };
    }

    return {
        isValid: true,
        data: {
            address,
            type: addressType,
            network
        }
    };
}

/**
 * Validates buffer length
 * 
 * @param {Buffer} buffer - Buffer to validate
 * @param {number} expectedLength - Expected length in bytes
 * @param {string} fieldName - Field name for error messages
 * @returns {ValidationResult} Validation result
 */
export function validateBufferLength(buffer, expectedLength, fieldName) {
    if (!Buffer.isBuffer(buffer)) {
        return {
            isValid: false,
            error: `${fieldName} must be a Buffer, got ${typeof buffer}`
        };
    }

    if (buffer.length !== expectedLength) {
        return {
            isValid: false,
            error: `${fieldName} must be ${expectedLength} bytes, got ${buffer.length}`
        };
    }

    return {
        isValid: true,
        data: { buffer }
    };
}

/**
 * Validates a number within a range
 * 
 * @param {number} value - Value to validate
 * @param {number} min - Minimum value (inclusive)
 * @param {number} max - Maximum value (inclusive)
 * @param {string} fieldName - Field name for error messages
 * @returns {ValidationResult} Validation result
 */
export function validateNumberRange(value, min, max, fieldName) {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        return {
            isValid: false,
            error: `${fieldName} must be a finite number, got ${typeof value}`
        };
    }

    if (value < min || value > max) {
        return {
            isValid: false,
            error: `${fieldName} must be between ${min} and ${max}, got ${value}`
        };
    }

    return {
        isValid: true,
        data: { value }
    };
}

/**
 * Validates and throws error if validation fails
 * 
 * @param {ValidationResult} result - Validation result to check
 * @throws {Error} If validation failed
 * 
 * @example
 * const result = validateNetwork('invalid');
 * assertValid(result); // Throws error with descriptive message
 */
export function assertValid(result) {
    if (!result.isValid) {
        throw new Error(result.error);
    }
}