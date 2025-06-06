/**
 * @fileoverview Address utility functions for Bitcoin address processing
 * 
 * This module provides shared utility functions for Bitcoin address decoding, bit conversion,
 * and checksum operations. These functions are used by various address format
 * implementations including Bech32 encoding and legacy address processing.
 * 
 * @author yfbsei
 * @version 2.0.0
 */

import { base58_to_binary } from 'base58-js';
import {
    NETWORK_VERSIONS,
    CRYPTO_CONSTANTS,
    ENCODING_CONSTANTS
} from '../core/constants.js';

/**
 * @typedef {Object} DecodedLegacyAddress
 * @property {string} prefix - Network prefix ('bc' for mainnet, 'tb' for testnet)
 * @property {string} hash160Hex - Hex-encoded hash160 value
 * @property {Buffer} hash160Buffer - Raw hash160 buffer
 * @property {string} addressType - Address type ('P2PKH' or 'P2SH')
 * @property {string} network - Network type ('mainnet' or 'testnet')
 */

/**
 * Decodes a legacy Bitcoin address to extract network and hash information
 * 
 * Validates the address format and extracts:
 * - Network type from version byte (0x00 = mainnet P2PKH, 0x6f = testnet P2PKH, etc.)
 * - Hash160 value (20 bytes) from the address payload
 * - Checksum validation through Base58Check decoding
 * 
 * **Supported Address Types:**
 * - P2PKH Mainnet (0x00): Addresses starting with "1"
 * - P2PKH Testnet (0x6f): Addresses starting with "m" or "n"  
 * - P2SH Mainnet (0x05): Addresses starting with "3"
 * - P2SH Testnet (0xc4): Addresses starting with "2"
 * 
 * @param {string} legacyAddress - Legacy address to decode
 * @returns {DecodedLegacyAddress} Decoded address information
 * @throws {Error} If address format is invalid or unsupported
 * 
 * @example
 * // Decode mainnet P2PKH address
 * const decoded = decodeLegacyAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
 * console.log(decoded);
 * // {
 * //   prefix: "bc",
 * //   hash160Hex: "76a04053bda0a88bda5177b86a15c3b29f559873",
 * //   hash160Buffer: <Buffer 76 a0 40 53 ...>,
 * //   addressType: "P2PKH",
 * //   network: "mainnet"
 * // }
 * 
 * @example
 * // Decode testnet P2PKH address
 * const testnetDecoded = decodeLegacyAddress("mgRpP3zP1hmxyoeYJgfbcmN3c2Qsurw48D");
 * console.log(testnetDecoded.network); // "testnet"
 * console.log(testnetDecoded.prefix);  // "tb"
 */
export function decodeLegacyAddress(legacyAddress) {
    if (!legacyAddress || typeof legacyAddress !== 'string') {
        throw new Error('Legacy address must be a non-empty string');
    }

    let addressBytes;
    try {
        addressBytes = base58_to_binary(legacyAddress);
    } catch (error) {
        throw new Error(`Invalid Base58Check encoding: ${error.message}`);
    }

    // Validate address length (1 version byte + 20 hash bytes + 4 checksum bytes = 25 total)
    const EXPECTED_ADDRESS_LENGTH = 1 + CRYPTO_CONSTANTS.HASH160_LENGTH + CRYPTO_CONSTANTS.CHECKSUM_LENGTH;
    if (addressBytes.length !== EXPECTED_ADDRESS_LENGTH) {
        throw new Error(
            `Invalid address length: expected ${EXPECTED_ADDRESS_LENGTH} bytes, got ${addressBytes.length}`
        );
    }

    const versionByte = addressBytes[0];
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
            throw new Error(`Unsupported address version byte: 0x${versionByte.toString(16)}`);
    }

    // Extract hash160 (skip version byte and checksum)
    const hash160Buffer = Buffer.from(
        addressBytes.slice(1, 1 + CRYPTO_CONSTANTS.HASH160_LENGTH)
    );
    const hash160Hex = hash160Buffer.toString('hex');

    return {
        prefix,
        hash160Hex,
        hash160Buffer,
        addressType,
        network
    };
}

/**
 * Converts data between different bit-width representations
 * 
 * Performs bit-packing conversion between arbitrary bit widths, commonly
 * used to convert from 8-bit bytes to 5-bit groups for Base32 encoding.
 * The conversion handles padding and ensures no data loss.
 * 
 * **Algorithm:**
 * 1. Accumulate input bits in a buffer
 * 2. Extract complete target-width values
 * 3. Apply padding to remaining bits if necessary
 * 4. Return converted array
 * 
 * @param {Uint8Array|Buffer|Array} inputData - Input data to convert
 * @param {number} fromBits - Source bit width (e.g., 8 for bytes)
 * @param {number} toBits - Target bit width (e.g., 5 for Base32)
 * @param {boolean} [addPadding=true] - Whether to add padding for remaining bits
 * @returns {Uint8Array} Converted data in target bit width
 * 
 * @throws {Error} If bit widths are invalid or conversion fails
 * 
 * @example
 * // Convert bytes to 5-bit groups for Base32
 * const bytes = new Uint8Array([0xFF, 0x80, 0x00]);
 * const fiveBitGroups = convertBitGroups(bytes, 8, 5);
 * console.log(Array.from(fiveBitGroups)); // [31, 30, 0, 0, 0]
 * 
 * @example
 * // Convert back from 5-bit to 8-bit
 * const fiveBit = new Uint8Array([31, 30, 0, 0, 0]);
 * const backToBytes = convertBitGroups(fiveBit, 5, 8, false);
 * console.log(Array.from(backToBytes)); // [255, 128]
 */
export function convertBitGroups(inputData, fromBits, toBits, addPadding = true) {
    // Validate input parameters
    if (!inputData || inputData.length === 0) {
        throw new Error('Input data cannot be empty');
    }

    if (!Number.isInteger(fromBits) || fromBits < 1 || fromBits > 32) {
        throw new Error(`Invalid fromBits: ${fromBits}. Must be integer between 1 and 32`);
    }

    if (!Number.isInteger(toBits) || toBits < 1 || toBits > 32) {
        throw new Error(`Invalid toBits: ${toBits}. Must be integer between 1 and 32`);
    }

    // Calculate output size
    const totalBits = inputData.length * fromBits;
    const outputSize = Math.ceil(totalBits / toBits);
    const result = new Uint8Array(outputSize);

    const targetMask = (1 << toBits) - 1;  // Bit mask for target width
    let accumulator = 0;                   // Bit accumulator
    let accumulatorBits = 0;              // Current bits in accumulator
    let outputIndex = 0;                  // Output array index

    for (let i = 0; i < inputData.length; i++) {
        const value = inputData[i];

        // Validate input value is within source bit width
        const maxValue = (1 << fromBits) - 1;
        if (value < 0 || value > maxValue) {
            throw new Error(
                `Invalid input value at index ${i}: ${value}. ` +
                `Must be between 0 and ${maxValue} for ${fromBits}-bit values`
            );
        }

        // Add new bits to accumulator
        accumulator = (accumulator << fromBits) | value;
        accumulatorBits += fromBits;

        // Extract complete target-width values
        while (accumulatorBits >= toBits) {
            accumulatorBits -= toBits;
            result[outputIndex] = (accumulator >> accumulatorBits) & targetMask;
            outputIndex++;
        }
    }

    // Handle remaining bits with padding
    if (accumulatorBits > 0) {
        if (addPadding) {
            result[outputIndex] = (accumulator << (toBits - accumulatorBits)) & targetMask;
            outputIndex++;
        } else {
            // Verify remaining bits are zeros when not padding
            if (accumulator !== 0) {
                throw new Error('Invalid padding bits: remaining bits must be zero when padding is disabled');
            }
        }
    }

    // Return appropriately sized result
    return outputIndex < result.length ? result.slice(0, outputIndex) : result;
}

/**
 * Converts a numeric checksum to 5-bit representation for Base32 encoding
 * 
 * Takes a checksum value and converts it to an array of eight 5-bit values
 * for inclusion in address encoding. The conversion extracts 5 bits
 * at a time from least significant to most significant.
 * 
 * **Bit Extraction Process:**
 * 1. Convert checksum to BigInt for proper bit manipulation
 * 2. Extract 5 bits at a time using bitwise AND with 0x1F (31)
 * 3. Shift right by 5 bits for next extraction
 * 4. Return array with most significant 5-bit group first
 * 
 * @param {number|bigint} checksum - Checksum value to convert
 * @param {number} [outputLength=8] - Number of 5-bit groups to generate
 * @returns {Uint8Array} Array of 5-bit values (0-31 each)
 * 
 * @throws {Error} If checksum is negative or output length is invalid
 * 
 * @example
 * const checksum = 0x1234567890;
 * const fiveBitChecksum = convertChecksumTo5Bit(checksum);
 * console.log(Array.from(fiveBitChecksum));
 * // [16, 18, 6, 22, 15, 4, 18, 0] (8 five-bit values)
 * 
 * @example
 * // Use with Base32 encoding
 * const checksumValue = 12345;
 * const fiveBitGroups = convertChecksumTo5Bit(checksumValue, 6);
 * const base32String = fiveBitGroups.map(val => 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'[val]).join('');
 */
export function convertChecksumTo5Bit(checksum, outputLength = 8) {
    if (typeof checksum !== 'number' && typeof checksum !== 'bigint') {
        throw new Error(`Checksum must be number or bigint, got ${typeof checksum}`);
    }

    if (checksum < 0) {
        throw new Error(`Checksum must be non-negative, got ${checksum}`);
    }

    if (!Number.isInteger(outputLength) || outputLength < 1 || outputLength > 16) {
        throw new Error(`Output length must be integer between 1 and 16, got ${outputLength}`);
    }

    // Convert to BigInt for consistent bit operations
    let checksumBig = BigInt(checksum);
    const result = new Uint8Array(outputLength);

    // Extract 5 bits at a time, from least to most significant
    for (let i = 0; i < outputLength; i++) {
        result[outputLength - 1 - i] = Number(checksumBig & 31n); // Extract lower 5 bits (31 = 0x1F)
        checksumBig = checksumBig >> 5n;                          // Shift right by 5 bits
    }

    return result;
}

/**
 * Validates and extracts components from a legacy Bitcoin address
 * 
 * Comprehensive validation that checks Base58Check encoding, length,
 * version byte, and extracts all relevant address components.
 * 
 * @param {string} address - Legacy Bitcoin address to validate and decode
 * @returns {DecodedLegacyAddress} Decoded and validated address information
 * @throws {Error} If address is invalid in any way
 * 
 * @example
 * try {
 *   const decoded = validateAndDecodeLegacyAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
 *   console.log(`Valid ${decoded.addressType} address on ${decoded.network}`);
 * } catch (error) {
 *   console.error('Invalid address:', error.message);
 * }
 */
export function validateAndDecodeLegacyAddress(address) {
    // Basic string validation
    if (!address || typeof address !== 'string') {
        throw new Error('Address must be a non-empty string');
    }

    // Length validation
    if (address.length < 26 || address.length > 35) {
        throw new Error(`Invalid address length: ${address.length}. Expected 26-35 characters`);
    }

    // Character validation (Base58 alphabet)
    const base58Regex = new RegExp(`^[${ENCODING_CONSTANTS.BASE58_ALPHABET}]+$`);
    if (!base58Regex.test(address)) {
        throw new Error('Address contains invalid Base58 characters');
    }

    // Decode and validate
    return decodeLegacyAddress(address);
}

/**
 * Detects the format of a Bitcoin address
 * 
 * @param {string} address - Bitcoin address to analyze
 * @returns {Object} Address format information
 * @returns {string} returns.format - Address format ('legacy', 'segwit', 'taproot', 'unknown')
 * @returns {string} returns.network - Network type ('mainnet', 'testnet', 'unknown')
 * @returns {string} returns.type - Address type ('P2PKH', 'P2SH', 'P2WPKH', 'P2WSH', 'P2TR', 'unknown')
 * 
 * @example
 * const info = detectAddressFormat("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
 * console.log(info);
 * // { format: 'legacy', network: 'mainnet', type: 'P2PKH' }
 * 
 * const segwitInfo = detectAddressFormat("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
 * console.log(segwitInfo);
 * // { format: 'segwit', network: 'mainnet', type: 'P2WPKH' }
 */
export function detectAddressFormat(address) {
    if (!address || typeof address !== 'string') {
        return { format: 'unknown', network: 'unknown', type: 'unknown' };
    }

    // Legacy addresses
    if (address.startsWith('1')) {
        return { format: 'legacy', network: 'mainnet', type: 'P2PKH' };
    }
    if (address.startsWith('3')) {
        return { format: 'legacy', network: 'mainnet', type: 'P2SH' };
    }
    if (address.startsWith('m') || address.startsWith('n')) {
        return { format: 'legacy', network: 'testnet', type: 'P2PKH' };
    }
    if (address.startsWith('2')) {
        return { format: 'legacy', network: 'testnet', type: 'P2SH' };
    }

    // SegWit addresses
    if (address.startsWith('bc1q')) {
        return { format: 'segwit', network: 'mainnet', type: 'P2WPKH' };
    }
    if (address.startsWith('bc1z')) {
        return { format: 'segwit', network: 'mainnet', type: 'P2WSH' };
    }
    if (address.startsWith('tb1q')) {
        return { format: 'segwit', network: 'testnet', type: 'P2WPKH' };
    }
    if (address.startsWith('tb1z')) {
        return { format: 'segwit', network: 'testnet', type: 'P2WSH' };
    }

    // Taproot addresses
    if (address.startsWith('bc1p')) {
        return { format: 'taproot', network: 'mainnet', type: 'P2TR' };
    }
    if (address.startsWith('tb1p')) {
        return { format: 'taproot', network: 'testnet', type: 'P2TR' };
    }

    return { format: 'unknown', network: 'unknown', type: 'unknown' };
}

/**
 * Normalizes an address by removing whitespace and validating format
 * 
 * @param {string} address - Address to normalize
 * @returns {string} Normalized address
 * @throws {Error} If address format is invalid
 * 
 * @example
 * const normalized = normalizeAddress("  1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2  ");
 * console.log(normalized); // "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
 */
export function normalizeAddress(address) {
    if (!address || typeof address !== 'string') {
        throw new Error('Address must be a non-empty string');
    }

    const normalized = address.trim();

    if (normalized.length === 0) {
        throw new Error('Address cannot be empty after normalization');
    }

    const formatInfo = detectAddressFormat(normalized);
    if (formatInfo.format === 'unknown') {
        throw new Error(`Unrecognized address format: ${normalized}`);
    }

    return normalized;
}

/**
 * Compares two addresses for equality, handling different formats appropriately
 * 
 * @param {string} address1 - First address to compare
 * @param {string} address2 - Second address to compare
 * @returns {boolean} True if addresses are equivalent
 * 
 * @example
 * const addr1 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
 * const addr2 = "  1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2  ";
 * console.log(compareAddresses(addr1, addr2)); // true
 */
export function compareAddresses(address1, address2) {
    try {
        const normalized1 = normalizeAddress(address1);
        const normalized2 = normalizeAddress(address2);
        return normalized1 === normalized2;
    } catch (error) {
        return false;
    }
}

/**
 * Extracts the network type from various address formats
 * 
 * @param {string} address - Bitcoin address
 * @returns {string} Network type ('mainnet', 'testnet', or 'unknown')
 * 
 * @example
 * console.log(getNetworkFromAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")); // "mainnet"
 * console.log(getNetworkFromAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")); // "testnet"
 */
export function getNetworkFromAddress(address) {
    const formatInfo = detectAddressFormat(address);
    return formatInfo.network;
}

/**
 * Checks if an address belongs to a specific network
 * 
 * @param {string} address - Bitcoin address to check
 * @param {string} expectedNetwork - Expected network ('mainnet' or 'testnet')
 * @returns {boolean} True if address belongs to expected network
 * 
 * @example
 * const isMainnet = isAddressForNetwork("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "mainnet");
 * console.log(isMainnet); // true
 */
export function isAddressForNetwork(address, expectedNetwork) {
    const actualNetwork = getNetworkFromAddress(address);
    return actualNetwork === expectedNetwork;
}

/**
 * Decodes WIF private key to raw bytes (legacy compatibility)
 * 
 * @param {string} wifPrivateKey - WIF private key
 * @returns {Uint8Array} Raw private key bytes
 */
export function decodeWIFPrivateKey(wifPrivateKey) {
    try {
        const decoded = base58_to_binary(wifPrivateKey);
        // Extract private key bytes (skip version byte and suffix)
        return decoded.filter((_, i) => i > 0 && i < 33);
    } catch (error) {
        throw new Error(`Failed to decode WIF private key: ${error.message}`);
    }
}

/**
 * Decodes legacy address hash (legacy compatibility)
 * 
 * @param {string} legacyAddress - Legacy address
 * @returns {Uint8Array} Hash160 bytes
 */
export function decodeLegacyAddressHash(legacyAddress) {
    try {
        const decoded = base58_to_binary(legacyAddress);
        // Extract hash160 (skip version byte and checksum)
        return decoded.filter((_, i) => i > 0 && i < 21);
    } catch (error) {
        throw new Error(`Failed to decode legacy address: ${error.message}`);
    }
}

/**
 * Legacy function aliases for backwards compatibility
 * Maps old function names to new function names
 */
export const decode_legacy_address = decodeLegacyAddress;
export const convertBits = convertBitGroups;
export const checksum_5bit = convertChecksumTo5Bit;
export const privateKey_decode = decodeWIFPrivateKey;
export const legacyAddress_decode = decodeLegacyAddressHash;