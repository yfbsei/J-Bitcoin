/**
 * @fileoverview Bitcoin address and key decoding utilities
 * 
 * This module provides functions to decode various Bitcoin key and address formats
 * back to their raw binary representations. It handles Wallet Import Format (WIF)
 * private keys and legacy Base58Check addresses, extracting the essential
 * cryptographic material while validating format integrity.
 * 
 * @see {@link https://en.bitcoin.it/wiki/Wallet_import_format|WIF - Wallet Import Format}
 * @see {@link https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses|Bitcoin Address Format}
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki|BIP38 - Passphrase-protected private keys}
 * @author yfbsei
 * @version 2.0.0
 */

import { base58_to_binary } from 'base58-js';
import {
    decodeLegacyAddress,
    validateAndDecodeLegacyAddress,
    decodeWIFPrivateKey,
    decodeLegacyAddressHash,
    detectAddressFormat
} from '../../utils/address-helpers.js';
import {
    validatePrivateKey,
    validateAddress,
    assertValid
} from '../../utils/validation.js';
import {
    CRYPTO_CONSTANTS,
    NETWORK_VERSIONS
} from '../../core/constants.js';

/**
 * @typedef {Object} DecodedPrivateKey
 * @property {Buffer} keyMaterial - Raw 32-byte private key material
 * @property {string} format - Format detected ('wif', 'hex', 'buffer')
 * @property {boolean} isCompressed - Whether the key indicates compressed public key
 * @property {string} network - Network type ('mainnet' or 'testnet')
 * @property {number} [wifVersionByte] - WIF version byte if applicable
 */

/**
 * @typedef {Object} DecodedAddress
 * @property {Buffer} hash160 - Raw 20-byte hash160 value
 * @property {string} addressType - Address type ('P2PKH', 'P2SH')
 * @property {string} network - Network type ('mainnet' or 'testnet')
 * @property {string} format - Address format ('legacy', 'segwit', 'taproot')
 * @property {number} versionByte - Original version byte from address
 */

/**
 * Decodes a WIF (Wallet Import Format) private key to raw bytes
 * 
 * WIF is the standard format for representing Bitcoin private keys in a human-readable
 * way while maintaining security through Base58Check encoding. This function extracts
 * the raw 32-byte private key material from the WIF-encoded string.
 * 
 * **WIF Format Structure:**
 * - 1 byte: Network version (0x80 mainnet, 0xef testnet)  
 * - 32 bytes: Private key material
 * - 1 byte: Compression flag (0x01 if present, indicates compressed public key)
 * - 4 bytes: Checksum (first 4 bytes of double SHA256)
 * 
 * **WIF Variants:**
 * - **Uncompressed WIF**: 51 characters, no compression flag
 * - **Compressed WIF**: 52 characters, includes 0x01 compression flag
 * - **Mainnet**: Starts with '5' (uncompressed) or 'K'/'L' (compressed)
 * - **Testnet**: Starts with '9' (uncompressed) or 'c' (compressed)
 * 
 * @param {string} wifPrivateKey - WIF-encoded private key
 * @returns {DecodedPrivateKey} Decoded private key information
 * 
 * @throws {Error} If WIF format is invalid or corrupted
 * @throws {Error} If Base58Check decoding fails (invalid checksum)
 * @throws {Error} If private key length is incorrect after decoding
 * 
 * @example
 * // Decode compressed mainnet WIF private key
 * const compressedWIF = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
 * const decoded = decodeWIFPrivateKey(compressedWIF);
 * 
 * console.log('Private key length:', decoded.keyMaterial.length); // 32
 * console.log('Is compressed:', decoded.isCompressed); // true
 * console.log('Network:', decoded.network); // "mainnet"
 * console.log('Private key hex:', decoded.keyMaterial.toString('hex'));
 * 
 * @example
 * // Decode uncompressed mainnet WIF private key
 * const uncompressedWIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
 * const decoded = decodeWIFPrivateKey(uncompressedWIF);
 * 
 * console.log('Is compressed:', decoded.isCompressed); // false
 * console.log('Format:', decoded.format); // "wif"
 */
function decodeWIFPrivateKey(wifPrivateKey) {
    // Validate input
    if (!wifPrivateKey || typeof wifPrivateKey !== 'string') {
        throw new Error('WIF private key must be a non-empty string');
    }

    // Validate WIF format
    const validation = validatePrivateKey(wifPrivateKey, 'wif');
    assertValid(validation);

    let decodedBytes;
    try {
        decodedBytes = base58_to_binary(wifPrivateKey);
    } catch (error) {
        throw new Error(`Invalid Base58Check encoding: ${error.message}`);
    }

    // Validate decoded length (version + key + optional compression flag + checksum)
    if (decodedBytes.length !== 37 && decodedBytes.length !== 38) {
        throw new Error(
            `Invalid WIF length: expected 37 or 38 bytes, got ${decodedBytes.length}`
        );
    }

    const versionByte = decodedBytes[0];
    const isCompressed = decodedBytes.length === 38;

    // Determine network from version byte
    let network;
    if (versionByte === NETWORK_VERSIONS.MAINNET.WIF_PRIVATE_KEY) {
        network = 'mainnet';
    } else if (versionByte === NETWORK_VERSIONS.TESTNET.WIF_PRIVATE_KEY) {
        network = 'testnet';
    } else {
        throw new Error(`Unsupported WIF version byte: 0x${versionByte.toString(16)}`);
    }

    // Extract private key material (skip version byte and suffix)
    const keyMaterial = Buffer.from(
        decodedBytes.slice(1, 1 + CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH)
    );

    // Validate private key is not zero
    const isZero = keyMaterial.every(byte => byte === 0);
    if (isZero) {
        throw new Error('Private key cannot be zero');
    }

    return {
        keyMaterial,
        format: 'wif',
        isCompressed,
        network,
        wifVersionByte: versionByte
    };
}

/**
 * Decodes a private key from hex string format
 * 
 * @param {string} hexPrivateKey - Hex-encoded private key (64 characters)
 * @returns {DecodedPrivateKey} Decoded private key information
 * 
 * @throws {Error} If hex format is invalid
 * 
 * @example
 * const hexKey = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
 * const decoded = decodeHexPrivateKey(hexKey);
 * console.log('Key material:', decoded.keyMaterial);
 */
function decodeHexPrivateKey(hexPrivateKey) {
    // Validate input
    if (!hexPrivateKey || typeof hexPrivateKey !== 'string') {
        throw new Error('Hex private key must be a non-empty string');
    }

    // Validate hex format
    const validation = validatePrivateKey(hexPrivateKey, 'hex');
    assertValid(validation);

    const keyMaterial = Buffer.from(hexPrivateKey, 'hex');

    // Validate private key is not zero
    const isZero = keyMaterial.every(byte => byte === 0);
    if (isZero) {
        throw new Error('Private key cannot be zero');
    }

    return {
        keyMaterial,
        format: 'hex',
        isCompressed: true, // Default assumption for hex keys
        network: 'unknown'  // Cannot determine network from hex alone
    };
}

/**
 * Decodes a legacy Bitcoin address to extract the HASH160 value
 * 
 * Legacy Bitcoin addresses use Base58Check encoding to represent the HASH160
 * of a public key or script. This function extracts the raw 20-byte hash
 * from P2PKH (Pay to Public Key Hash) and P2SH addresses.
 * 
 * @param {string} legacyAddress - Base58Check encoded legacy address
 * @returns {DecodedAddress} Decoded address information
 * 
 * @throws {Error} If address format is invalid or corrupted
 * @throws {Error} If Base58Check decoding fails (invalid checksum)
 * @throws {Error} If address length is not 25 bytes after decoding
 * 
 * @example
 * // Decode mainnet P2PKH address
 * const mainnetAddress = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
 * const decoded = decodeLegacyAddressComplete(mainnetAddress);
 * 
 * console.log('Hash160 length:', decoded.hash160.length); // 20
 * console.log('Address type:', decoded.addressType); // "P2PKH"
 * console.log('Network:', decoded.network); // "mainnet"
 * console.log('Hash160 hex:', decoded.hash160.toString('hex'));
 * 
 * @example
 * // Decode testnet P2SH address
 * const testnetAddress = "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc";
 * const decoded = decodeLegacyAddressComplete(testnetAddress);
 * 
 * console.log('Address type:', decoded.addressType); // "P2SH"
 * console.log('Network:', decoded.network); // "testnet"
 */
function decodeLegacyAddressComplete(legacyAddress) {
    // Validate input
    if (!legacyAddress || typeof legacyAddress !== 'string') {
        throw new Error('Legacy address must be a non-empty string');
    }

    // Use helper function for decoding
    const decodedInfo = validateAndDecodeLegacyAddress(legacyAddress);

    let versionByte;
    if (decodedInfo.network === 'mainnet') {
        versionByte = decodedInfo.addressType === 'P2PKH'
            ? NETWORK_VERSIONS.MAINNET.P2PKH_ADDRESS
            : NETWORK_VERSIONS.MAINNET.P2SH_ADDRESS;
    } else {
        versionByte = decodedInfo.addressType === 'P2PKH'
            ? NETWORK_VERSIONS.TESTNET.P2PKH_ADDRESS
            : NETWORK_VERSIONS.TESTNET.P2SH_ADDRESS;
    }

    return {
        hash160: decodedInfo.hash160Buffer,
        addressType: decodedInfo.addressType,
        network: decodedInfo.network,
        format: 'legacy',
        versionByte
    };
}

/**
 * Auto-detects and decodes a private key from various formats
 * 
 * @param {string|Buffer} privateKey - Private key in unknown format
 * @returns {DecodedPrivateKey} Decoded private key information
 * 
 * @throws {Error} If format cannot be detected or decoding fails
 * 
 * @example
 * // Auto-detect WIF
 * const wifDecoded = decodePrivateKeyAuto("L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS");
 * console.log('Detected format:', wifDecoded.format); // "wif"
 * 
 * // Auto-detect hex
 * const hexDecoded = decodePrivateKeyAuto("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
 * console.log('Detected format:', hexDecoded.format); // "hex"
 */
function decodePrivateKeyAuto(privateKey) {
    // Handle Buffer input
    if (Buffer.isBuffer(privateKey)) {
        if (privateKey.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH) {
            throw new Error(
                `Invalid private key buffer length: expected ${CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH}, got ${privateKey.length}`
            );
        }

        return {
            keyMaterial: privateKey,
            format: 'buffer',
            isCompressed: true,
            network: 'unknown'
        };
    }

    // Handle string input
    if (typeof privateKey !== 'string') {
        throw new Error(`Private key must be string or Buffer, got ${typeof privateKey}`);
    }

    // Auto-detect format based on length and characteristics
    if (privateKey.length === CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH * 2) {
        // Likely hex format (64 characters)
        return decodeHexPrivateKey(privateKey);
    } else if (privateKey.length >= 51 && privateKey.length <= 52) {
        // Likely WIF format
        return decodeWIFPrivateKey(privateKey);
    } else {
        throw new Error(
            `Cannot auto-detect private key format. Length: ${privateKey.length}. ` +
            `Expected 64 (hex) or 51-52 (WIF) characters.`
        );
    }
}

/**
 * Auto-detects and decodes a Bitcoin address from various formats
 * 
 * @param {string} address - Bitcoin address in unknown format
 * @returns {DecodedAddress} Decoded address information
 * 
 * @throws {Error} If format cannot be detected or decoding fails
 * 
 * @example
 * const decoded = decodeAddressAuto("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
 * console.log('Detected format:', decoded.format); // "legacy"
 * console.log('Address type:', decoded.addressType); // "P2PKH"
 */
function decodeAddressAuto(address) {
    // Validate input
    if (!address || typeof address !== 'string') {
        throw new Error('Address must be a non-empty string');
    }

    // Detect format
    const formatInfo = detectAddressFormat(address);

    if (formatInfo.format === 'unknown') {
        throw new Error(`Unrecognized address format: ${address}`);
    }

    // Currently only legacy addresses are fully supported for decoding
    if (formatInfo.format === 'legacy') {
        return decodeLegacyAddressComplete(address);
    } else {
        throw new Error(
            `Decoding for ${formatInfo.format} addresses not yet implemented. ` +
            `Detected: ${formatInfo.type} on ${formatInfo.network}`
        );
    }
}

// privateKey_decode, legacyAddress_decode
export { decodeWIFPrivateKey, decodeLegacyAddressComplete, decodeAddressAuto, decodePrivateKeyAuto }

// Re-export helper functions for convenience
export {
    decodeLegacyAddress,
    validateAndDecodeLegacyAddress,
    decodeWIFPrivateKey,
    decodeLegacyAddressHash,
} from '../../utils/address-helpers.js';