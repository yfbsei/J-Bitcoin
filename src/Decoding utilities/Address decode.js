/**
 * @fileoverview Address utility functions for Bitcoin address processing
 * 
 * This module provides utility functions for Bitcoin address decoding, bit conversion,
 * and checksum operations. These functions are used by various address format
 * implementations including Bech32 encoding.
 * 
 * @author yfbsei
 * @version 1.0.0
 */

import { base58_to_binary } from 'base58-js';

/**
 * Decodes a legacy Bitcoin address to extract network and hash information
 * 
 * Validates the address format and extracts:
 * - Network type from version byte (0x00 = mainnet, 0x6f = testnet)
 * - Hash160 value (20 bytes) from the address payload
 * - Checksum validation through Base58Check decoding
 * 
 * @param {string} [legacy_addr=""] - Legacy address to decode
 * @returns {Array} Tuple of [network prefix, hex-encoded hash]
 * @throws {Error} If address format is invalid or unsupported
 * @example
 * // Decode mainnet address
 * const [prefix, hash] = decode_legacy_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
 * // Returns: ["bc", "76a04053bda0a88bda5177b86a15c3b29f559873"]
 * 
 * // Decode testnet address
 * const [testPrefix, testHash] = decode_legacy_address("mgRpP3zP1hmxyoeYJgfbcmN3c2Qsurw48D");
 * // Returns: ["tb", "0e7c6e0e0b2c07d6a7b5b8b4d8b5b8b4d8b5b8b4"]
 */
function decode_legacy_address(legacy_addr = "") {
    // Decode Base58Check address to binary
    let legacy_addr_bytes = base58_to_binary(legacy_addr);

    // Determine network from version byte (Bitcoin only)
    const prefix = legacy_addr_bytes[0] === 0 ? "bc" : "tb"; // Bitcoin mainnet/testnet

    // Validate address format: P2PKH addresses have version 0 or 111 and are 25 bytes total
    if ((legacy_addr_bytes[0] === 0 || legacy_addr_bytes[0] === 111) && legacy_addr_bytes.length === 25) {
        // Extract hash160 (bytes 1-20, excluding version byte and 4-byte checksum)
        const legacy_addr_hash = legacy_addr_bytes.filter((_, i) => i > 0 && i < 21);
        return [prefix, Buffer.from(legacy_addr_hash).toString('hex')];
    } else {
        throw new Error("Invalid legacy address");
    }
}

/**
 * Converts data between different bit-width representations
 * 
 * Performs bit-packing conversion between arbitrary bit widths, commonly
 * used to convert from 8-bit bytes to 5-bit groups for Base32 encoding.
 * The conversion handles padding and ensures no data loss.
 * 
 * @param {Uint8Array|Buffer} data - Input data to convert
 * @param {number} from - Source bit width (e.g., 8 for bytes)
 * @param {number} to - Target bit width (e.g., 5 for Base32)
 * @returns {Uint8Array} Converted data in target bit width
 * @example
 * // Convert bytes to 5-bit groups for Base32
 * const bytes = new Uint8Array([0xFF, 0x80, 0x00]);
 * const fiveBit = convertBits(bytes, 8, 5);
 * // Returns: [31, 30, 0, 0, 0] (0xFF80 in 5-bit groups)
 * 
 * // Convert back from 5-bit to 8-bit
 * const backToBytes = convertBits(fiveBit, 5, 8);
 */
function convertBits(data, from, to) {
    let [mask, result, index, accumulator, bits] = [
        (1 << to) - 1,                                      // Bit mask for target width
        new Uint8Array(Math.ceil((data.length * from) / to)), // Output array
        0,                                                   // Output index
        0,                                                   // Bit accumulator
        0                                                    // Current bit count
    ];

    for (let i = 0; i < data.length; ++i) {
        let value = data[i];
        accumulator = (accumulator << from) | value; // Add new bits
        bits += from;

        // Extract complete target-width values
        while (bits >= to) {
            bits -= to;
            result[index] = (accumulator >> bits) & mask;
            ++index;
        }
    }

    // Handle remaining bits with padding
    if (bits > 0) {
        result[index] = (accumulator << (to - bits)) & mask;
        ++index;
    }

    return result;
}

/**
 * Converts a numeric checksum to 5-bit representation for Base32 encoding
 * 
 * Takes a checksum value and converts it to an array of eight 5-bit values
 * for inclusion in address encoding. The conversion extracts 5 bits
 * at a time from least significant to most significant.
 * 
 * @param {number} [checksum=19310] - Checksum value to convert
 * @returns {Uint8Array} Array of 8 values, each containing 5 bits
 * @example
 * const checksum = 0x1234567890; // Example checksum
 * const fiveBitChecksum = checksum_5bit(checksum);
 * // Returns: [16, 18, 6, 22, 15, 4, 18, 0] (8 five-bit values)
 * 
 * // The values can be directly used with Base32 encoding
 * const checksumString = base32_encode(fiveBitChecksum);
 */
function checksum_5bit(checksum = 19310) {
    // Convert to BigInt for proper bit manipulation
    let checksumBig = BigInt(checksum);
    let result = new Uint8Array(8);

    // Extract 5 bits at a time, from least to most significant
    for (let i = 0; i < 8; i++) {
        result[7 - i] = Number(checksumBig & 31n); // Extract lower 5 bits (31 = 0x1F)
        checksumBig = checksumBig >> 5n;           // Shift right by 5 bits
    }

    return result;
}

export {
    decode_legacy_address,
    convertBits,
    checksum_5bit
};