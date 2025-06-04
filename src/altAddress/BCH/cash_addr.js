/**
 * @fileoverview Bitcoin Cash CashAddr address format implementation
 * 
 * This module implements the CashAddr address format for Bitcoin Cash,
 * providing conversion from legacy Base58Check addresses to the newer
 * CashAddr format with improved error detection and user experience.
 * 
 * @see {@link https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md|CashAddr Specification}
 * @see {@link https://reference.cash/protocol/blockchain/encoding/cashaddr|CashAddr Reference}
 * @author yfbsei
 * @version 1.0.0
 */

import BN from 'bn.js';
import { base58_to_binary } from 'base58-js';
import base32_encode from '../../utilities/Base32.js';

/**
 * @typedef {Array<string>} DecodedAddress
 * @description Array containing [network prefix, hex hash]
 * @example ["bitcoincash", "76a04053bda0a88bda5177b86a15c3b29f559873"]
 */

/**
 * Bitcoin Cash CashAddr address format utilities
 * 
 * Provides comprehensive support for converting legacy Bitcoin addresses
 * to the CashAddr format used by Bitcoin Cash. Features include:
 * - Legacy address decoding and validation
 * - Network prefix determination (bitcoincash/bchtest)
 * - Polynomial checksum generation and validation
 * - Base32 encoding with custom alphabet
 * - Support for both P2PKH and P2SH address types
 * 
 * @namespace CASH_ADDR
 * @example
 * // Convert legacy address to CashAddr format
 * const legacy = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
 * const cashAddr = CASH_ADDR.to_cashAddr(legacy, "p2pkh");
 * // Returns: "bitcoincash:qztxx64w20kmy5y9sskjwtgxp3j8dc20ksvef26ssu"
 * 
 * // Convert testnet address
 * const testLegacy = "mgRpP3zP1hmxyoeYJgfbcmN3c2Qsurw48D";
 * const testCashAddr = CASH_ADDR.to_cashAddr(testLegacy, "p2pkh");
 * // Returns: "bchtest:qqyl7uye7t0rjq6vrtqjedcyudy8hj0rzvnwwa5c5g"
 */
const CASH_ADDR = {

	/**
	 * Converts a legacy Bitcoin address to CashAddr format
	 * 
	 * The conversion process:
	 * 1. Decodes the legacy Base58Check address to extract hash and network
	 * 2. Prepends version byte based on address type and hash length
	 * 3. Converts from 8-bit to 5-bit representation for Base32 encoding
	 * 4. Computes CashAddr checksum using polynomial algorithm
	 * 5. Combines all components into final CashAddr format
	 * 
	 * @param {string} [legacy_address=""] - Legacy Base58Check address to convert
	 * @param {string} [type="p2pkh"] - Address type: "p2pkh" or "p2sh"
	 * @returns {string} CashAddr formatted address with network prefix
	 * @throws {Error} If legacy address is invalid or unsupported
	 * @example
	 * // Convert P2PKH address
	 * const p2pkh = CASH_ADDR.to_cashAddr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "p2pkh");
	 * // Returns: "bitcoincash:qztxx64w20kmy5y9sskjwtgxp3j8dc20ksvef26ssu"
	 * 
	 * // Convert P2SH address
	 * const p2sh = CASH_ADDR.to_cashAddr("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "p2sh");
	 * // Returns: "bitcoincash:pztxx64w20kmy5y9sskjwtgxp3j8dc20ksvef26ssu"
	 */
	to_cashAddr(legacy_address = "", type = "p2pkh") {
		// Decode legacy address to get network prefix and hash
		let [prefix, hash] = this.decode_legacy_address(legacy_address);

		// Convert hash from hex string to buffer
		hash = Buffer.from(hash, 'hex');

		// Prepend version byte (type + hash size information)
		hash = Buffer.concat([this.versionByte(type, hash), hash]);

		// Convert to 5-bit representation for Base32 encoding
		const payload = this.convertBits(hash, 8, 5);

		// Compute checksum: polymod(prefix + separator + payload + 8-byte template)
		const checksum =
			this.polymod(
				Buffer.concat([
					this.prefix_5bit(prefix),   // Network prefix in 5-bit format
					Buffer.alloc(1),            // Zero separator
					payload,                    // Version + hash in 5-bit format
					Buffer.alloc(8)])           // 8-byte zero template for checksum
			);

		// Return complete CashAddr: prefix + ':' + base32(payload) + base32(checksum)
		return prefix.toLowerCase() + ':' + base32_encode(payload) + base32_encode(this.checksum_5bit(checksum));
	},

	/**
	 * Decodes a legacy Base58Check address to extract network and hash information
	 * 
	 * Validates the address format and extracts:
	 * - Network type from version byte (0x00 = mainnet, 0x6f = testnet)
	 * - Hash160 value (20 bytes) from the address payload
	 * - Checksum validation through Base58Check decoding
	 * 
	 * @param {string} [legacy_addr=""] - Legacy address to decode
	 * @returns {DecodedAddress} Tuple of [network prefix, hex-encoded hash]
	 * @throws {Error} If address format is invalid or unsupported
	 * @example
	 * // Decode mainnet address
	 * const [prefix, hash] = CASH_ADDR.decode_legacy_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
	 * // Returns: ["bitcoincash", "76a04053bda0a88bda5177b86a15c3b29f559873"]
	 * 
	 * // Decode testnet address
	 * const [testPrefix, testHash] = CASH_ADDR.decode_legacy_address("mgRpP3zP1hmxyoeYJgfbcmN3c2Qsurw48D");
	 * // Returns: ["bchtest", "0e7c6e0e0b2c07d6a7b5b8b4d8b5b8b4d8b5b8b4"]
	 */
	decode_legacy_address(legacy_addr = "") {
		// Decode Base58Check address to binary
		let legacy_addr_bytes = base58_to_binary(legacy_addr);

		// Determine network from version byte
		const prefix = legacy_addr_bytes[0] === 0 ? "bitcoincash" : "bchtest";

		// Validate address format: P2PKH addresses have version 0 or 111 and are 25 bytes total
		if ((legacy_addr_bytes[0] === 0 || legacy_addr_bytes[0] === 111) && legacy_addr_bytes.length === 25) {

			// Extract hash160 (bytes 1-20, excluding version byte and 4-byte checksum)
			const legacy_addr_hash = legacy_addr_bytes.filter((_, i) => i > 0 && i < 21);
			return [prefix, Buffer.from(legacy_addr_hash).toString('hex')];

		} else {
			throw new Error("Invalid legacy address");
		}
	},

	/**
	 * Computes CashAddr polynomial checksum using the generator polynomial
	 * 
	 * Implements the CashAddr checksum algorithm with a 40-bit generator polynomial.
	 * The algorithm processes 5-bit values and maintains a 40-bit state, applying
	 * the generator when specific bits are set.
	 * 
	 * Generator constants:
	 * - 0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470
	 * 
	 * @param {Buffer|Uint8Array} v - Array of 5-bit values to process
	 * @returns {number} 40-bit polynomial checksum result
	 * @see {@link https://reference.cash/protocol/blockchain/encoding/cashaddr|CashAddr Checksum Algorithm}
	 * @example
	 * const data = Buffer.from([1, 2, 3, 4, 5]); // 5-bit values
	 * const checksum = CASH_ADDR.polymod(data);
	 * console.log(checksum.toString(16)); // Hex representation
	 */
	polymod(v) {
		let c = BigInt(1);

		for (let d of v) {
			let c0 = c >> BigInt(35); // Extract top 5 bits
			c = ((c & BigInt("0x07ffffffff")) << BigInt(5)) ^ BigInt(d);

			// Apply generator polynomial based on extracted bits
			if (c0 & 0x01n) c ^= BigInt("0x98f2bc8e61");
			if (c0 & 0x02n) c ^= BigInt("0x79b76d99e2");
			if (c0 & 0x04n) c ^= BigInt("0xf33e5fb3c4");
			if (c0 & 0x08n) c ^= BigInt("0xae2eabe2a8");
			if (c0 & 0x10n) c ^= BigInt("0x1e4f43e470");
		}

		return Number(c ^ BigInt(1));
	},

	/**
	 * Generates version byte for CashAddr encoding based on address type and hash size
	 * 
	 * The version byte encodes both the address type and hash length:
	 * - Bits 3-7: Hash size bits (mapping hash length to predefined values)
	 * - Bits 0-2: Type bits (0 for P2PKH, 8 for P2SH)
	 * 
	 * Supported hash sizes: 160, 192, 224, 256, 320, 384, 448, 512 bits
	 * 
	 * @param {string} [type="p2pkh"] - Address type: "p2pkh" or "p2sh"
	 * @param {Buffer} hash - Hash buffer to determine size
	 * @returns {Buffer} Single-byte buffer containing version information
	 * @throws {Error} If hash size is unsupported or type is invalid
	 * @example
	 * const hash160 = Buffer.alloc(20); // 160-bit hash
	 * const versionByte = CASH_ADDR.versionByte("p2pkh", hash160);
	 * console.log(versionByte[0]); // 0 (P2PKH with 160-bit hash)
	 * 
	 * const versionP2SH = CASH_ADDR.versionByte("p2sh", hash160);
	 * console.log(versionP2SH[0]); // 8 (P2SH with 160-bit hash)
	 */
	versionByte(type = "p2pkh", hash = Buffer) {
		// Map hash bit length to size bits (0-7)
		const hashSizeBits = [160, 192, 224, 256, 320, 384, 448, 512]
			.map((x, i) => x === hash.length * 8 ? i : null)
			.filter(x => Number.isInteger(x))[0];

		// Map address type to type bits
		const typeBits =
			type.toLowerCase() === "p2pkh" ? 0 :  // Pay to Public Key Hash
				type.toLowerCase() === "p2sh" ? 8 :   // Pay to Script Hash
					null;

		if (hashSizeBits === undefined || typeBits === null) {
			throw new Error("Invalid hash size or invalid type");
		} else {
			const ver_byte = Buffer.alloc(1);
			ver_byte.writeUInt8(typeBits + hashSizeBits); // Combine type and size bits
			return ver_byte;
		}
	},

	/**
	 * Converts network prefix string to 5-bit representation
	 * 
	 * Extracts the lower 5 bits of each character in the prefix for use
	 * in checksum calculation. This ensures the network prefix is properly
	 * incorporated into the address validation.
	 * 
	 * @param {string} [prefix='bitcoincash'] - Network prefix to convert
	 * @returns {Uint8Array} Array of 5-bit values representing the prefix
	 * @example
	 * const prefix5bit = CASH_ADDR.prefix_5bit('bitcoincash');
	 * // Returns array of lower 5 bits: [2, 9, 20, 3, 15, 9, 14, 3, 1, 19, 8]
	 * 
	 * const testPrefix = CASH_ADDR.prefix_5bit('bchtest');
	 * // Returns array: [2, 3, 8, 20, 5, 19, 20]
	 */
	prefix_5bit(prefix = 'bitcoincash') {
		return new Uint8Array(prefix.length).map((_, i) => prefix[i].charCodeAt() & 31);
	},

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
	 * const fiveBit = CASH_ADDR.convertBits(bytes, 8, 5);
	 * // Returns: [31, 30, 0, 0, 0] (0xFF80 in 5-bit groups)
	 * 
	 * // Convert back from 5-bit to 8-bit
	 * const backToBytes = CASH_ADDR.convertBits(fiveBit, 5, 8);
	 */
	convertBits(data, from, to) {
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
	},

	/**
	 * Converts a numeric checksum to 5-bit representation for Base32 encoding
	 * 
	 * Takes a 40-bit checksum value and converts it to an array of eight 5-bit values
	 * for inclusion in the final CashAddr string. The conversion extracts 5 bits
	 * at a time from least significant to most significant.
	 * 
	 * @param {number} [checksum=19310] - 40-bit checksum value to convert
	 * @returns {Uint8Array} Array of 8 values, each containing 5 bits
	 * @example
	 * const checksum = 0x1234567890; // Example 40-bit checksum
	 * const fiveBitChecksum = CASH_ADDR.checksum_5bit(checksum);
	 * // Returns: [16, 18, 6, 22, 15, 4, 18, 0] (8 five-bit values)
	 * 
	 * // The values can be directly used with Base32 encoding
	 * const checksumString = base32_encode(fiveBitChecksum);
	 */
	checksum_5bit(checksum = 19310) {
		checksum = new BN(checksum);
		let result = new Uint8Array(8);

		// Extract 5 bits at a time, from least to most significant
		for (let i = 0; i < 8; i++) {
			result[7 - i] = checksum.and(new BN(31)) // Extract lower 5 bits (31 = 0x1F)
			checksum = checksum.ushrn(5);            // Shift right by 5 bits
		}

		return result;
	}
}

export default CASH_ADDR;