/**
 * @fileoverview BIP39 implementation for mnemonic phrase generation and seed derivation
 * 
 * This module implements the BIP39 specification for generating deterministic keys
 * from mnemonic phrases. It supports 12-word mnemonics with checksum validation
 * and PBKDF2-based seed generation with optional passphrases.
 * 
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki|BIP39 Specification}
 * @author yfbsei
 * @version 1.0.0
 */

import { createHash, randomBytes, pbkdf2Sync } from 'node:crypto';
import wordList_en from './wordList_en.js';

/**
 * @typedef {Object} MnemonicResult
 * @property {string} mnemonic - 12-word mnemonic phrase
 * @property {string} seed - Hex-encoded 64-byte seed derived from mnemonic
 */

/**
 * BIP39 mnemonic and seed generation utilities
 * 
 * Provides functionality for generating secure mnemonic phrases, validating checksums,
 * and deriving cryptographic seeds according to the BIP39 standard.
 * 
 * @namespace BIP39
 * @example
 * // Generate a random mnemonic and seed
 * const { mnemonic, seed } = BIP39.random('my-passphrase');
 * 
 * // Validate an existing mnemonic
 * const isValid = BIP39.checkSum(mnemonic);
 * 
 * // Convert mnemonic to seed
 * const seed = BIP39.mnemonic2seed(mnemonic, 'passphrase');
 */
const BIP39 = {

	/**
	 * Generates a random 12-word mnemonic phrase using cryptographically secure entropy
	 * 
	 * The function:
	 * 1. Generates 16 bytes (128 bits) of secure random entropy
	 * 2. Computes SHA256 hash and takes first 4 bits as checksum
	 * 3. Concatenates entropy + checksum to create 132 bits
	 * 4. Splits into 12 groups of 11 bits each
	 * 5. Maps each 11-bit value to a word from the BIP39 wordlist
	 * 
	 * @returns {string} Space-separated 12-word mnemonic phrase
	 * @example
	 * const mnemonic = BIP39.mnemonic();
	 * // Returns: "abandon ability able about above absent absorb abstract absurd abuse access accident"
	 */
	mnemonic() {
		// Generate 16 bytes of cryptographically secure random data
		const buf = randomBytes(16);

		// Calculate SHA256 hash for checksum
		const hash = createHash('sha256').update(buf).digest();

		// Convert entropy to binary string (128 bits) + checksum (4 bits) = 132 bits total
		const bin = buf.reduce((str, byte) => str + byte.toString(2).padStart(8, '0'), '') +
			('00000000' + hash[0].toString(2)).slice(-8).slice(0, (16 * 8) / 32);

		// Split 132 bits into 12 groups of 11 bits, convert to word indices, map to words
		return [...Array(12).keys()]
			.map(i => parseInt(bin.slice(i * 11, (i + 1) * 11), 2))
			.map(w => wordList_en[w])
			.toString()
			.replaceAll(',', ' ');
	},

	/**
	 * Derives a cryptographic seed from a mnemonic phrase using PBKDF2
	 * 
	 * Uses PBKDF2-HMAC-SHA512 with 2048 iterations as specified in BIP39.
	 * The salt is constructed as "mnemonic" + passphrase.
	 * 
	 * @param {string} [mnemonic=''] - Space-separated mnemonic phrase
	 * @param {string} [passphrase=''] - Optional passphrase for additional security
	 * @returns {string} Hex-encoded 64-byte (512-bit) seed
	 * @example
	 * const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	 * const seed = BIP39.seed(mnemonic, "my-passphrase");
	 * // Returns 128-character hex string
	 */
	seed(mnemonic = '', passphrase = '') {
		// Prepare secret (mnemonic) and salt ("mnemonic" + passphrase)
		const secret = Buffer.from(mnemonic);
		const salt = Buffer.concat([
			Buffer.from('mnemonic'),
			Buffer.from(passphrase)
		]);

		// Derive 64-byte seed using PBKDF2-HMAC-SHA512 with 2048 iterations
		const seed = pbkdf2Sync(secret, salt, 2048, 64, 'sha512');

		return seed.toString('hex');
	},

	/**
	 * Validates the checksum of a BIP39 mnemonic phrase
	 * 
	 * The validation process:
	 * 1. Converts words back to 11-bit indices
	 * 2. Concatenates all indices to reconstruct the binary data
	 * 3. Splits into entropy (128 bits) and checksum (4 bits)
	 * 4. Recalculates checksum from entropy using SHA256
	 * 5. Compares calculated checksum with embedded checksum
	 * 
	 * @param {string} [mnemonic=''] - Space-separated mnemonic phrase to validate
	 * @returns {boolean} True if checksum is valid, false otherwise
	 * @example
	 * const validMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	 * const isValid = BIP39.checkSum(validMnemonic); // true
	 * 
	 * const invalidMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
	 * const isInvalid = BIP39.checkSum(invalidMnemonic); // false
	 */
	checkSum(mnemonic = '') {
		// Convert mnemonic words back to binary representation
		const bin = mnemonic.split(' ')
			.map(x => wordList_en.indexOf(x))  // Get word index
			.reduce((str, byte) => str + byte.toString(2).padStart(11, '0'), ''); // Convert to 11-bit binary

		// Extract entropy (first 128 bits) and convert to bytes
		const buf = Buffer.from([...Array(16).keys()]
			.map(i => parseInt(bin.slice(i * 8, (i + 1) * 8), 2)));

		// Calculate expected checksum from entropy
		const hash = createHash('sha256').update(buf).digest();
		const expectedChecksum = [hash[0].toString(2)]
			.reduce((str, byte) => str + byte.toString(2).padStart(8, '0'), '')
			.slice(0, 4);

		// Compare expected checksum with embedded checksum (last 4 bits)
		return expectedChecksum === bin.slice(-4);
	},

	/**
	 * Generates a random mnemonic with validated checksum and derives its seed
	 * 
	 * This is a convenience method that combines mnemonic generation and seed derivation
	 * with built-in checksum validation for additional security.
	 * 
	 * @param {string} [passphrase=''] - Optional passphrase for seed derivation
	 * @returns {MnemonicResult} Object containing both mnemonic and seed
	 * @throws {string} Throws 'invalid checksum' if generated mnemonic fails validation
	 * @example
	 * const { mnemonic, seed } = BIP39.random('my-secure-passphrase');
	 * console.log(mnemonic); // "word1 word2 word3 ..."
	 * console.log(seed);     // "a1b2c3d4e5f6..."
	 */
	random(passphrase = '') {
		const mnemonic = this.mnemonic();

		// Validate the generated mnemonic before returning
		if (this.checkSum(mnemonic)) {
			return {
				mnemonic,
				seed: this.seed(mnemonic, passphrase)
			}
		}
		else {
			throw 'invalid checksum';
		}
	},

	/**
	 * Converts a mnemonic phrase to a seed with checksum validation
	 * 
	 * This method validates the mnemonic's checksum before deriving the seed,
	 * ensuring that only valid mnemonics are processed.
	 * 
	 * @param {string} [mnemonic=''] - Space-separated mnemonic phrase
	 * @param {string} [passphrase=''] - Optional passphrase for additional security
	 * @returns {string} Hex-encoded 64-byte seed
	 * @throws {string} Throws 'invalid checksum' if mnemonic validation fails
	 * @example
	 * const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	 * const seed = BIP39.mnemonic2seed(mnemonic, "passphrase");
	 * 
	 * // With invalid mnemonic
	 * try {
	 *   const seed = BIP39.mnemonic2seed("invalid mnemonic phrase");
	 * } catch (error) {
	 *   console.log(error); // "invalid checksum"
	 * }
	 */
	mnemonic2seed(mnemonic = '', passphrase = '') {
		if (this.checkSum(mnemonic)) {
			return this.seed(mnemonic, passphrase);
		}
		else {
			throw 'invalid checksum';
		}
	}

}

export default BIP39;