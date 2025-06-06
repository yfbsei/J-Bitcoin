/**
 * @fileoverview BIP39 mnemonic phrase generation and seed derivation
 * 
 * This module implements the BIP39 specification for generating deterministic keys
 * from mnemonic phrases. It supports 12-word mnemonics with checksum validation
 * and PBKDF2-based seed generation with optional passphrases.
 * 
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki|BIP39 Specification}
 * @author yfbsei
 * @version 2.0.0
 */

import { createHash, randomBytes, pbkdf2Sync } from 'node:crypto';
import ENGLISH_WORDLIST from './wordlist-en.js';

/**
 * BIP39 specification constants
 * @constant {Object}
 */
const BIP39_CONSTANTS = {
	ENTROPY_BITS: 128,
	CHECKSUM_BITS: 4,
	WORD_COUNT: 12,
	BITS_PER_WORD: 11,
	PBKDF2_ITERATIONS: 2048,
	SEED_LENGTH_BYTES: 64,
	MNEMONIC_SALT_PREFIX: 'mnemonic'
};

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
 */
const BIP39 = {

	/**
	 * Generates a random 12-word mnemonic phrase using cryptographically secure entropy
	 * 
	 * The function follows BIP39 specification:
	 * 1. Generates 16 bytes (128 bits) of secure random entropy
	 * 2. Computes SHA256 hash and takes first 4 bits as checksum
	 * 3. Concatenates entropy + checksum to create 132 bits
	 * 4. Splits into 12 groups of 11 bits each
	 * 5. Maps each 11-bit value to a word from the BIP39 wordlist
	 * 
	 * @returns {string} Space-separated 12-word mnemonic phrase
	 * @throws {Error} If entropy generation fails
	 * 
	 * @example
	 * const mnemonic = BIP39.generateMnemonic();
	 * console.log(mnemonic);
	 * // "abandon ability able about above absent absorb abstract absurd abuse access accident"
	 */
	generateMnemonic() {
		// Generate cryptographically secure entropy
		const entropyBytes = randomBytes(BIP39_CONSTANTS.ENTROPY_BITS / 8);

		// Calculate SHA256 hash for checksum computation
		const entropyHash = createHash('sha256').update(entropyBytes).digest();

		// Convert entropy to binary string representation
		const entropyBinary = entropyBytes.reduce((binaryString, byte) =>
			binaryString + byte.toString(2).padStart(8, '0'), '');

		// Extract checksum bits from hash (first 4 bits)
		const checksumBinary = entropyHash[0].toString(2).padStart(8, '0')
			.slice(0, BIP39_CONSTANTS.CHECKSUM_BITS);

		// Combine entropy and checksum (132 bits total)
		const completeBinary = entropyBinary + checksumBinary;

		// Convert to mnemonic words
		const mnemonicWords = [];
		for (let i = 0; i < BIP39_CONSTANTS.WORD_COUNT; i++) {
			const startBit = i * BIP39_CONSTANTS.BITS_PER_WORD;
			const endBit = startBit + BIP39_CONSTANTS.BITS_PER_WORD;
			const wordIndex = parseInt(completeBinary.slice(startBit, endBit), 2);
			mnemonicWords.push(ENGLISH_WORDLIST[wordIndex]);
		}

		return mnemonicWords.join(' ');
	},

	/**
	 * Derives a cryptographic seed from a mnemonic phrase using PBKDF2
	 * 
	 * Uses PBKDF2-HMAC-SHA512 with 2048 iterations as specified in BIP39.
	 * The salt is constructed as "mnemonic" + passphrase.
	 * 
	 * @param {string} mnemonicPhrase - Space-separated mnemonic phrase
	 * @param {string} [passphrase=''] - Optional passphrase for additional security
	 * @returns {string} Hex-encoded 64-byte (512-bit) seed
	 * @throws {Error} If mnemonic phrase is empty or invalid
	 * 
	 * @example
	 * const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	 * const seed = BIP39.deriveSeed(mnemonic, "my-passphrase");
	 * console.log(seed.length); // 128 hex characters (64 bytes)
	 */
	deriveSeed(mnemonicPhrase, passphrase = '') {
		if (!mnemonicPhrase || typeof mnemonicPhrase !== 'string') {
			throw new Error('Mnemonic phrase is required and must be a string');
		}

		// Prepare PBKDF2 inputs according to BIP39 specification
		const secretData = Buffer.from(mnemonicPhrase.trim(), 'utf8');
		const saltData = Buffer.concat([
			Buffer.from(BIP39_CONSTANTS.MNEMONIC_SALT_PREFIX, 'utf8'),
			Buffer.from(passphrase, 'utf8')
		]);

		// Derive seed using PBKDF2-HMAC-SHA512
		const seedBytes = pbkdf2Sync(
			secretData,
			saltData,
			BIP39_CONSTANTS.PBKDF2_ITERATIONS,
			BIP39_CONSTANTS.SEED_LENGTH_BYTES,
			'sha512'
		);

		return seedBytes.toString('hex');
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
	 * @param {string} mnemonicPhrase - Space-separated mnemonic phrase to validate
	 * @returns {boolean} True if checksum is valid, false otherwise
	 * @throws {Error} If mnemonic format is invalid
	 * 
	 * @example
	 * const validMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	 * const isValid = BIP39.validateChecksum(validMnemonic); // true
	 * 
	 * const invalidMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
	 * const isInvalid = BIP39.validateChecksum(invalidMnemonic); // false
	 */
	validateChecksum(mnemonicPhrase) {
		if (!mnemonicPhrase || typeof mnemonicPhrase !== 'string') {
			throw new Error('Mnemonic phrase is required and must be a string');
		}

		const words = mnemonicPhrase.trim().split(/\s+/);

		if (words.length !== BIP39_CONSTANTS.WORD_COUNT) {
			throw new Error(`Invalid mnemonic length: expected ${BIP39_CONSTANTS.WORD_COUNT} words, got ${words.length}`);
		}

		// Convert words back to binary representation
		let completeBinary = '';
		for (const word of words) {
			const wordIndex = ENGLISH_WORDLIST.indexOf(word);
			if (wordIndex === -1) {
				throw new Error(`Invalid word in mnemonic: "${word}"`);
			}
			completeBinary += wordIndex.toString(2).padStart(BIP39_CONSTANTS.BITS_PER_WORD, '0');
		}

		// Split into entropy and embedded checksum
		const entropyBinary = completeBinary.slice(0, BIP39_CONSTANTS.ENTROPY_BITS);
		const embeddedChecksum = completeBinary.slice(BIP39_CONSTANTS.ENTROPY_BITS);

		// Reconstruct entropy bytes for checksum calculation
		const entropyBytes = [];
		for (let i = 0; i < BIP39_CONSTANTS.ENTROPY_BITS; i += 8) {
			const byteBinary = entropyBinary.slice(i, i + 8);
			entropyBytes.push(parseInt(byteBinary, 2));
		}

		// Calculate expected checksum from entropy
		const entropyBuffer = Buffer.from(entropyBytes);
		const entropyHash = createHash('sha256').update(entropyBuffer).digest();
		const expectedChecksum = entropyHash[0].toString(2).padStart(8, '0')
			.slice(0, BIP39_CONSTANTS.CHECKSUM_BITS);

		return expectedChecksum === embeddedChecksum;
	},

	/**
	 * Generates a random mnemonic with validated checksum and derives its seed
	 * 
	 * This is a convenience method that combines mnemonic generation and seed derivation
	 * with built-in checksum validation for additional security.
	 * 
	 * @param {string} [passphrase=''] - Optional passphrase for seed derivation
	 * @returns {MnemonicResult} Object containing both mnemonic and seed
	 * @throws {Error} If generated mnemonic fails validation (should never occur)
	 * 
	 * @example
	 * const { mnemonic, seed } = BIP39.generateRandom('my-secure-passphrase');
	 * console.log('Mnemonic:', mnemonic); // "word1 word2 word3 ..."
	 * console.log('Seed:', seed);         // "a1b2c3d4e5f6..."
	 */
	generateRandom(passphrase = '') {
		const mnemonicPhrase = this.generateMnemonic();

		// Validate the generated mnemonic before returning
		if (!this.validateChecksum(mnemonicPhrase)) {
			throw new Error('Generated mnemonic failed checksum validation');
		}

		return {
			mnemonic: mnemonicPhrase,
			seed: this.deriveSeed(mnemonicPhrase, passphrase)
		};
	},

	/**
	 * Converts a mnemonic phrase to a seed with checksum validation
	 * 
	 * This method validates the mnemonic's checksum before deriving the seed,
	 * ensuring that only valid mnemonics are processed.
	 * 
	 * @param {string} mnemonicPhrase - Space-separated mnemonic phrase
	 * @param {string} [passphrase=''] - Optional passphrase for additional security
	 * @returns {string} Hex-encoded 64-byte seed
	 * @throws {Error} If mnemonic validation fails
	 * 
	 * @example
	 * const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	 * const seed = BIP39.mnemonicToSeed(mnemonic, "passphrase");
	 * 
	 * // With invalid mnemonic
	 * try {
	 *   const seed = BIP39.mnemonicToSeed("invalid mnemonic phrase");
	 * } catch (error) {
	 *   console.log(error.message); // "Invalid mnemonic length: expected 12 words, got 3"
	 * }
	 */
	mnemonicToSeed(mnemonicPhrase, passphrase = '') {
		if (!this.validateChecksum(mnemonicPhrase)) {
			throw new Error('Invalid mnemonic: checksum validation failed');
		}

		return this.deriveSeed(mnemonicPhrase, passphrase);
	}
};

export default BIP39;