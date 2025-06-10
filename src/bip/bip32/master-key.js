/**
 * @fileoverview Enhanced BIP32 master key generation with critical security fixes
 * 
 * SECURITY IMPROVEMENTS (v2.1.1):
 * - FIX #2: Added validation for invalid master keys (IL ≥ n or IL = 0)
 * - FIX #5: Enhanced seed validation and boundary checks
 * - FIX #6: Secure memory clearing of sensitive data
 * - FIX #12: Cross-implementation compatibility validation
 * - FIX #13: Missing import fixes and proper error handling
 * - FIX #14: Corrected HMAC clearing and buffer management
 * 
 * @author yfbsei
 * @version 2.1.1
 */

import { createHmac, randomBytes } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { secp256k1 } from '@noble/curves/secp256k1';
import { encodeExtendedKey } from '../../encoding/address/encode.js';
import {
	BIP32_CONSTANTS,
	CRYPTO_CONSTANTS,
	validateAndGetNetwork
} from '../../constants.js';
import BN from 'bn.js';

/**
 * Enhanced security utilities for BIP32 operations
 */
class BIP32SecurityUtils {
	/**
	 * FIX #2: CRITICAL - Validates master key according to BIP32 specification
	 * Must check: parse256(IL) ≠ 0 and parse256(IL) < n (secp256k1 order)
	 */
	static validateMasterKey(privateKeyMaterial, chainCode) {
		if (!Buffer.isBuffer(privateKeyMaterial) || privateKeyMaterial.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH) {
			throw new Error(`Invalid private key material length: expected ${CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH}, got ${privateKeyMaterial?.length || 'undefined'}`);
		}

		if (!Buffer.isBuffer(chainCode) || chainCode.length !== CRYPTO_CONSTANTS.CHAIN_CODE_LENGTH) {
			throw new Error(`Invalid chain code length: expected ${CRYPTO_CONSTANTS.CHAIN_CODE_LENGTH}, got ${chainCode?.length || 'undefined'}`);
		}

		const keyBN = new BN(privateKeyMaterial);
		const curveOrder = new BN(CRYPTO_CONSTANTS.SECP256K1_ORDER, 'hex');

		// BIP32 CRITICAL requirement: validate IL ≠ 0 and IL < n
		if (keyBN.isZero()) {
			throw new Error('CRITICAL: Invalid master key - private key is zero. Must generate new seed.');
		}

		if (keyBN.gte(curveOrder)) {
			throw new Error('CRITICAL: Invalid master key - private key >= curve order. Must generate new seed.');
		}

		// Additional validation: ensure key is not obviously weak
		const keyHex = privateKeyMaterial.toString('hex');

		// Check for obviously weak keys (all same bytes)
		const allSame = privateKeyMaterial.every(byte => byte === privateKeyMaterial[0]);
		if (allSame) {
			throw new Error('CRITICAL: Weak master key detected - all bytes identical. Must generate new seed.');
		}

		// Check for keys that are too close to curve order
		const nearOrder = curveOrder.sub(keyBN);
		if (nearOrder.lt(new BN(1000))) {
			console.warn('⚠️  WARNING: Master key is very close to curve order');
		}

		return true;
	}

	/**
	 * FIX #5: Enhanced seed validation
	 */
	static validateSeedInput(seedHex, network) {
		if (!seedHex || typeof seedHex !== 'string') {
			throw new Error('Seed is required and must be a hex string');
		}

		// Validate hex format
		const hexRegex = /^[0-9a-fA-F]+$/;
		if (!hexRegex.test(seedHex)) {
			throw new Error('Seed must be a valid hexadecimal string');
		}

		// Validate seed length (must be even number of hex characters)
		if (seedHex.length % 2 !== 0) {
			throw new Error('Seed hex string must have even length');
		}

		const byteLength = seedHex.length / 2;

		// BIP39 seeds are typically 64 bytes, but BIP32 allows 128-512 bits (16-64 bytes)
		if (byteLength < ENHANCED_BIP32_CONSTANTS.MIN_SEED_BYTES || byteLength > ENHANCED_BIP32_CONSTANTS.MAX_SEED_BYTES) {
			throw new Error(
				`Seed length must be between ${ENHANCED_BIP32_CONSTANTS.MIN_SEED_BYTES}-${ENHANCED_BIP32_CONSTANTS.MAX_SEED_BYTES} bytes, got ${byteLength} bytes`
			);
		}

		// Validate network parameter
		if (network !== 'main' && network !== 'test') {
			throw new Error(`Invalid network: ${network}. Must be 'main' or 'test'`);
		}

		return true;
	}

	/**
	 * FIX #6: Secure memory clearing with proper buffer handling
	 */
	static secureClear(buffer) {
		if (Buffer.isBuffer(buffer)) {
			// Overwrite with cryptographically secure random data first
			try {
				const random = randomBytes(buffer.length);
				random.copy(buffer);
				buffer.fill(0);
				// Clear the random buffer too
				random.fill(0);
			} catch (error) {
				// If random generation fails, still clear with patterns
				buffer.fill(0xAA);
				buffer.fill(0x55);
				buffer.fill(0x00);
			}
		}
	}

	/**
	 * FIX #12: Validate extended key format for cross-compatibility
	 */
	static validateExtendedKeyFormat(extendedKey, expectedType) {
		if (!extendedKey || typeof extendedKey !== 'string') {
			throw new Error('Extended key must be a non-empty string');
		}

		// Validate Base58 format and length
		const base58Regex = /^[1-9A-HJ-NP-Za-km-z]+$/;
		if (!base58Regex.test(extendedKey)) {
			throw new Error('Extended key contains invalid Base58 characters');
		}

		// Extended keys should be exactly 111 characters when Base58-encoded
		if (extendedKey.length !== 111) {
			throw new Error(`Invalid extended key length: expected 111 characters, got ${extendedKey.length}`);
		}

		// Validate prefix matches expected type
		const validPrefixes = {
			xprv: ['xprv'], // mainnet private
			xpub: ['xpub'], // mainnet public
			tprv: ['tprv'], // testnet private
			tpub: ['tpub']  // testnet public
		};

		if (expectedType && validPrefixes[expectedType]) {
			const hasValidPrefix = validPrefixes[expectedType].some(prefix =>
				extendedKey.startsWith(prefix)
			);

			if (!hasValidPrefix) {
				throw new Error(
					`Extended key has wrong prefix for type ${expectedType}. ` +
					`Expected: ${validPrefixes[expectedType].join(' or ')}, ` +
					`got: ${extendedKey.substring(0, 4)}`
				);
			}
		}

		return true;
	}

	/**
	 * Validates that the implementation produces Bitcoin Core compatible results
	 */
	static validateBitcoinCoreCompatibility(masterKeys, seedHex) {
		// Test against known Bitcoin Core test vectors
		const knownTestVectors = [
			{
				seed: '000102030405060708090a0b0c0d0e0f',
				expectedXprv: 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
				expectedXpub: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
			}
		];

		for (const vector of knownTestVectors) {
			if (seedHex === vector.seed) {
				if (masterKeys.extendedPrivateKey !== vector.expectedXprv) {
					throw new Error(
						`Bitcoin Core compatibility check failed for xprv. ` +
						`Expected: ${vector.expectedXprv}, ` +
						`Got: ${masterKeys.extendedPrivateKey}`
					);
				}

				if (masterKeys.extendedPublicKey !== vector.expectedXpub) {
					throw new Error(
						`Bitcoin Core compatibility check failed for xpub. ` +
						`Expected: ${vector.expectedXpub}, ` +
						`Got: ${masterKeys.extendedPublicKey}`
					);
				}

				console.log('✅ Bitcoin Core compatibility verified');
				break;
			}
		}
	}

	/**
	 * FIX #14: Secure HMAC clearing
	 */
	static clearHMAC(hmac) {
		try {
			// Clear HMAC internal state if possible
			if (hmac && typeof hmac.destroy === 'function') {
				hmac.destroy();
			}
		} catch (error) {
			// Ignore cleanup errors, but log them
			console.warn('⚠️  Warning: Could not properly clear HMAC state');
		}
	}
}

/**
 * Enhanced constants with additional validation parameters
 */
const ENHANCED_BIP32_CONSTANTS = {
	...BIP32_CONSTANTS,
	MIN_SEED_BYTES: 16,  // 128 bits minimum
	MAX_SEED_BYTES: 64,  // 512 bits maximum
	MASTER_KEY_RETRY_LIMIT: 1000 // Maximum retries for invalid master key
};

/**
 * FIX #2: Enhanced master key generation with invalid key handling
 */
function generateMasterKey(seedHex, network = 'main') {
	// FIX #5: Enhanced input validation
	BIP32SecurityUtils.validateSeedInput(seedHex, network);

	// Validate and get network configuration
	const networkConfig = validateAndGetNetwork(network);

	// Convert hex-encoded seed to buffer for cryptographic operations
	let seedBuffer;
	try {
		seedBuffer = Buffer.from(seedHex, 'hex');
	} catch (error) {
		throw new Error(`Invalid hex seed: ${error.message}`);
	}

	let masterKeyMaterial;
	let chainCode;
	let attemptCount = 0;
	let hmacResult;

	// FIX #2: Retry until we get a valid master key (BIP32 requirement)
	while (attemptCount < ENHANCED_BIP32_CONSTANTS.MASTER_KEY_RETRY_LIMIT) {
		attemptCount++;

		// Generate 512-bit HMAC using "Bitcoin seed" as key (BIP32 specification)
		const hmac = createHmac('sha512', Buffer.from(BIP32_CONSTANTS.MASTER_KEY_HMAC_KEY));
		hmacResult = hmac.update(seedBuffer).digest();

		// Split HMAC result: first 256 bits = private key, last 256 bits = chain code
		masterKeyMaterial = hmacResult.slice(0, CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH);
		chainCode = hmacResult.slice(
			CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH,
			CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH + CRYPTO_CONSTANTS.CHAIN_CODE_LENGTH
		);

		try {
			// FIX #2: CRITICAL - Validate master key according to BIP32
			BIP32SecurityUtils.validateMasterKey(masterKeyMaterial, chainCode);

			// If we get here, the key is valid
			break;

		} catch (error) {
			if (attemptCount >= ENHANCED_BIP32_CONSTANTS.MASTER_KEY_RETRY_LIMIT) {
				throw new Error(
					`Failed to generate valid master key after ${attemptCount} attempts. ` +
					`This is extremely rare (~1 in 2^127). Please use a different seed.`
				);
			}

			// For retry, we modify the seed slightly
			// In practice, you would typically use a completely different seed
			console.warn(`⚠️  Invalid master key (attempt ${attemptCount}), retrying...`);
			const hmacForSeed = createHmac('sha256', seedBuffer);
			seedBuffer = hmacForSeed.update(Buffer.from([attemptCount])).digest();

			// Clear the invalid key material
			BIP32SecurityUtils.secureClear(masterKeyMaterial);
			BIP32SecurityUtils.secureClear(chainCode);
			BIP32SecurityUtils.secureClear(hmacResult);

			// Clear HMAC states
			BIP32SecurityUtils.clearHMAC(hmac);
			BIP32SecurityUtils.clearHMAC(hmacForSeed);
		}
	}

	try {
		// Derive compressed public key from private key
		const compressedPublicKey = Buffer.from(secp256k1.getPublicKey(masterKeyMaterial, true));
		const publicKeyPoint = secp256k1.ProjectivePoint.fromPrivateKey(masterKeyMaterial);

		// Create master key context according to BIP32
		const masterKeyContext = {
			// Network-specific version bytes for extended key serialization
			versionBytes: {
				extendedPublicKey: networkConfig.versions.EXTENDED_PUBLIC_KEY,
				extendedPrivateKey: networkConfig.versions.EXTENDED_PRIVATE_KEY
			},

			// Master key always has depth 0 (root of tree)
			depth: BIP32_CONSTANTS.MASTER_KEY_DEPTH,

			// Master key has no parent, so fingerprint is all zeros
			parentFingerprint: BIP32_CONSTANTS.ZERO_PARENT_FINGERPRINT,

			// Master key index is always 0
			childIndex: BIP32_CONSTANTS.MASTER_CHILD_INDEX,

			// Chain code from HMAC (used for child key derivation)
			chainCode: chainCode,

			// Master private key information
			privateKey: {
				keyMaterial: masterKeyMaterial,  // 32-byte private key from HMAC
				wifVersionByte: networkConfig.versions.WIF_PRIVATE_KEY  // WIF version byte
			},

			// Master public key information
			publicKey: {
				keyMaterial: compressedPublicKey,  // Compressed public key (33 bytes)
				point: publicKeyPoint              // Elliptic curve point for operations
			}
		};

		// Generate extended keys using the context
		const extendedPrivateKey = encodeExtendedKey('private', masterKeyContext);
		const extendedPublicKey = encodeExtendedKey('public', masterKeyContext);

		// FIX #12: Validate extended key format
		BIP32SecurityUtils.validateExtendedKeyFormat(extendedPrivateKey, network === 'main' ? 'xprv' : 'tprv');
		BIP32SecurityUtils.validateExtendedKeyFormat(extendedPublicKey, network === 'main' ? 'xpub' : 'tpub');

		const result = {
			extendedPrivateKey,  // Extended private key (xprv/tprv)
			extendedPublicKey,   // Extended public key (xpub/tpub)
		};

		// FIX #12: Validate Bitcoin Core compatibility if using known test vectors
		try {
			BIP32SecurityUtils.validateBitcoinCoreCompatibility(result, seedHex);
		} catch (error) {
			// Only log warning for unknown seeds
			if (seedHex === '000102030405060708090a0b0c0d0e0f') {
				throw error; // This is a known test vector, should match exactly
			} else {
				console.warn(`⚠️  Bitcoin Core compatibility check skipped: ${error.message}`);
			}
		}

		return [result, masterKeyContext];

	} finally {
		// FIX #6: Always clear sensitive data, even on success
		if (seedBuffer) {
			BIP32SecurityUtils.secureClear(seedBuffer);
		}
		if (hmacResult) {
			BIP32SecurityUtils.secureClear(hmacResult);
		}
		// Note: Don't clear masterKeyMaterial and chainCode here as they're still needed
		// They will be cleared when the masterKeyContext is no longer needed
	}
}

/**
 * Enhanced master key generation with secure cleanup
 */
function generateMasterKeySecure(seedHex, network = 'main') {
	try {
		return generateMasterKey(seedHex, network);
	} catch (error) {
		// Ensure no sensitive data leaks in error messages
		if (error.message.includes(seedHex)) {
			throw new Error('Master key generation failed - invalid seed parameters');
		}
		throw error;
	}
}

/**
 * Utility function to validate master key generation
 */
function validateMasterKeyGeneration() {
	console.log('🧪 Validating BIP32 master key generation...');

	// Test with known Bitcoin Core test vector
	const testSeed = '000102030405060708090a0b0c0d0e0f';
	const expectedXprv = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi';

	try {
		const [masterKeys] = generateMasterKey(testSeed, 'main');

		if (masterKeys.extendedPrivateKey !== expectedXprv) {
			throw new Error('Master key generation test failed');
		}

		console.log('✅ BIP32 master key generation validation passed');
		return true;
	} catch (error) {
		console.error('❌ BIP32 master key generation validation failed:', error.message);
		return false;
	}
}

/**
 * FIX #13: Cleanup function for master key context
 */
function clearMasterKeyContext(masterKeyContext) {
	if (!masterKeyContext) return;

	try {
		// Clear private key material
		if (masterKeyContext.privateKey?.keyMaterial) {
			BIP32SecurityUtils.secureClear(masterKeyContext.privateKey.keyMaterial);
		}

		// Clear chain code
		if (masterKeyContext.chainCode) {
			BIP32SecurityUtils.secureClear(masterKeyContext.chainCode);
		}

		// Clear public key material
		if (masterKeyContext.publicKey?.keyMaterial) {
			BIP32SecurityUtils.secureClear(masterKeyContext.publicKey.keyMaterial);
		}

		// Clear parent fingerprint
		if (masterKeyContext.parentFingerprint) {
			BIP32SecurityUtils.secureClear(masterKeyContext.parentFingerprint);
		}

		console.log('✅ Master key context cleared securely');
	} catch (error) {
		console.warn('⚠️  Warning: Error during master key context cleanup:', error.message);
	}
}

export {
	BIP32SecurityUtils,
	ENHANCED_BIP32_CONSTANTS,
	generateMasterKey,
	generateMasterKeySecure,
	validateMasterKeyGeneration,
	clearMasterKeyContext
};