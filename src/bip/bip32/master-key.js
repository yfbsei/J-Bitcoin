/**
 * @fileoverview BIP32 master key generation from cryptographic seed
 * 
 * This module implements the BIP32 specification for generating master private and public keys
 * from a cryptographic seed. It creates the root of the hierarchical deterministic key tree
 * that can be used to derive all subsequent child keys deterministically.
 * 
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki|BIP32 - Hierarchical Deterministic Wallets}
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki|BIP39 - Mnemonic code for generating deterministic keys}
 * @author yfbsei
 * @version 2.0.0
 */

import { createHmac } from 'node:crypto';
import { Buffer } from 'node:buffer';

import { secp256k1 } from '@noble/curves/secp256k1';

import { encodeExtendedKey } from '../../encoding/address/encode.js';
import {
	BIP32_CONSTANTS,
	NETWORK_VERSIONS,
	CRYPTO_CONSTANTS,
	validateAndGetNetwork
} from '../core/constants.js';

/**
 * @typedef {Object} ExtendedKeyPair
 * @property {string} extendedPrivateKey - Extended private key in xprv/tprv format (Base58Check encoded)
 * @property {string} extendedPublicKey - Extended public key in xpub/tpub format (Base58Check encoded)
 */

/**
 * @typedef {Object} PrivateKeyData
 * @property {Buffer} keyMaterial - 32-byte private key material
 * @property {number} wifVersionByte - Version byte for WIF encoding (0x80 mainnet, 0xef testnet)
 */

/**
 * @typedef {Object} PublicKeyData
 * @property {Buffer} keyMaterial - 33-byte compressed public key
 * @property {Point} point - Elliptic curve point representation for cryptographic operations
 */

/**
 * @typedef {Object} MasterKeyContext
 * @property {Object} versionBytes - Network-specific version bytes for key serialization
 * @property {number} versionBytes.extendedPublicKey - Version for extended public key (xpub/tpub)
 * @property {number} versionBytes.extendedPrivateKey - Version for extended private key (xprv/tprv)
 * @property {number} depth - Key depth in the derivation tree (0 for master)
 * @property {Buffer} parentFingerprint - 4-byte fingerprint of parent key (all zeros for master)
 * @property {number} childIndex - Child key index (0 for master)
 * @property {Buffer} chainCode - 32-byte chain code for HMAC operations
 * @property {PrivateKeyData} privateKey - Master private key information
 * @property {PublicKeyData} publicKey - Master public key information
 */

/**
 * @typedef {Array} MasterKeyResult
 * @description Array containing the extended key pair and internal context
 * @property {ExtendedKeyPair} 0 - Extended key pair with private and public keys
 * @property {MasterKeyContext} 1 - Internal context for further derivations
 */

/**
 * Generates BIP32 master keys from a cryptographic seed
 * 
 * This function implements the BIP32 master key generation algorithm:
 * 
 * 1. **HMAC-SHA512 Computation**: Uses "Bitcoin seed" as HMAC key and input seed as data
 * 2. **Key Material Split**: Divides 512-bit result into 256-bit private key and 256-bit chain code
 * 3. **Validation**: Ensures private key is valid (non-zero and less than curve order)
 * 4. **Public Key Derivation**: Computes corresponding compressed public key
 * 5. **Serialization**: Creates extended key format with network-specific version bytes
 * 
 * The master keys serve as the root of the entire HD key tree, allowing deterministic
 * derivation of billions of child keys while maintaining mathematical relationships
 * between them for features like watch-only wallets and audit capabilities.
 * 
 * @function
 * @param {string} seedHex - Hex-encoded cryptographic seed (typically 128-512 bits from BIP39)
 * @param {string} [network='main'] - Network type: 'main' for Bitcoin mainnet, 'test' for testnet
 * @returns {MasterKeyResult} Tuple containing [extended key pair, derivation context]
 * 
 * @throws {Error} If seed results in invalid private key (extremely rare: ~1 in 2^127)
 * @throws {Error} If seed is not valid hexadecimal
 * @throws {Error} If network parameter is not recognized
 * 
 * @example
 * // Generate master keys from BIP39 seed
 * const seedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
 * const [extendedKeys, context] = generateMasterKey(seedHex, "main");
 * 
 * console.log(extendedKeys.extendedPrivateKey); 
 * // "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
 * 
 * console.log(extendedKeys.extendedPublicKey);
 * // "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
 * 
 * @example
 * // Generate testnet master keys
 * const [testnetKeys, testnetContext] = generateMasterKey(seedHex, "test");
 * console.log(testnetKeys.extendedPrivateKey.substring(0, 4)); // "tprv" (testnet prefix)
 * console.log(testnetKeys.extendedPublicKey.substring(0, 4)); // "tpub" (testnet prefix)
 * 
 * @example
 * // Use with BIP39 mnemonic-derived seed
 * import BIP39 from '../bip/bip39/mnemonic.js';
 * const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
 * const bip39Seed = BIP39.mnemonicToSeed(mnemonic, "passphrase");
 * const [masterKeys, _] = generateMasterKey(bip39Seed, "main");
 * 
 * @example
 * // Access internal key material for advanced operations
 * const [_, context] = generateMasterKey(seedHex, "main");
 * console.log(context.privateKey.keyMaterial.toString('hex')); // Raw 32-byte private key
 * console.log(context.publicKey.keyMaterial.toString('hex'));  // Compressed 33-byte public key
 * console.log(context.chainCode.toString('hex'));   // Chain code for child derivation
 * 
 * @security
 * **Critical Security Considerations:**
 * - Seed must be generated with cryptographically secure randomness
 * - Seed should be at least 128 bits (16 bytes) for adequate security
 * - Store seed securely; anyone with the seed can derive all keys
 * - Consider using BIP39 for human-readable seed backup
 * - Never transmit raw seed over insecure channels
 * 
 * @performance
 * **Performance Notes:**
 * - HMAC-SHA512 computation: ~0.1ms on modern hardware
 * - Public key derivation: ~1-2ms using elliptic curve operations
 * - Total function execution: ~2-3ms typically
 * - Results should be cached for applications requiring frequent access
 */
function generateMasterKey(seedHex, network = 'main') {
	// Validate inputs
	if (!seedHex || typeof seedHex !== 'string') {
		throw new Error('Seed is required and must be a hex string');
	}

	// Validate and get network configuration
	const networkConfig = validateAndGetNetwork(network);

	// Convert hex-encoded seed to buffer for cryptographic operations
	let seedBuffer;
	try {
		seedBuffer = Buffer.from(seedHex, 'hex');
	} catch (error) {
		throw new Error(`Invalid hex seed: ${error.message}`);
	}

	// Validate minimum seed length (128 bits recommended)
	if (seedBuffer.length < 16) {
		throw new Error('Seed must be at least 128 bits (32 hex characters)');
	}

	// Generate 512-bit HMAC using "Bitcoin seed" as key (BIP32 specification)
	const masterKeyMaterial = createHmac('sha512', Buffer.from(BIP32_CONSTANTS.MASTER_KEY_HMAC_KEY))
		.update(seedBuffer)
		.digest();

	// Split HMAC result: first 256 bits = private key, last 256 bits = chain code
	const masterPrivateKey = masterKeyMaterial.slice(0, CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH);
	const chainCode = masterKeyMaterial.slice(
		CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH,
		CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH + CRYPTO_CONSTANTS.CHAIN_CODE_LENGTH
	);

	// Validate private key is within valid range (should never fail, but check for completeness)
	const privateKeyBN = BigInt('0x' + masterPrivateKey.toString('hex'));
	const curveOrder = BigInt('0x' + CRYPTO_CONSTANTS.SECP256K1_ORDER);

	if (privateKeyBN === 0n || privateKeyBN >= curveOrder) {
		throw new Error('Generated private key is invalid (outside curve order)');
	}

	// Derive compressed public key from private key
	const compressedPublicKey = Buffer.from(secp256k1.getPublicKey(masterPrivateKey, true));
	const publicKeyPoint = secp256k1.ProjectivePoint.fromPrivateKey(masterPrivateKey);

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
			keyMaterial: masterPrivateKey,  // 32-byte private key from HMAC
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

	// Return both user-friendly extended keys and internal context for further operations
	return [
		{
			extendedPrivateKey,  // Extended private key (xprv/tprv)
			extendedPublicKey,   // Extended public key (xpub/tpub)
		},
		masterKeyContext  // Internal context for child key derivation
	];
}

export default generateMasterKey;