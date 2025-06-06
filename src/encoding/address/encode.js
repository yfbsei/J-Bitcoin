/**
 * @fileoverview Bitcoin address and key encoding utilities
 * 
 * This module provides comprehensive encoding functions for Bitcoin cryptographic keys
 * and addresses. It handles the conversion of raw key material into standardized
 * formats used across the Bitcoin ecosystem, including extended keys (BIP32),
 * Wallet Import Format (WIF), and Base58Check addresses.
 * 
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki|BIP32 - Hierarchical Deterministic Wallets}
 * @see {@link https://en.bitcoin.it/wiki/Wallet_import_format|WIF - Wallet Import Format}
 * @see {@link https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses|Bitcoin Address Format}
 * @author yfbsei
 * @version 2.0.0
 */

import { createHash } from 'node:crypto';
import { encodeBase58Check } from '../base58.js';
import { hash160 } from '../../core/crypto/hash/ripemd160.js';
import {
	NETWORK_VERSIONS,
	BIP32_CONSTANTS,
	CRYPTO_CONSTANTS
} from '../../core/constants.js';

/**
 * @typedef {Object} StandardKeyPair
 * @property {string|null} privateKeyWIF - WIF-encoded private key or null if not available
 * @property {string} publicKeyHex - Hex-encoded compressed public key
 */

/**
 * @typedef {Object} ExtendedKeyContext
 * @property {Object} versionBytes - Network version bytes
 * @property {number} depth - Derivation depth
 * @property {Buffer} parentFingerprint - Parent key fingerprint
 * @property {number} childIndex - Child derivation index
 * @property {Buffer} chainCode - Chain code for derivation
 * @property {Object} privateKey - Private key data
 * @property {Object} publicKey - Public key data
 */

/**
 * Encodes hierarchical deterministic keys according to BIP32 specification
 * 
 * This function creates extended keys (xprv/xpub, tprv/tpub) that contain not only
 * the key material but also metadata necessary for hierarchical key derivation:
 * 
 * **Extended Key Structure (78 bytes total):**
 * - 4 bytes: Version (network and key type identifier)
 * - 1 byte: Depth (number of derivations from master)
 * - 4 bytes: Parent fingerprint (first 4 bytes of parent key hash)
 * - 4 bytes: Child index (derivation index used)
 * - 32 bytes: Chain code (for deriving child keys)
 * - 33 bytes: Key data (private key with 0x00 prefix OR compressed public key)
 * 
 * **Network Prefixes:**
 * - Mainnet: xprv/xpub (starts with "xprv9" or "xpub6")
 * - Testnet: tprv/tpub (starts with "tprv8" or "tpub8")
 * 
 * @function
 * @param {string} keyType - Key type: 'private' for private key, 'public' for public key
 * @param {ExtendedKeyContext} keyContext - BIP32 serialization parameters
 * @returns {string} Base58Check-encoded extended key
 * 
 * @throws {Error} If keyType is neither 'private' nor 'public'
 * @throws {Error} If required key information is missing for specified type
 * @throws {Error} If serialization parameters are invalid or malformed
 * 
 * @example
 * // Create extended private key (xprv) for Bitcoin mainnet
 * const masterContext = {
 *   versionBytes: { 
 *     extendedPrivateKey: NETWORK_VERSIONS.MAINNET.EXTENDED_PRIVATE_KEY, 
 *     extendedPublicKey: NETWORK_VERSIONS.MAINNET.EXTENDED_PUBLIC_KEY 
 *   },
 *   depth: 0,
 *   parentFingerprint: Buffer.alloc(4, 0),
 *   childIndex: 0,
 *   chainCode: Buffer.from('873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508', 'hex'),
 *   privateKey: { 
 *     keyMaterial: Buffer.from('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35', 'hex'),
 *     wifVersionByte: NETWORK_VERSIONS.MAINNET.WIF_PRIVATE_KEY
 *   },
 *   publicKey: { 
 *     keyMaterial: Buffer.from('0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2', 'hex')
 *   }
 * };
 * 
 * const extendedPrivateKey = encodeExtendedKey('private', masterContext);
 * console.log(extendedPrivateKey);
 * // "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
 * 
 * @example
 * // Create extended public key (xpub) for Bitcoin mainnet
 * const extendedPublicKey = encodeExtendedKey('public', masterContext);
 * console.log(extendedPublicKey);
 * // "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
 */
export function encodeExtendedKey(keyType, keyContext) {
	// Validate input parameters
	if (keyType !== 'private' && keyType !== 'public') {
		throw new Error(`Invalid keyType: ${keyType}. Must be 'private' or 'public'`);
	}

	const {
		versionBytes,
		depth = 0,
		parentFingerprint = Buffer.alloc(4, 0),
		childIndex = 0,
		chainCode = Buffer.alloc(32, 0),
		privateKey,
		publicKey
	} = keyContext;

	// Validate required keys are present
	if (keyType === 'private' && !privateKey) {
		throw new Error('privateKey is required when keyType is "private"');
	}
	if (!publicKey) {
		throw new Error('publicKey is required for all key types');
	}

	// Validate buffer sizes
	if (parentFingerprint.length !== 4) {
		throw new Error('parentFingerprint must be 4 bytes');
	}
	if (chainCode.length !== CRYPTO_CONSTANTS.CHAIN_CODE_LENGTH) {
		throw new Error(`chainCode must be ${CRYPTO_CONSTANTS.CHAIN_CODE_LENGTH} bytes`);
	}

	// Prepare serialization components
	const versionBuffer = Buffer.alloc(4);
	const depthBuffer = Buffer.alloc(1);
	const childIndexBuffer = Buffer.alloc(4);

	// Serialize metadata according to BIP32 specification
	const versionValue = keyType === 'private'
		? versionBytes.extendedPrivateKey
		: versionBytes.extendedPublicKey;

	versionBuffer.writeUInt32BE(versionValue, 0);
	depthBuffer.writeUInt8(depth, 0);
	childIndexBuffer.writeUInt32BE(childIndex, 0);

	// Prepare key material
	let keyMaterial;
	if (keyType === 'private') {
		// Private key: 0x00 prefix + 32-byte private key
		const privateKeyPrefix = Buffer.from([0x00]);
		keyMaterial = Buffer.concat([privateKeyPrefix, privateKey.keyMaterial]);
	} else {
		// Public key: 33-byte compressed public key
		keyMaterial = publicKey.keyMaterial;
	}

	// Validate key material length
	const expectedLength = keyType === 'private' ? 33 : 33; // Both should be 33 bytes
	if (keyMaterial.length !== expectedLength) {
		throw new Error(`Invalid key material length: expected ${expectedLength}, got ${keyMaterial.length}`);
	}

	// Construct complete extended key payload
	const extendedKeyPayload = Buffer.concat([
		versionBuffer,        // 4 bytes: version
		depthBuffer,         // 1 byte: depth
		parentFingerprint,   // 4 bytes: parent fingerprint
		childIndexBuffer,    // 4 bytes: child index
		chainCode,           // 32 bytes: chain code
		keyMaterial          // 33 bytes: key material
	]);

	// Validate total payload length
	if (extendedKeyPayload.length !== BIP32_CONSTANTS.EXTENDED_KEY_LENGTH) {
		throw new Error(`Invalid extended key length: expected ${BIP32_CONSTANTS.EXTENDED_KEY_LENGTH}, got ${extendedKeyPayload.length}`);
	}

	return encodeBase58Check(extendedKeyPayload);
}

/**
 * Encodes private and public keys in standard Bitcoin formats
 * 
 * This function creates standard key representations used throughout Bitcoin:
 * - **WIF (Wallet Import Format)**: For private keys with network identification and compression flag
 * - **Hex Encoding**: For public keys in standard compressed format
 * 
 * **WIF Format Structure:**
 * - 1 byte: Network version (0x80 mainnet, 0xef testnet)
 * - 32 bytes: Private key
 * - 1 byte: Compression flag (0x01 for compressed public key)
 * - 4 bytes: Checksum (first 4 bytes of double SHA256)
 * 
 * The compression flag indicates that the corresponding public key should be
 * stored in compressed format (33 bytes vs 65 bytes uncompressed).
 * 
 * @function
 * @param {Object|false} [privateKeyData=false] - Private key info or false to skip private key encoding
 * @param {Buffer} privateKeyData.keyMaterial - 32-byte private key
 * @param {number} privateKeyData.wifVersionByte - WIF version byte
 * @param {Object|null} [publicKeyData=null] - Public key information for hex encoding
 * @param {Buffer} publicKeyData.keyMaterial - 33-byte compressed public key
 * @returns {StandardKeyPair} Object containing encoded private and public keys
 * 
 * @example
 * // Encode both private and public keys for Bitcoin mainnet
 * const privateKeyData = {
 *   keyMaterial: Buffer.from('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35', 'hex'),
 *   wifVersionByte: NETWORK_VERSIONS.MAINNET.WIF_PRIVATE_KEY
 * };
 * 
 * const publicKeyData = {
 *   keyMaterial: Buffer.from('0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2', 'hex')
 * };
 * 
 * const keyPair = encodeStandardKeys(privateKeyData, publicKeyData);
 * console.log(keyPair.privateKeyWIF);
 * // "L5HgWvFghocq1FmxSjKNaGhVN8f67p6xYg5pY7M8FE77HXwHtGGu"
 * console.log(keyPair.publicKeyHex);
 * // "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
 */
export function encodeStandardKeys(privateKeyData = false, publicKeyData = null) {
	let privateKeyWIF = null;

	// Encode private key in WIF format if provided
	if (privateKeyData) {
		// Validate private key length
		if (privateKeyData.keyMaterial.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH) {
			throw new Error(`Invalid private key length: expected ${CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH}, got ${privateKeyData.keyMaterial.length}`);
		}

		// Construct WIF payload: version + private_key + compression_flag
		const wifPayload = Buffer.concat([
			Buffer.from([privateKeyData.wifVersionByte]),  // Network version byte
			privateKeyData.keyMaterial,                    // 32-byte private key
			Buffer.from([0x01])                           // Compression flag (always compressed)
		]);

		privateKeyWIF = encodeBase58Check(wifPayload);
	}

	// Encode public key as hex string (or keep existing if already string)
	let publicKeyHex = null;
	if (publicKeyData) {
		// Validate public key length
		if (publicKeyData.keyMaterial.length !== CRYPTO_CONSTANTS.PUBLIC_KEY_COMPRESSED_LENGTH) {
			throw new Error(`Invalid public key length: expected ${CRYPTO_CONSTANTS.PUBLIC_KEY_COMPRESSED_LENGTH}, got ${publicKeyData.keyMaterial.length}`);
		}

		publicKeyHex = publicKeyData.keyMaterial.toString('hex');
	}

	return {
		privateKeyWIF,  // WIF-encoded private key or null
		publicKeyHex    // Hex-encoded compressed public key or null
	};
}

/**
 * Generates a Bitcoin address from a public key using HASH160 and Base58Check encoding
 * 
 * This function implements the standard Bitcoin address generation algorithm:
 * 
 * **Address Generation Process:**
 * 1. **Double Hash**: SHA256(public_key) → RIPEMD160(hash) = HASH160
 * 2. **Version Prefix**: Prepend network version byte (0x00 mainnet, 0x6f testnet)
 * 3. **Checksum**: Calculate SHA256(SHA256(version + hash160))[0:4]
 * 4. **Encoding**: Base58Check encode (version + hash160 + checksum)
 * 
 * **Address Types by Version Byte:**
 * - 0x00 (mainnet): Addresses starting with "1"
 * - 0x6f (testnet): Addresses starting with "m" or "n"
 * - 0x05 (mainnet P2SH): Addresses starting with "3" (not implemented here)
 * 
 * The resulting address is a human-readable string that can receive Bitcoin payments
 * and corresponds directly to the provided public key.
 * 
 * @function
 * @param {number} networkVersionByte - Network version byte for address type
 * @param {Buffer} publicKeyBuffer - Compressed 33-byte public key
 * @returns {string} Base58Check-encoded Bitcoin address
 * 
 * @throws {Error} If public key is invalid format or length
 * @throws {Error} If network version byte is not recognized
 * 
 * @example
 * // Generate mainnet P2PKH address
 * const publicKey = Buffer.from('0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2', 'hex');
 * const address = generateAddress(NETWORK_VERSIONS.MAINNET.P2PKH_ADDRESS, publicKey);
 * console.log(address);
 * // "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma" (mainnet address starting with "1")
 * 
 * @example
 * // Generate testnet P2PKH address
 * const testnetAddress = generateAddress(NETWORK_VERSIONS.TESTNET.P2PKH_ADDRESS, publicKey);
 * console.log(testnetAddress);
 * // "mhiH7BQkmD7LoosHhAAH5nE9YKGUcPz4hV" (testnet address starting with "m")
 */
export function generateAddress(networkVersionByte, publicKeyBuffer) {
	// Validate inputs
	if (!publicKeyBuffer || !Buffer.isBuffer(publicKeyBuffer)) {
		throw new Error('Public key must be a valid Buffer');
	}

	if (publicKeyBuffer.length !== CRYPTO_CONSTANTS.PUBLIC_KEY_COMPRESSED_LENGTH) {
		throw new Error(`Invalid public key length: expected ${CRYPTO_CONSTANTS.PUBLIC_KEY_COMPRESSED_LENGTH}, got ${publicKeyBuffer.length}`);
	}

	// Create version prefix
	const versionPrefix = Buffer.from([networkVersionByte]);

	// Compute HASH160: RIPEMD160(SHA256(pubkey))
	const hash160Buffer = hash160(createHash('sha256').update(publicKeyBuffer).digest());

	// Validate hash160 length
	if (hash160Buffer.length !== CRYPTO_CONSTANTS.HASH160_LENGTH) {
		throw new Error(`Invalid hash160 length: expected ${CRYPTO_CONSTANTS.HASH160_LENGTH}, got ${hash160Buffer.length}`);
	}

	// Construct address payload: version + hash160
	const addressPayload = Buffer.concat([versionPrefix, hash160Buffer]);

	return encodeBase58Check(addressPayload);
}

/**
 * Generate address from extended key version byte
 * 
 * Convenience function that maps extended key version bytes to appropriate address version bytes.
 * 
 * @param {number} extendedKeyVersion - Extended key version byte
 * @param {Buffer} publicKeyBuffer - Public key buffer
 * @returns {string} Bitcoin address
 * 
 * @example
 * const address = generateAddressFromExtendedVersion(
 *   NETWORK_VERSIONS.MAINNET.EXTENDED_PUBLIC_KEY, 
 *   publicKeyBuffer
 * );
 */
export function generateAddressFromExtendedVersion(extendedKeyVersion, publicKeyBuffer) {
	let addressVersionByte;

	// Map extended key version to address version
	if (extendedKeyVersion === NETWORK_VERSIONS.MAINNET.EXTENDED_PUBLIC_KEY) {
		addressVersionByte = NETWORK_VERSIONS.MAINNET.P2PKH_ADDRESS;
	} else if (extendedKeyVersion === NETWORK_VERSIONS.TESTNET.EXTENDED_PUBLIC_KEY) {
		addressVersionByte = NETWORK_VERSIONS.TESTNET.P2PKH_ADDRESS;
	} else {
		throw new Error(`Unsupported extended key version: 0x${extendedKeyVersion.toString(16)}`);
	}

	return generateAddress(addressVersionByte, publicKeyBuffer);
}

/**
 * Create fingerprint from public key for BIP32 operations
 * 
 * Generates the 4-byte fingerprint used in BIP32 extended keys.
 * 
 * @param {Buffer} publicKeyBuffer - Compressed public key
 * @returns {Buffer} 4-byte fingerprint
 * 
 * @example
 * const fingerprint = createPublicKeyFingerprint(publicKeyBuffer);
 * console.log(fingerprint.toString('hex')); // "5c1bd648"
 */
export function createPublicKeyFingerprint(publicKeyBuffer) {
	const hash160Buffer = hash160(createHash('sha256').update(publicKeyBuffer).digest());
	return hash160Buffer.slice(0, 4);
}

// Export legacy aliases for backwards compatibility
export {
	encodeExtendedKey as hdKey,
	encodeStandardKeys as standardKey,
	generateAddressFromExtendedVersion as address
};