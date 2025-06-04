/**
 * @fileoverview Main wallet classes for J-Bitcoin library providing custodial and non-custodial wallet functionality
 * @author yfbsei
 * @version 1.0.0
 */

import fromSeed from './BIP32/fromSeed.js';
import derive from './BIP32/derive.js';
import bip39 from './BIP39/bip39.js';
import ecdsa from './ECDSA/ecdsa.js';

import { standardKey, address } from './utilities/encodeKeys.js';
import ThresholdSignature from './Threshold-signature/threshold_signature.js';
import BN from 'bn.js';
import { secp256k1 } from '@noble/curves/secp256k1';

/**
 * @typedef {Object} HDKeys
 * @property {string} HDpri - Hierarchical deterministic private key (xprv format)
 * @property {string} HDpub - Hierarchical deterministic public key (xpub format)
 */

/**
 * @typedef {Object} KeyPair
 * @property {string} pri - WIF-encoded private key
 * @property {string} pub - Hex-encoded public key
 */

/**
 * @typedef {Object} ChildKeyInfo
 * @property {number} depth - Derivation depth in the HD tree
 * @property {number} childIndex - Index of this child key
 * @property {HDKeys} hdKey - HD key pair for this child
 * @property {KeyPair} keypair - Standard key pair for this child
 * @property {string} address - Bitcoin address for this child key
 */

/**
 * @typedef {Object} SignatureResult
 * @property {Uint8Array} 0 - The signature bytes
 * @property {number} 1 - Recovery ID for public key recovery
 */

/**
 * Custodial wallet implementation supporting hierarchical deterministic key derivation
 * and standard ECDSA signatures. Suitable for single-party control scenarios.
 * 
 * @class Custodial_Wallet
 * @example
 * // Generate a new wallet
 * const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
 * 
 * // Import from existing mnemonic
 * const wallet = Custodial_Wallet.fromMnemonic('main', mnemonic, 'password');
 * 
 * // Derive child keys
 * wallet.derive("m/0'/1", 'pri');
 * 
 * // Sign a message
 * const [signature, recovery] = wallet.sign("Hello World");
 */
class Custodial_Wallet {
	/**
	 * Private field storing the serialization format for key derivation
	 * @private
	 * @type {Object}
	 */
	#serialization_format;

	/**
	 * Creates a new Custodial_Wallet instance
	 * 
	 * @param {string} net - Network type ('main' for mainnet, 'test' for testnet)
	 * @param {Object} master_keys - Master key information
	 * @param {HDKeys} master_keys.hdKey - Hierarchical deterministic keys
	 * @param {KeyPair} master_keys.keypair - Standard key pair
	 * @param {string} master_keys.address - Bitcoin address
	 * @param {Object} serialization_format - Internal serialization format for key derivation
	 */
	constructor(net, master_keys, serialization_format) {
		/**
		 * Network type ('main' or 'test')
		 * @type {string}
		 * @readonly
		 */
		this.net = net;

		/**
		 * Hierarchical deterministic key pair
		 * @type {HDKeys}
		 * @readonly
		 */
		this.hdKey = master_keys.hdKey;

		/**
		 * Standard key pair (WIF private key and hex public key)
		 * @type {KeyPair}
		 * @readonly
		 */
		this.keypair = master_keys.keypair;

		/**
		 * Bitcoin address for this wallet
		 * @type {string}
		 * @readonly
		 */
		this.address = master_keys.address;

		/**
		 * Set of derived child keys
		 * @type {Set<ChildKeyInfo>}
		 */
		this.child_keys = new Set();

		this.#serialization_format = serialization_format;
	}

	/**
	 * Generates a new random wallet with mnemonic phrase
	 * 
	 * @static
	 * @param {string} [net='main'] - Network type ('main' or 'test')
	 * @param {string} [passphrase=''] - Optional passphrase for additional security
	 * @returns {Array} Array containing mnemonic phrase and wallet instance
	 * @returns {string} returns.0 - Generated mnemonic phrase
	 * @returns {Custodial_Wallet} returns.1 - New wallet instance
	 * @example
	 * const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main', 'my-passphrase');
	 * console.log(mnemonic); // "abandon abandon abandon ..."
	 */
	static fromRandom(net = 'main', passphrase = '') {
		const { mnemonic, seed } = bip39.random(passphrase);
		return [mnemonic, this.fromSeed(net, seed)];
	}

	/**
	 * Creates a wallet from an existing mnemonic phrase
	 * 
	 * @static
	 * @param {string} [net='main'] - Network type ('main' or 'test')
	 * @param {string} [mnemonic=''] - 12-word mnemonic phrase
	 * @param {string} [passphrase=''] - Optional passphrase used during generation
	 * @returns {Custodial_Wallet} New wallet instance
	 * @throws {Error} If mnemonic has invalid checksum
	 * @example
	 * const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	 * const wallet = Custodial_Wallet.fromMnemonic('main', mnemonic);
	 */
	static fromMnemonic(net = 'main', mnemonic = '', passphrase = '') {
		const seed = bip39.mnemonic2seed(mnemonic, passphrase);
		return this.fromSeed(net, seed);
	}

	/**
	 * Creates a wallet from a hex-encoded seed
	 * 
	 * @static
	 * @param {string} [net='main'] - Network type ('main' or 'test')
	 * @param {string} [seed="000102030405060708090a0b0c0d0e0f"] - Hex-encoded seed
	 * @returns {Custodial_Wallet} New wallet instance
	 * @example
	 * const seed = "000102030405060708090a0b0c0d0e0f";
	 * const wallet = Custodial_Wallet.fromSeed('main', seed);
	 */
	static fromSeed(net = 'main', seed = "000102030405060708090a0b0c0d0e0f") {
		const [hdKey, serialization_format] = fromSeed(seed, net);
		return new this(
			net,
			{
				hdKey,
				keypair: standardKey(serialization_format.privKey, serialization_format.pubKey),
				address: address(serialization_format.versionByte.pubKey, serialization_format.pubKey.key)
			},
			serialization_format
		);
	}

	/**
	 * Derives a child key from the current wallet using BIP32 derivation path
	 * 
	 * @param {string} [path="m/0'"] - BIP32 derivation path (e.g., "m/0'/1/2")
	 * @param {string} [keyType='pri'] - Key type to derive ('pri' for private, 'pub' for public)
	 * @returns {Custodial_Wallet} Returns this wallet instance for method chaining
	 * @throws {Error} If trying to derive hardened path from public key
	 * @example
	 * // Derive hardened child key
	 * wallet.derive("m/0'", 'pri');
	 * 
	 * // Derive non-hardened child (can be done with public key)
	 * wallet.derive("m/0/1", 'pub');
	 * 
	 * // Method chaining
	 * wallet.derive("m/0'").derive("m/1'");
	 */
	derive(path = "m/0'", keyType = 'pri') {
		const key = this.hdKey[keyType === 'pri' ? 'HDpri' : 'HDpub'];
		const [hdKey, serialization_format] = derive(path, key, this.#serialization_format);

		this.child_keys.add({
			depth: serialization_format.depth,
			childIndex: serialization_format.childIndex,
			hdKey,
			keypair: standardKey(keyType !== 'pub' ? serialization_format.privKey : false, serialization_format.pubKey),
			address: address(serialization_format.versionByte.pubKey, serialization_format.pubKey.key)
		});

		return this;
	}

	/**
	 * Signs a message using ECDSA with the wallet's private key
	 * 
	 * @param {string} [message=''] - Message to sign
	 * @returns {SignatureResult} Tuple of [signature bytes, recovery ID]
	 * @example
	 * const [signature, recoveryId] = wallet.sign("Hello Bitcoin!");
	 * 
	 * // Verify the signature
	 * const isValid = wallet.verify(signature, "Hello Bitcoin!");
	 */
	sign(message = '') {
		return ecdsa.sign(this.keypair.pri, message);
	}

	/**
	 * Verifies an ECDSA signature against a message using the wallet's public key
	 * 
	 * @param {Uint8Array|Buffer} sig - Signature to verify
	 * @param {string} msg - Original message that was signed
	 * @returns {boolean} True if signature is valid, false otherwise
	 * @example
	 * const [signature, _] = wallet.sign("Hello Bitcoin!");
	 * const isValid = wallet.verify(signature, "Hello Bitcoin!"); // true
	 */
	verify(sig, msg) {
		return ecdsa.verify(sig, msg, this.#serialization_format.pubKey.key);
	}
}

/**
 * @typedef {Object} ThresholdSignature
 * @property {Object} sig - Signature object with r and s values
 * @property {string} serialized_sig - Base64 encoded compact signature
 * @property {Buffer} msgHash - SHA256 hash of the signed message
 * @property {number} recovery_id - Recovery ID for public key recovery
 */

/**
 * Non-custodial wallet implementation using Threshold Signature Scheme (TSS)
 * for distributed key management. Enables multi-party control without a trusted party.
 * 
 * @class Non_Custodial_Wallet
 * @extends ThresholdSignature
 * @example
 * // Create a 2-of-3 threshold wallet
 * const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
 * 
 * // Get shares for distribution to participants
 * const shares = wallet._shares;
 * 
 * // Reconstruct wallet from shares
 * const reconstructed = Non_Custodial_Wallet.fromShares("main", shares, 2);
 * 
 * // Sign with threshold signature
 * const signature = wallet.sign("Hello Threshold!");
 */
class Non_Custodial_Wallet extends ThresholdSignature {

	/**
	 * Creates a new Non_Custodial_Wallet instance
	 * 
	 * @param {string} net - Network type ('main' for mainnet, 'test' for testnet)
	 * @param {number} group_size - Total number of participants in the threshold scheme
	 * @param {number} threshold - Minimum number of participants required to sign
	 */
	constructor(net, group_size, threshold) {
		super(group_size, threshold);

		/**
		 * Network type ('main' or 'test')
		 * @type {string}
		 * @readonly
		 */
		this.net = net;

		[this.publicKey, this.address] = this.#wallet();
	}

	/**
	 * Generates a new random threshold wallet
	 * 
	 * @static
	 * @param {string} [net="main"] - Network type ('main' or 'test')
	 * @param {number} [group_size=3] - Total number of participants
	 * @param {number} [threshold=2] - Minimum participants required for signing
	 * @returns {Non_Custodial_Wallet} New threshold wallet instance
	 * @throws {Error} If threshold is greater than group_size or less than 2
	 * @example
	 * // Create a 3-of-5 wallet
	 * const wallet = Non_Custodial_Wallet.fromRandom("main", 5, 3);
	 */
	static fromRandom(net = "main", group_size = 3, threshold = 2) {
		return new this(
			net,
			group_size,
			threshold
		)
	}

	/**
	 * Reconstructs a threshold wallet from existing shares
	 * 
	 * @static
	 * @param {string} [net="main"] - Network type ('main' or 'test')
	 * @param {string[]} shares - Array of hex-encoded secret shares
	 * @param {number} [threshold=2] - Minimum participants required for signing
	 * @returns {Non_Custodial_Wallet} Reconstructed wallet instance
	 * @example
	 * const shares = [
	 *   '79479395a59a8e9d930f2b10ccd5ac3671b0ff0bf8a66aaa1d74978c5353694b',
	 *   '98510126c920e18b148130ac1145686cb299d21f0e010b98ede44169a7bb1c13'
	 * ];
	 * const wallet = Non_Custodial_Wallet.fromShares("main", shares, 2);
	 */
	static fromShares(net = "main", shares, threshold = 2) {
		const wallet = new this(
			net,
			shares.length,
			threshold
		)

		// Convert shares into Big number and reconstruct keys
		wallet.shares = shares.map(x => new BN(x, 'hex'));
		wallet.public_key = secp256k1.ProjectivePoint.fromPrivateKey(wallet.privite_key().toBuffer());
		[wallet.publicKey, wallet.address] = wallet.#wallet();

		return wallet;
	}

	/**
	 * Gets the secret shares as hex strings for distribution to participants
	 * 
	 * @returns {string[]} Array of hex-encoded secret shares
	 * @example
	 * const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
	 * const shares = wallet._shares;
	 * // Distribute shares[0] to participant 1, shares[1] to participant 2, etc.
	 */
	get _shares() {
		return this.shares.map(x => x.toString('hex'));
	}

	/**
	 * Private method to generate wallet address from public key
	 * 
	 * @private
	 * @returns {Array} Array containing hex public key and bitcoin address
	 * @returns {string} returns.0 - Hex-encoded public key
	 * @returns {string} returns.1 - Bitcoin address
	 */
	#wallet() {
		const
			versionByte = this.net === "main" ? 0x0488b21e : 0x043587cf,
			pubKeyToBuff = Buffer.from(this.public_key.toHex(true), 'hex');

		return [
			this.public_key.toHex(true),
			address(versionByte, pubKeyToBuff)
		];
	}

	/**
	 * Gets the reconstructed private key in WIF format
	 * 
	 * @returns {string} WIF-encoded private key
	 * @example
	 * const wallet = Non_Custodial_Wallet.fromShares("main", shares, 2);
	 * const privateKey = wallet._privateKey;
	 * // This should only be used when full control is needed
	 */
	get _privateKey() {
		const privKey = {
			key: this.privite_key().toBuffer(),
			versionByteNum: this.net === 'main' ? 0x80 : 0xef
		}
		return standardKey(privKey, undefined).pri;
	}

	/**
	 * Verifies a threshold signature against the original message hash
	 * 
	 * @param {Object} sig - Signature object with r and s properties
	 * @param {Buffer} msgHash - SHA256 hash of the original message
	 * @returns {boolean} True if signature is valid, false otherwise
	 * @example
	 * const signature = wallet.sign("Hello World!");
	 * const isValid = wallet.verify(signature.sig, signature.msgHash); // true
	 */
	verify(sig, msgHash) {
		return ThresholdSignature.verify_threshold_signature(this.public_key, msgHash, sig);
	}
}

export {
	Custodial_Wallet,
	Non_Custodial_Wallet
}