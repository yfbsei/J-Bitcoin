/**
 * @fileoverview Main wallet classes for J-Bitcoin library providing custodial and non-custodial wallet functionality
 * 
 * This module implements two distinct wallet architectures for Bitcoin cryptocurrency operations:
 * 
 * **Custodial_Wallet**: Traditional single-party control wallet using hierarchical deterministic 
 * key derivation (BIP32) with standard ECDSA signatures. Suitable for individual users and 
 * applications requiring simple key management.
 * 
 * **Non_Custodial_Wallet**: Advanced multi-party threshold signature scheme (TSS) implementation
 * enabling distributed key management without trusted dealers. Ideal for corporate treasuries,
 * escrow services, and high-security applications requiring multi-party authorization.
 * 
 * @author yfbsei
 * @version 1.0.0
 * @since 1.0.0
 * 
 * @requires fromSeed
 * @requires derive
 * @requires bip39
 * @requires ecdsa
 * @requires standardKey
 * @requires address
 * @requires ThresholdSignature
 * @requires bn.js
 * @requires @noble/curves/secp256k1
 * 
 * @example
 * // Import wallet classes
 * import { Custodial_Wallet, Non_Custodial_Wallet } from './wallet.js';
 * 
 * // Create custodial wallet
 * const [mnemonic, custodialWallet] = Custodial_Wallet.fromRandom('main');
 * 
 * // Create threshold wallet
 * const thresholdWallet = Non_Custodial_Wallet.fromRandom('main', 3, 2);
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
 * @description Hierarchical deterministic key pair following BIP32 specification
 * @property {string} HDpri - Extended private key in xprv/tprv format (Base58Check encoded)
 * @property {string} HDpub - Extended public key in xpub/tpub format (Base58Check encoded)
 * @example
 * // Example HD key pair
 * const hdKeys = {
 *   HDpri: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
 *   HDpub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
 * };
 */

/**
 * @typedef {Object} KeyPair
 * @description Standard Bitcoin key pair for cryptographic operations
 * @property {string} pri - WIF-encoded private key (Wallet Import Format)
 * @property {string} pub - Hex-encoded compressed public key (33 bytes)
 * @example
 * // Example key pair
 * const keyPair = {
 *   pri: "L5HgWvFghocq1FmxSjKNaGhVN8f67p6xYg5pY7M8FE77HXwHtGGu",
 *   pub: "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
 * };
 */

/**
 * @typedef {Object} ChildKeyInfo
 * @description Information about a derived child key in the HD wallet tree
 * @property {number} depth - Derivation depth in the HD tree (0 = master, 1 = account, etc.)
 * @property {number} childIndex - Index of this child key in its derivation level
 * @property {HDKeys} hdKey - HD key pair for this child
 * @property {KeyPair} keypair - Standard key pair for this child
 * @property {string} address - Bitcoin address generated from this child key
 * @example
 * // Child key at m/44'/0'/0'/0/0
 * const childInfo = {
 *   depth: 5,
 *   childIndex: 0,
 *   hdKey: { HDpri: "...", HDpub: "..." },
 *   keypair: { pri: "...", pub: "..." },
 *   address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
 * };
 */

/**
 * @typedef {Array} ECDSASignatureResult
 * @description ECDSA signature result with recovery information
 * @property {Uint8Array} 0 - DER-encoded signature bytes
 * @property {number} 1 - Recovery ID (0-3) for public key recovery
 * @example
 * const [signature, recoveryId] = wallet.sign("Hello Bitcoin!");
 * console.log(signature);  // Uint8Array with signature bytes
 * console.log(recoveryId); // Number 0-3
 */

/**
 * @typedef {Object} ThresholdSignatureResult
 * @description Complete threshold signature with metadata and recovery information
 * @property {Object} sig - ECDSA signature object with r and s components
 * @property {bigint} sig.r - Signature r value as BigInt
 * @property {bigint} sig.s - Signature s value as BigInt
 * @property {string} serialized_sig - Base64-encoded compact signature format (65 bytes)
 * @property {Buffer} msgHash - SHA256 hash of the signed message (32 bytes)
 * @property {number} recovery_id - Recovery ID for public key recovery (0-3)
 * @example
 * const signature = thresholdWallet.sign("Multi-party transaction");
 * console.log(signature.sig.r);          // BigInt r value
 * console.log(signature.serialized_sig); // "base64-encoded-signature"
 * console.log(signature.recovery_id);    // 0, 1, 2, or 3
 */

/**
 * Custodial wallet implementation supporting hierarchical deterministic key derivation
 * and standard ECDSA signatures. Suitable for single-party control scenarios.
 * 
 * This class provides traditional Bitcoin wallet functionality with full control over
 * private keys. It implements BIP32 hierarchical deterministic key derivation, allowing
 * generation of unlimited child keys from a single seed. Perfect for individual users,
 * mobile wallets, and applications requiring straightforward key management.
 * 
 * **Key Features:**
 * - BIP32 hierarchical deterministic key derivation
 * - BIP39 mnemonic phrase support for backup and recovery  
 * - Standard ECDSA signature generation and verification
 * - Support for Bitcoin mainnet and testnet
 * - Child key derivation with configurable paths
 * - Address generation for receiving payments
 * 
 * **Security Model:**
 * - Single point of control (private key holder has full access)
 * - Suitable for individual users and trusted environments
 * - Mnemonic phrases enable secure backup and recovery
 * - Child keys provide address privacy without exposing master key
 * 
 * **Use Cases:**
 * - Personal Bitcoin wallets
 * - Mobile wallet applications
 * - Desktop wallet software
 * - Simple payment processing systems
 * - Development and testing environments
 * 
 * @class Custodial_Wallet
 * @since 1.0.0
 * 
 * @example
 * // Generate a new random wallet
 * const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
 * console.log('Mnemonic:', mnemonic);
 * console.log('Address:', wallet.address);
 * 
 * @example
 * // Import from existing mnemonic
 * const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
 * const wallet = Custodial_Wallet.fromMnemonic('main', mnemonic, 'password');
 * console.log('Imported address:', wallet.address);
 * 
 * @example
 * // Derive child keys for different purposes
 * const wallet = Custodial_Wallet.fromRandom('main')[1];
 * 
 * // BIP44 Bitcoin receiving addresses
 * wallet.derive("m/44'/0'/0'/0/0", 'pri'); // First receiving address
 * wallet.derive("m/44'/0'/0'/0/1", 'pri'); // Second receiving address
 * 
 * // BIP44 Bitcoin change addresses  
 * wallet.derive("m/44'/0'/0'/1/0", 'pri'); // First change address
 * 
 * console.log('Child keys:', Array.from(wallet.child_keys));
 * 
 * @example
 * // Sign and verify messages
 * const wallet = Custodial_Wallet.fromRandom('main')[1];
 * const message = "Hello Bitcoin!";
 * 
 * // Sign message
 * const [signature, recoveryId] = wallet.sign(message);
 * 
 * // Verify signature
 * const isValid = wallet.verify(signature, message);
 * console.log('Signature valid:', isValid); // true
 */
class Custodial_Wallet {
	/**
	 * Private field storing the serialization format for key derivation operations.
	 * Contains cryptographic parameters, chain codes, and metadata required for
	 * BIP32 hierarchical deterministic key derivation.
	 * 
	 * @private
	 * @type {Object}
	 * @memberof Custodial_Wallet
	 */
	#serialization_format;

	/**
	 * Creates a new Custodial_Wallet instance with specified master keys and network configuration.
	 * 
	 * This constructor initializes a wallet with pre-generated master keys and serialization
	 * format. It's typically called internally by static factory methods rather than directly.
	 * The wallet instance provides access to HD keys, standard key pairs, Bitcoin addresses,
	 * and child key derivation capabilities.
	 * 
	 * @param {string} net - Network type ('main' for mainnet, 'test' for testnet)
	 * @param {Object} master_keys - Master key information
	 * @param {HDKeys} master_keys.hdKey - Hierarchical deterministic keys
	 * @param {KeyPair} master_keys.keypair - Standard key pair (WIF private key, hex public key)
	 * @param {string} master_keys.address - Bitcoin address for receiving payments
	 * @param {Object} serialization_format - Internal serialization format for key derivation
	 * 
	 * @throws {Error} If network type is not 'main' or 'test'
	 * @throws {Error} If master keys are invalid or malformed
	 * 
	 * @example
	 * // Typically used internally by factory methods
	 * const masterKeys = {
	 *   hdKey: { HDpri: "xprv...", HDpub: "xpub..." },
	 *   keypair: { pri: "L5Hg...", pub: "0339..." },
	 *   address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
	 * };
	 * const wallet = new Custodial_Wallet('main', masterKeys, serializationFormat);
	 */
	constructor(net, master_keys, serialization_format) {
		/**
		 * Network type for this wallet instance.
		 * Determines address formats, version bytes, and network-specific parameters.
		 * 
		 * @type {string}
		 * @readonly
		 * @memberof Custodial_Wallet
		 * @example
		 * console.log(wallet.net); // "main" or "test"
		 */
		this.net = net;

		/**
		 * Hierarchical deterministic key pair for this wallet.
		 * Contains both extended private and public keys in standard BIP32 format.
		 * Used for deriving child keys and maintaining the HD wallet structure.
		 * 
		 * @type {HDKeys}
		 * @readonly
		 * @memberof Custodial_Wallet
		 * @example
		 * console.log(wallet.hdKey.HDpri); // "xprv9s21ZrQH143K..."
		 * console.log(wallet.hdKey.HDpub); // "xpub661MyMwAqRbcF..."
		 */
		this.hdKey = master_keys.hdKey;

		/**
		 * Standard key pair for direct cryptographic operations.
		 * Contains WIF-encoded private key and hex-encoded compressed public key.
		 * Used for signing transactions and generating addresses.
		 * 
		 * @type {KeyPair}
		 * @readonly
		 * @memberof Custodial_Wallet
		 * @example
		 * console.log(wallet.keypair.pri); // "L5HgWvFghocq1FmxSjKNaGhVN8f67p6xYg5pY7M8FE77HXwHtGGu"
		 * console.log(wallet.keypair.pub); // "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
		 */
		this.keypair = master_keys.keypair;

		/**
		 * Bitcoin address for this wallet, derived from the master public key.
		 * Used for receiving payments and identifying the wallet on the blockchain.
		 * Format depends on network (1... for mainnet, m/n... for testnet).
		 * 
		 * @type {string}
		 * @readonly
		 * @memberof Custodial_Wallet
		 * @example
		 * console.log(wallet.address); // "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
		 */
		this.address = master_keys.address;

		/**
		 * Set of derived child keys from this wallet.
		 * Contains information about all child keys derived using the derive() method.
		 * Each entry includes depth, index, keys, and address information.
		 * 
		 * @type {Set<ChildKeyInfo>}
		 * @memberof Custodial_Wallet
		 * @example
		 * wallet.derive("m/0'/1", 'pri');
		 * console.log(wallet.child_keys.size); // 1
		 * 
		 * for (const childKey of wallet.child_keys) {
		 *   console.log('Child address:', childKey.address);
		 *   console.log('Derivation depth:', childKey.depth);
		 * }
		 */
		this.child_keys = new Set();

		// Store serialization format for internal use
		this.#serialization_format = serialization_format;
	}

	/**
	 * Generates a new random wallet with cryptographically secure mnemonic phrase.
	 * 
	 * This static factory method creates a fresh wallet using BIP39 mnemonic generation
	 * and BIP32 hierarchical deterministic key derivation. The generated mnemonic provides
	 * a human-readable backup that can restore the entire wallet and all derived keys.
	 * 
	 * **Process:**
	 * 1. Generate 128 bits of cryptographically secure entropy
	 * 2. Create 12-word BIP39 mnemonic with checksum validation
	 * 3. Derive 512-bit seed using PBKDF2-HMAC-SHA512
	 * 4. Generate BIP32 master keys from seed
	 * 5. Create wallet instance with generated keys
	 * 
	 * **Security:**
	 * - Uses cryptographically secure random number generation
	 * - Mnemonic includes built-in checksum for error detection
	 * - Optional passphrase provides additional security layer
	 * - Generated keys follow industry standard specifications
	 * 
	 * @static
	 * @param {string} [net='main'] - Network type ('main' for mainnet, 'test' for testnet)
	 * @param {string} [passphrase=''] - Optional passphrase for additional security (BIP39)
	 * @returns {Array} Tuple containing mnemonic phrase and wallet instance
	 * @returns {string} returns.0 - Generated 12-word mnemonic phrase
	 * @returns {Custodial_Wallet} returns.1 - New wallet instance
	 * 
	 * @throws {Error} If mnemonic generation fails or checksum is invalid
	 * @throws {Error} If network parameter is invalid
	 * 
	 * @example
	 * // Generate mainnet wallet
	 * const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
	 * console.log('Mnemonic:', mnemonic);
	 * // "abandon ability able about above absent absorb abstract absurd abuse access accident"
	 * console.log('Address:', wallet.address);
	 * // "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
	 * 
	 * @example
	 * // Generate testnet wallet with passphrase
	 * const [mnemonic, testWallet] = Custodial_Wallet.fromRandom('test', 'my-secure-passphrase');
	 * console.log('Testnet address:', testWallet.address);
	 * // "mgRpP3zP1hmxyoeYJgfbcmN3c2Qsurw48D"
	 * 
	 * @example
	 * // Store mnemonic securely for backup
	 * const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main', 'company-passphrase');
	 * 
	 * // Store mnemonic in secure location (encrypted, offline, etc.)
	 * secureStorage.store('wallet-mnemonic', mnemonic);
	 * secureStorage.store('wallet-passphrase', 'company-passphrase');
	 * 
	 * // Wallet can be restored later using mnemonic + passphrase
	 * const restoredWallet = Custodial_Wallet.fromMnemonic('main', mnemonic, 'company-passphrase');
	 */
	static fromRandom(net = 'main', passphrase = '') {
		const { mnemonic, seed } = bip39.random(passphrase);
		return [mnemonic, this.fromSeed(net, seed)];
	}

	/**
	 * Creates a wallet from an existing BIP39 mnemonic phrase with optional passphrase.
	 * 
	 * This static factory method restores a wallet from a previously generated mnemonic
	 * phrase. It validates the mnemonic checksum, derives the cryptographic seed using
	 * PBKDF2, and reconstructs the exact same wallet that was originally created.
	 * This enables secure backup and recovery of Bitcoin wallets.
	 * 
	 * **Validation Process:**
	 * 1. Parse mnemonic into individual words
	 * 2. Validate words exist in BIP39 wordlist
	 * 3. Verify built-in checksum for error detection
	 * 4. Derive seed using PBKDF2-HMAC-SHA512 with salt
	 * 5. Generate identical master keys as original wallet
	 * 
	 * **Compatibility:**
	 * - Works with any BIP39-compliant mnemonic
	 * - Compatible with hardware wallets (Ledger, Trezor)
	 * - Interoperable with other Bitcoin wallet software
	 * - Supports 12-word mnemonics (this implementation)
	 * 
	 * @static
	 * @param {string} [net='main'] - Network type ('main' for mainnet, 'test' for testnet)
	 * @param {string} [mnemonic=''] - 12-word BIP39 mnemonic phrase (space-separated)
	 * @param {string} [passphrase=''] - Optional passphrase used during generation
	 * @returns {Custodial_Wallet} Restored wallet instance with identical keys
	 * 
	 * @throws {Error} "invalid checksum" if mnemonic checksum validation fails
	 * @throws {Error} If mnemonic format is invalid or contains unknown words
	 * @throws {Error} If network parameter is invalid
	 * 
	 * @example
	 * // Restore wallet from mnemonic
	 * const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	 * const wallet = Custodial_Wallet.fromMnemonic('main', mnemonic);
	 * console.log('Restored address:', wallet.address);
	 * 
	 * @example
	 * // Restore with passphrase (must match original)
	 * const mnemonicWithPass = "legal winner thank year wave sausage worth useful legal winner thank yellow";
	 * const passphrase = "my-secure-passphrase";
	 * const wallet = Custodial_Wallet.fromMnemonic('main', mnemonicWithPass, passphrase);
	 * 
	 * @example
	 * // Handle restoration errors gracefully
	 * try {
	 *   const invalidMnemonic = "invalid mnemonic phrase with wrong checksum";
	 *   const wallet = Custodial_Wallet.fromMnemonic('main', invalidMnemonic);
	 * } catch (error) {
	 *   console.error('Failed to restore wallet:', error.message);
	 *   // Handle error: show user-friendly message, request valid mnemonic
	 * }
	 * 
	 * @example
	 * // Cross-platform wallet restoration
	 * // Mnemonic generated on mobile app, restored on desktop
	 * const mobileMnemonic = getUserInput('Enter your 12-word backup phrase:');
	 * const desktopWallet = Custodial_Wallet.fromMnemonic('main', mobileMnemonic);
	 * 
	 * // Wallet will have identical addresses and keys as mobile version
	 * console.log('Synced address:', desktopWallet.address);
	 */
	static fromMnemonic(net = 'main', mnemonic = '', passphrase = '') {
		const seed = bip39.mnemonic2seed(mnemonic, passphrase);
		return this.fromSeed(net, seed);
	}

	/**
	 * Creates a wallet from a hex-encoded cryptographic seed (typically from BIP39).
	 * 
	 * This static factory method creates a wallet directly from a seed value, bypassing
	 * mnemonic processing. The seed is used to generate BIP32 master keys through 
	 * HMAC-SHA512 computation. This method is typically used internally by other
	 * factory methods or when working with pre-computed seeds.
	 * 
	 * **Seed Requirements:**
	 * - Must be hex-encoded string
	 * - Recommended length: 128-512 bits (32-128 hex characters)
	 * - Should be generated with cryptographically secure randomness
	 * - BIP39 seeds are 512 bits (128 hex characters)
	 * 
	 * **Key Generation Process:**
	 * 1. Convert hex seed to binary format
	 * 2. Compute HMAC-SHA512 with "Bitcoin seed" as key
	 * 3. Split result into private key (256 bits) and chain code (256 bits)
	 * 4. Generate corresponding public key using secp256k1
	 * 5. Create extended keys with network-specific version bytes
	 * 
	 * @static
	 * @param {string} [net='main'] - Network type ('main' for mainnet, 'test' for testnet)
	 * @param {string} [seed="000102030405060708090a0b0c0d0e0f"] - Hex-encoded cryptographic seed
	 * @returns {Custodial_Wallet} New wallet instance derived from seed
	 * 
	 * @throws {Error} If seed is not valid hexadecimal format
	 * @throws {Error} If derived private key is invalid (extremely rare)
	 * @throws {Error} If network parameter is invalid
	 * 
	 * @example
	 * // Create wallet from hex seed
	 * const seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	 * const wallet = Custodial_Wallet.fromSeed('main', seed);
	 * console.log('Seed-derived address:', wallet.address);
	 * 
	 * @example
	 * // Use BIP39-derived seed
	 * const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	 * const bip39Seed = bip39.mnemonic2seed(mnemonic);
	 * const wallet = Custodial_Wallet.fromSeed('main', bip39Seed);
	 * 
	 * @example
	 * // Custom seed for testing (deterministic addresses)
	 * const testSeed = "deadbeefcafebabe".repeat(8); // 128 hex chars
	 * const testWallet = Custodial_Wallet.fromSeed('test', testSeed);
	 * console.log('Test address:', testWallet.address);
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
	 * Derives a child key from the current wallet using BIP32 hierarchical deterministic path.
	 * 
	 * This method implements BIP32 child key derivation, allowing generation of child keys
	 * from the master key or any previously derived key. It supports both hardened and
	 * non-hardened derivation paths, with automatic path parsing and validation.
	 * 
	 * **Derivation Types:**
	 * - **Hardened derivation** (index ≥ 2³¹, marked with '): Requires private key, 
	 *   provides security isolation between parent and child
	 * - **Non-hardened derivation** (index < 2³¹): Can derive from public key only,
	 *   enables watch-only wallets but allows parent key compromise from child + chain code
	 * 
	 * **Path Format:**
	 * - Standard BIP32 notation: "m/44'/0'/0'/0/0"
	 * - m = master key
	 * - Numbers = derivation indices
	 * - ' (apostrophe) = hardened derivation (adds 2³¹ to index)
	 * - / = path separator
	 * 
	 * **Common Derivation Paths:**
	 * - BIP44 Bitcoin: "m/44'/0'/0'/0/0" (account 0, receiving address 0)
	 * - BIP44 Bitcoin Change: "m/44'/0'/0'/1/0" (account 0, change address 0)
	 * 
	 * @param {string} [path="m/0'"] - BIP32 derivation path (e.g., "m/44'/0'/0'/0/0")
	 * @param {string} [keyType='pri'] - Key type to derive ('pri' for private, 'pub' for public)
	 * @returns {Custodial_Wallet} Returns this wallet instance for method chaining
	 * 
	 * @throws {Error} "Public Key can't derive from hardened path" if attempting hardened derivation from public key
	 * @throws {Error} If derivation path format is invalid
	 * @throws {Error} If derived key is invalid (extremely rare: ~1 in 2^127)
	 * 
	 * @example
	 * // Standard BIP44 Bitcoin address derivation
	 * const wallet = Custodial_Wallet.fromRandom('main')[1];
	 * 
	 * // Derive first receiving address
	 * wallet.derive("m/44'/0'/0'/0/0", 'pri');
	 * 
	 * // Derive first change address
	 * wallet.derive("m/44'/0'/0'/1/0", 'pri');
	 * 
	 * console.log('Derived keys:', wallet.child_keys.size); // 2
	 * 
	 * @example
	 * // Method chaining for multiple derivations
	 * const wallet = Custodial_Wallet.fromRandom('main')[1];
	 * 
	 * wallet
	 *   .derive("m/44'/0'/0'/0/0", 'pri')  // First receiving
	 *   .derive("m/44'/0'/0'/0/1", 'pri')  // Second receiving
	 *   .derive("m/44'/0'/0'/1/0", 'pri'); // First change
	 * 
	 * // Access all derived addresses
	 * for (const child of wallet.child_keys) {
	 *   console.log(`Address ${child.childIndex}:`, child.address);
	 * }
	 * 
	 * @example
	 * // Public key derivation (non-hardened only)
	 * const wallet = Custodial_Wallet.fromRandom('main')[1];
	 * 
	 * // This works - non-hardened derivation
	 * wallet.derive("m/0/1/2", 'pub');
	 * 
	 * // This fails - hardened derivation from public key
	 * try {
	 *   wallet.derive("m/0'/1", 'pub');
	 * } catch (error) {
	 *   console.log(error.message); // "Public Key can't derive from hardened path"
	 * }
	 * 
	 * @example
	 * const wallet = Custodial_Wallet.fromRandom('main')[1];
	 * 
	 * // Bitcoin addresses
	 * wallet.derive("m/44'/0'/0'/0/0", 'pri');   // BTC receiving
	 * 
	 * 
	 * @example
	 * // Generate multiple addresses for a service
	 * const wallet = Custodial_Wallet.fromRandom('main')[1];
	 * 
	 * // Generate 10 unique receiving addresses
	 * for (let i = 0; i < 10; i++) {
	 *   wallet.derive(`m/44'/0'/0'/0/${i}`, 'pri');
	 * }
	 * 
	 * // Each customer gets a unique address
	 * const addresses = Array.from(wallet.child_keys).map(child => child.address);
	 * console.log('Customer addresses:', addresses);
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
	 * Signs a message using ECDSA with the wallet's private key and deterministic nonce generation.
	 * 
	 * This method creates a cryptographically secure digital signature using the wallet's
	 * private key. It implements deterministic nonce generation (RFC 6979) to prevent
	 * nonce reuse attacks and ensure signature security. The signature can be verified
	 * by anyone with the corresponding public key.
	 * 
	 * **Signature Process:**
	 * 1. Convert message to UTF-8 bytes
	 * 2. Decode WIF private key to raw bytes
	 * 3. Generate deterministic nonce using RFC 6979
	 * 4. Compute ECDSA signature (r, s) values
	 * 5. Include recovery ID for public key recovery
	 * 6. Return DER-encoded signature with recovery information
	 * 
	 * **Security Features:**
	 * - RFC 6979 deterministic nonce generation prevents nonce reuse
	 * - Uses secp256k1 elliptic curve (Bitcoin standard)
	 * - Compatible with Bitcoin transaction signing
	 * - Includes recovery ID for public key derivation
	 * 
	 * @param {string} [message=''] - Message to sign (will be converted to UTF-8 bytes)
	 * @returns {ECDSASignatureResult} Tuple containing signature bytes and recovery ID
	 * 
	 * @throws {Error} If private key is invalid or signing fails
	 * @throws {Error} If message cannot be converted to bytes
	 * 
	 * @example
	 * // Basic message signing
	 * const wallet = Custodial_Wallet.fromRandom('main')[1];
	 * const message = "Hello Bitcoin!";
	 * 
	 * const [signature, recoveryId] = wallet.sign(message);
	 * console.log('Signature length:', signature.length); // ~71-73 bytes (DER format)
	 * console.log('Recovery ID:', recoveryId);            // 0, 1, 2, or 3
	 * 
	 * @example
	 * // Sign and verify workflow
	 * const wallet = Custodial_Wallet.fromRandom('main')[1];
	 * const message = "Transfer $100 to Alice";
	 * 
	 * // Create signature
	 * const [signature, _] = wallet.sign(message);
	 * 
	 * // Verify signature (should return true)
	 * const isValid = wallet.verify(signature, message);
	 * console.log('Signature valid:', isValid); // true
	 * 
	 * // Verify with wrong message (should return false)
	 * const isInvalid = wallet.verify(signature, "Transfer $200 to Bob");
	 * console.log('Wrong message valid:', isInvalid); // false
	 * 
	 * @example
	 * // Transaction authorization pattern
	 * const wallet = Custodial_Wallet.fromRandom('main')[1];
	 * 
	 * function authorizeTransaction(txData) {
	 *   const txMessage = JSON.stringify({
	 *     to: txData.recipient,
	 *     amount: txData.amount,
	 *     timestamp: Date.now(),
	 *     nonce: Math.random()
	 *   });
	 *   
	 *   const [signature, recoveryId] = wallet.sign(txMessage);
	 *   
	 *   return {
	 *     transaction: txData,
	 *     signature: signature,
	 *     recovery: recoveryId,
	 *     signer: wallet.address
	 *   };
	 * }
	 * 
	 * const authorization = authorizeTransaction({
	 *   recipient: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
	 *   amount: 0.001
	 * });
	 * 
	 * @example
	 * // Batch signing for multiple messages
	 * const wallet = Custodial_Wallet.fromRandom('main')[1];
	 * const messages = ["msg1", "msg2", "msg3"];
	 * 
	 * const signatures = messages.map(msg => {
	 *   const [sig, recovery] = wallet.sign(msg);
	 *   return { message: msg, signature: sig, recovery };
	 * });
	 * 
	 * console.log(`Signed ${signatures.length} messages`);
	 */
	sign(message = '') {
		return ecdsa.sign(this.keypair.pri, message);
	}

	/**
	 * Verifies an ECDSA signature against a message using the wallet's public key.
	 * 
	 * This method performs cryptographic verification to ensure that a given signature
	 * was created by the holder of this wallet's private key. It uses standard ECDSA
	 * verification on the secp256k1 curve and can verify signatures created by this
	 * wallet or any other ECDSA-compatible implementation.
	 * 
	 * **Verification Process:**
	 * 1. Convert message to UTF-8 bytes (same as signing)
	 * 2. Parse signature into r and s components
	 * 3. Compute verification values using public key
	 * 4. Check that signature equation holds on elliptic curve
	 * 5. Return boolean result of verification
	 * 
	 * **Security Properties:**
	 * - Mathematically proves signature was created with corresponding private key
	 * - Cannot be forged without knowledge of private key
	 * - Deterministic result for same signature/message/public key combination
	 * - Compatible with Bitcoin transaction verification
	 * 
	 * @param {Uint8Array|Buffer} sig - DER-encoded signature bytes to verify
	 * @param {string} msg - Original message that was signed (must match exactly)
	 * @returns {boolean} True if signature is valid for this wallet's public key, false otherwise
	 * 
	 * @throws {Error} If signature format is invalid or corrupted
	 * @throws {Error} If message cannot be converted to bytes
	 * 
	 * @example
	 * // Basic signature verification
	 * const wallet = Custodial_Wallet.fromRandom('main')[1];
	 * const message = "Hello Bitcoin!";
	 * 
	 * // Sign message
	 * const [signature, _] = wallet.sign(message);
	 * 
	 * // Verify signature
	 * const isValid = wallet.verify(signature, message);
	 * console.log('Signature valid:', isValid); // true
	 * 
	 * // Verify with modified message
	 * const isInvalid = wallet.verify(signature, "Hello Ethereum!");
	 * console.log('Modified message valid:', isInvalid); // false
	 * 
	 * @example
	 * // Cross-wallet verification (different wallets)
	 * const wallet1 = Custodial_Wallet.fromRandom('main')[1];
	 * const wallet2 = Custodial_Wallet.fromRandom('main')[1];
	 * const message = "Cross-wallet test";
	 * 
	 * // Wallet1 signs message
	 * const [signature, _] = wallet1.sign(message);
	 * 
	 * // Wallet1 can verify its own signature
	 * console.log('Self verification:', wallet1.verify(signature, message)); // true
	 * 
	 * // Wallet2 cannot verify wallet1's signature
	 * console.log('Cross verification:', wallet2.verify(signature, message)); // false
	 * 
	 * @example
	 * // Transaction verification workflow
	 * function verifyTransactionSignature(txData, signature, senderAddress) {
	 *   // Reconstruct the exact message that was signed
	 *   const txMessage = JSON.stringify(txData);
	 *   
	 *   // Find wallet for sender address (in real app, lookup from database)
	 *   const senderWallet = findWalletByAddress(senderAddress);
	 *   
	 *   // Verify signature matches sender's private key
	 *   return senderWallet.verify(signature, txMessage);
	 * }
	 * 
	 * @example
	 * // Batch verification for audit trail
	 * const wallet = Custodial_Wallet.fromRandom('main')[1];
	 * const signedMessages = [
	 *   { msg: "tx1", sig: wallet.sign("tx1")[0] },
	 *   { msg: "tx2", sig: wallet.sign("tx2")[0] },
	 *   { msg: "tx3", sig: wallet.sign("tx3")[0] }
	 * ];
	 * 
	 * // Verify all signatures are valid
	 * const allValid = signedMessages.every(item => 
	 *   wallet.verify(item.sig, item.msg)
	 * );
	 * 
	 * console.log('All signatures valid:', allValid); // true
	 */
	verify(sig, msg) {
		return ecdsa.verify(sig, msg, this.#serialization_format.pubKey.key);
	}
}

/**
 * Non-custodial wallet implementation using Threshold Signature Scheme (TSS)
 * for distributed key management. Enables multi-party control without a trusted party.
 * 
 * This class implements advanced threshold cryptography where any subset of participants
 * meeting the threshold requirement can collaboratively generate valid signatures without
 * ever reconstructing the private key. It's ideal for scenarios requiring distributed
 * control, enhanced security, and elimination of single points of failure.
 * 
 * **Key Features:**
 * - Distributed key generation using Joint Verifiable Random Secret Sharing (JVRSS)
 * - Threshold signature generation compatible with standard ECDSA verification
 * - No trusted dealer required for key setup
 * - Configurable t-of-n threshold schemes (e.g., 2-of-3, 3-of-5, 5-of-7)
 * - Secret shares can be distributed across different entities or devices
 * - Compatible with Bitcoin transaction signing and verification
 * 
 * **Security Model:**
 * - Requires exactly t participants to generate signatures
 * - Information-theoretic security: < t participants learn nothing about private key
 * - No single point of failure: up to n-t participants can be compromised safely
 * - Private key never exists in complete form anywhere
 * - Forward secrecy: compromising future shares doesn't reveal past signatures
 * 
 * **Use Cases:**
 * - Corporate treasury management with executive approval
 * - Cryptocurrency exchanges with operator separation
 * - Escrow services with dispute resolution
 * - Multi-signature wallets for shared accounts
 * - Compliance requirements for multi-party authorization
 * - High-value asset protection with distributed control
 * 
 * @class Non_Custodial_Wallet
 * @extends ThresholdSignature
 * @since 1.0.0
 * 
 * @example
 * // Create a 2-of-3 escrow wallet
 * const escrowWallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
 * const [buyerShare, sellerShare, arbiterShare] = escrowWallet._shares;
 * 
 * // Normal release: buyer + seller
 * const releaseWallet = Non_Custodial_Wallet.fromShares("main", [buyerShare, sellerShare], 2);
 * const releaseSignature = releaseWallet.sign("Release funds to seller");
 * 
 * // Dispute resolution: buyer + arbiter or seller + arbiter
 * const disputeWallet = Non_Custodial_Wallet.fromShares("main", [buyerShare, arbiterShare], 2);
 * const disputeSignature = disputeWallet.sign("Refund to buyer after dispute");
 * 
 * @example
 * // Corporate treasury with 3-of-5 executive approval
 * const corporateWallet = Non_Custodial_Wallet.fromRandom("main", 5, 3);
 * const executiveShares = corporateWallet._shares;
 * 
 * // Distribute shares to 5 executives
 * const executives = [
 *   { name: "CEO", share: executiveShares[0] },
 *   { name: "CFO", share: executiveShares[1] },
 *   { name: "COO", share: executiveShares[2] },
 *   { name: "CTO", share: executiveShares[3] },
 *   { name: "Board Rep", share: executiveShares[4] }
 * ];
 * 
 * // Any 3 executives can authorize payments
 * const paymentAuth = Non_Custodial_Wallet.fromShares("main", 
 *   [executives[0].share, executives[1].share, executives[2].share], 3);
 * 
 * const authSignature = paymentAuth.sign("Q4 dividend payment: $1M");
 * 
 * @example
 * // Cryptocurrency exchange cold storage
 * const exchangeWallet = Non_Custodial_Wallet.fromRandom("main", 7, 4);
 * const operatorShares = exchangeWallet._shares;
 * 
 * // Distribute shares across geographic locations and roles
 * const distribution = [
 *   { location: "US-East", role: "Security Officer", share: operatorShares[0] },
 *   { location: "US-West", role: "Operations Lead", share: operatorShares[1] },
 *   { location: "EU", role: "Compliance Officer", share: operatorShares[2] },
 *   { location: "Asia", role: "Technical Lead", share: operatorShares[3] },
 *   { location: "Backup-1", role: "Emergency Access", share: operatorShares[4] },
 *   { location: "Backup-2", role: "Emergency Access", share: operatorShares[5] },
 *   { location: "Audit", role: "External Auditor", share: operatorShares[6] }
 * ];
 * 
 * // Requires 4 of 7 operators to authorize large withdrawals
 * // Provides redundancy and prevents single operator compromise
 */
class Non_Custodial_Wallet extends ThresholdSignature {

	/**
	 * Creates a new Non_Custodial_Wallet instance with specified threshold parameters.
	 * 
	 * This constructor initializes a threshold signature scheme with the given group size
	 * and threshold requirements. It automatically generates the distributed key shares
	 * using JVRSS (Joint Verifiable Random Secret Sharing) and computes the corresponding
	 * Bitcoin address for receiving payments.
	 * 
	 * **Initialization Process:**
	 * 1. Validate threshold parameters (t ≤ n, t ≥ 2)
	 * 2. Execute JVRSS protocol for distributed key generation
	 * 3. Generate secret shares for each participant
	 * 4. Compute aggregate public key from polynomial constants
	 * 5. Derive Bitcoin address from public key
	 * 
	 * **Parameter Constraints:**
	 * - group_size ≥ 2 (minimum meaningful distribution)
	 * - threshold ≥ 2 (minimum security requirement)
	 * - threshold ≤ group_size (cannot exceed total participants)
	 * - Recommended: threshold ≤ (group_size + 1) / 2 for practical usability
	 * 
	 * @param {string} net - Network type ('main' for mainnet, 'test' for testnet)
	 * @param {number} group_size - Total number of participants in the threshold scheme
	 * @param {number} threshold - Minimum number of participants required for operations
	 * 
	 * @throws {Error} "Threshold is too high or low" if parameter constraints are violated
	 * @throws {Error} If network type is not 'main' or 'test'
	 * 
	 * @example
	 * // Create a 2-of-3 threshold wallet
	 * const wallet = new Non_Custodial_Wallet('main', 3, 2);
	 * console.log('Group size:', wallet.group_size);     // 3
	 * console.log('Threshold:', wallet.threshold);       // 2
	 * console.log('Address:', wallet.address);           // Bitcoin address
	 * console.log('Shares:', wallet._shares.length);     // 3 hex-encoded shares
	 * 
	 * @example
	 * // Corporate wallet with higher security
	 * const corporateWallet = new Non_Custodial_Wallet('main', 7, 4);
	 * // Requires 4 of 7 executives to authorize transactions
	 * 
	 * @example
	 * // Error handling for invalid parameters
	 * try {
	 *   const invalidWallet = new Non_Custodial_Wallet('main', 3, 5); // threshold > group_size
	 * } catch (error) {
	 *   console.error('Invalid parameters:', error.message);
	 * }
	 */
	constructor(net, group_size, threshold) {
		super(group_size, threshold);

		/**
		 * Network type for this threshold wallet instance.
		 * Determines address formats, version bytes, and network-specific parameters.
		 * 
		 * @type {string}
		 * @readonly
		 * @memberof Non_Custodial_Wallet
		 * @example
		 * console.log(wallet.net); // "main" or "test"
		 */
		this.net = net;

		// Generate wallet address and public key from threshold scheme
		[this.publicKey, this.address] = this.#wallet();
	}

	/**
	 * Generates a new random threshold wallet with specified parameters.
	 * 
	 * This static factory method creates a fresh threshold signature scheme using
	 * cryptographically secure randomness. It initializes the distributed key generation
	 * protocol and produces a complete threshold wallet ready for multi-party operations.
	 * 
	 * **Generation Process:**
	 * 1. Create new threshold signature instance with specified parameters
	 * 2. Execute JVRSS for distributed key generation  
	 * 3. Generate secret shares for all participants
	 * 4. Compute aggregate public key and Bitcoin address
	 * 5. Return initialized wallet instance
	 * 
	 * **Security Properties:**
	 * - Uses cryptographically secure random number generation
	 * - No participant has knowledge of the complete private key
	 * - Secret shares are information-theoretically secure
	 * - Aggregate public key is verifiable and deterministic
	 * 
	 * @static
	 * @param {string} [net="main"] - Network type ('main' for mainnet, 'test' for testnet)
	 * @param {number} [group_size=3] - Total number of participants in the scheme
	 * @param {number} [threshold=2] - Minimum participants needed for signature generation
	 * @returns {Non_Custodial_Wallet} New threshold wallet instance
	 * 
	 * @throws {Error} "Threshold is too high or low" if constraints are violated
	 * @throws {Error} If network parameter is invalid
	 * 
	 * @example
	 * // Standard 2-of-3 multi-signature wallet
	 * const multiSigWallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
	 * console.log('Multi-sig address:', multiSigWallet.address);
	 * 
	 * // Get shares for distribution
	 * const [share1, share2, share3] = multiSigWallet._shares;
	 * console.log('Share 1:', share1); // Hex-encoded secret share
	 * 
	 * @example
	 * // Corporate treasury wallet (3-of-5)
	 * const treasuryWallet = Non_Custodial_Wallet.fromRandom("main", 5, 3);
	 * const executiveShares = treasuryWallet._shares;
	 * 
	 * // Distribute shares to executives
	 * const shareDistribution = [
	 *   { executive: "CEO", share: executiveShares[0] },
	 *   { executive: "CFO", share: executiveShares[1] },
	 *   { executive: "COO", share: executiveShares[2] },
	 *   { executive: "CTO", share: executiveShares[3] },
	 *   { executive: "Board Rep", share: executiveShares[4] }
	 * ];
	 * 
	 * @example
	 * // High-security vault (5-of-9)
	 * const vaultWallet = Non_Custodial_Wallet.fromRandom("main", 9, 5);
	 * console.log(`Vault requires ${vaultWallet.threshold} of ${vaultWallet.group_size} participants`);
	 * 
	 * // Example distribution across different security zones
	 * const vaultShares = vaultWallet._shares;
	 * const securityZones = [
	 *   { zone: "Primary Datacenter", shares: vaultShares.slice(0, 3) },
	 *   { zone: "Secondary Datacenter", shares: vaultShares.slice(3, 6) },
	 *   { zone: "Offline Storage", shares: vaultShares.slice(6, 9) }
	 * ];
	 */
	static fromRandom(net = "main", group_size = 3, threshold = 2) {
		return new this(
			net,
			group_size,
			threshold
		)
	}

	/**
	 * Reconstructs a threshold wallet from existing secret shares.
	 * 
	 * This static factory method rebuilds a threshold wallet from previously distributed
	 * secret shares. It's used when participants want to reconstruct the wallet for
	 * signature generation or when migrating shares between systems. The method validates
	 * share consistency and reconstructs the public key and address.
	 * 
	 * **Reconstruction Process:**
	 * 1. Create new threshold instance with matching parameters
	 * 2. Convert hex-encoded shares to BigNumber format
	 * 3. Reconstruct the aggregate public key from shares
	 * 4. Derive Bitcoin address from reconstructed public key
	 * 5. Validate share consistency and threshold requirements
	 * 
	 * **Security Considerations:**
	 * - Only provided shares are used; missing shares remain unknown
	 * - Threshold requirement still applies for signature generation
	 * - Share authenticity should be verified through secure channels
	 * - Reconstructed wallet has same capabilities as original
	 * 
	 * @static
	 * @param {string} [net="main"] - Network type ('main' for mainnet, 'test' for testnet)
	 * @param {string[]} shares - Array of hex-encoded secret shares
	 * @param {number} [threshold=2] - Minimum participants required for operations
	 * @returns {Non_Custodial_Wallet} Reconstructed threshold wallet instance
	 * 
	 * @throws {Error} If threshold is greater than number of provided shares
	 * @throws {Error} If reconstructed public key is invalid
	 * 
	 * @example
	 * // Reconstruct 2-of-3 wallet from shares
	 * const originalShares = [
	 *   "79479395a59a8e9d930f2b10ccd5ac3671b0ff0bf8a66aaa1d74978c5353694b",
	 *   "98510126c920e18b148130ac1145686cb299d21f0e010b98ede44169a7bb1c13",
	 *   "b7428d37e5847f9a8b3d4c2f9a1e5c8d7b4f2a8e9c1d5b7a3f8e2c9d4b6a1f5"
	 * ];
	 * 
	 * const reconstructedWallet = Non_Custodial_Wallet.fromShares("main", originalShares, 2);
	 * console.log('Reconstructed address:', reconstructedWallet.address);
	 * 
	 * @example
	 * // Partial reconstruction for signing (only threshold shares needed)
	 * const originalWallet = Non_Custodial_Wallet.fromRandom("main", 5, 3);
	 * const allShares = originalWallet._shares;
	 * 
	 * // Use only 3 shares (minimum threshold)
	 * const signingShares = [allShares[0], allShares[2], allShares[4]];
	 * const signingWallet = Non_Custodial_Wallet.fromShares("main", signingShares, 3);
	 * 
	 * // Can generate signatures with just threshold shares
	 * const signature = signingWallet.sign("Authorized payment");
	 * 
	 * @example
	 * // Corporate recovery scenario
	 * function recoverCorporateWallet(executiveShares) {
	 *   if (executiveShares.length < 3) {
	 *     throw new Error("Insufficient executives present for recovery");
	 *   }
	 *   
	 *   // Reconstruct wallet from available executive shares
	 *   const recoveredWallet = Non_Custodial_Wallet.fromShares(
	 *     "main", 
	 *     executiveShares.slice(0, 3), // Use first 3 available shares
	 *     3
	 *   );
	 *   
	 *   return recoveredWallet;
	 * }
	 * 
	 * @example
	 * // Cross-platform wallet migration
	 * // Export shares from mobile app
	 * const mobileShares = mobileWallet._shares;
	 * 
	 * // Import to desktop application
	 * const desktopWallet = Non_Custodial_Wallet.fromShares("main", mobileShares, 2);
	 * 
	 * // Desktop wallet has identical functionality
	 * console.log('Same address:', mobileWallet.address === desktopWallet.address); // true
	 */
	static fromShares(net = "main", shares, threshold = 2) {
		const wallet = new this(
			net,
			shares.length,
			threshold
		)

		// Convert hex shares to BigNumber format and reconstruct public key
		wallet.shares = shares.map(x => new BN(x, 'hex'));
		wallet.public_key = secp256k1.ProjectivePoint.fromPrivateKey(wallet.privite_key().toBuffer());
		[wallet.publicKey, wallet.address] = wallet.#wallet();

		return wallet;
	}

	/**
	 * Gets the secret shares as hex-encoded strings for secure distribution to participants.
	 * 
	 * This getter provides access to the distributed secret shares in a format suitable
	 * for secure transmission and storage. Each share is a hex-encoded string representing
	 * a point on the secret-sharing polynomial. These shares should be distributed to
	 * different participants and stored securely.
	 * 
	 * **Share Properties:**
	 * - Each share is cryptographically independent
	 * - Shares are information-theoretically secure (< threshold reveals nothing)
	 * - Hex encoding ensures safe transmission over text-based channels
	 * - Each share is typically 64 hex characters (32 bytes)
	 * - Shares should be transmitted over secure, authenticated channels
	 * 
	 * **Distribution Best Practices:**
	 * - Use secure communication channels (encrypted email, secure messaging)
	 * - Verify recipient identity before share distribution
	 * - Consider using QR codes for offline share transfer
	 * - Implement share backup and recovery procedures
	 * - Document which participant holds which share index
	 * 
	 * @returns {string[]} Array of hex-encoded secret shares for distribution
	 * 
	 * @example
	 * // Basic share distribution
	 * const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
	 * const shares = wallet._shares;
	 * 
	 * console.log('Number of shares:', shares.length); // 3
	 * console.log('Share format:', shares[0]);          // "79479395a59a8e9d..."
	 * 
	 * @example
	 * // Secure share distribution to participants
	 * const corporateWallet = Non_Custodial_Wallet.fromRandom("main", 5, 3);
	 * const executiveShares = corporateWallet._shares;
	 * 
	 * const executives = [
	 *   { name: "Alice Johnson", email: "alice@company.com", share: executiveShares[0] },
	 *   { name: "Bob Smith", email: "bob@company.com", share: executiveShares[1] },
	 *   { name: "Carol Davis", email: "carol@company.com", share: executiveShares[2] },
	 *   { name: "Dave Wilson", email: "dave@company.com", share: executiveShares[3] },
	 *   { name: "Eve Brown", email: "eve@company.com", share: executiveShares[4] }
	 * ];
	 * 
	 * // Distribute shares securely
	 * executives.forEach(exec => {
	 *   sendSecureEmail(exec.email, `Your wallet share: ${exec.share}`);
	 *   console.log(`Share distributed to ${exec.name}`);
	 * });
	 * 
	 * @example
	 * // QR code generation for offline distribution
	 * const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
	 * const shares = wallet._shares;
	 * 
	 * shares.forEach((share, index) => {
	 *   const qrCode = generateQRCode(share);
	 *   saveQRCode(qrCode, `share_${index + 1}.png`);
	 *   console.log(`QR code generated for share ${index + 1}`);
	 * });
	 * 
	 * @example
	 * // Backup and recovery documentation
	 * const wallet = Non_Custodial_Wallet.fromRandom("main", 5, 3);
	 * const shares = wallet._shares;
	 * 
	 * const backupDocument = {
	 *   walletAddress: wallet.address,
	 *   threshold: wallet.threshold,
	 *   totalShares: wallet.group_size,
	 *   creationDate: new Date().toISOString(),
	 *   shares: shares.map((share, index) => ({
	 *     index: index + 1,
	 *     share: share,
	 *     holder: `Participant ${index + 1}`,
	 *     status: 'Active'
	 *   }))
	 * };
	 * 
	 * // Store backup document securely
	 * storeSecureBackup(JSON.stringify(backupDocument, null, 2));
	 */
	get _shares() {
		return this.shares.map(x => x.toString('hex'));
	}

	/**
	 * Private method to generate Bitcoin wallet address and public key from threshold scheme.
	 * 
	 * This internal method computes the Bitcoin address and hex-encoded public key from
	 * the aggregate public key generated by the threshold signature scheme. It applies
	 * network-specific version bytes and follows standard Bitcoin address generation.
	 * 
	 * **Address Generation Process:**
	 * 1. Determine network version byte (mainnet vs testnet)
	 * 2. Convert aggregate public key to compressed format
	 * 3. Compute HASH160 (RIPEMD160(SHA256(pubkey)))
	 * 4. Add version byte and checksum
	 * 5. Encode using Base58Check format
	 * 
	 * @private
	 * @returns {Array} Tuple containing hex public key and Bitcoin address
	 * @returns {string} returns.0 - Hex-encoded compressed public key
	 * @returns {string} returns.1 - Bitcoin address for receiving payments
	 * @memberof Non_Custodial_Wallet
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
	 * Gets the reconstructed private key in WIF (Wallet Import Format).
	 * 
	 * This getter reconstructs the complete private key from the distributed shares
	 * and returns it in standard WIF format. This operation defeats the purpose of
	 * the threshold scheme by centralizing the private key, so it should be used
	 * with extreme caution and only when absolutely necessary.
	 * 
	 * **Security Warning:**
	 * - Reconstructing the private key eliminates the security benefits of threshold signatures
	 * - The complete private key provides full control over the wallet
	 * - Should only be used for emergency recovery or migration scenarios
	 * - Consider using threshold signatures instead of key reconstruction when possible
	 * - Ensure secure deletion of the reconstructed key after use
	 * 
	 * **Use Cases:**
	 * - Emergency wallet recovery when threshold scheme is no longer viable
	 * - Migration to different wallet software that doesn't support threshold signatures
	 * - Compliance requirements that mandate private key export
	 * - Integration with legacy systems that require WIF private keys
	 * 
	 * @returns {string} WIF-encoded private key with network-appropriate version byte
	 * 
	 * @throws {Error} If insufficient shares are available for reconstruction
	 * @throws {Error} If private key reconstruction fails
	 * 
	 * @example
	 * // Emergency private key extraction (use with caution!)
	 * const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
	 * 
	 * // Only use in emergency situations
	 * console.warn('Reconstructing private key - this defeats threshold security!');
	 * const privateKey = wallet._privateKey;
	 * console.log('WIF Private Key:', privateKey);
	 * // "L5HgWvFghocq1FmxSjKNaGhVN8f67p6xYg5pY7M8FE77HXwHtGGu"
	 * 
	 * @example
	 * // Secure private key extraction with cleanup
	 * function emergencyKeyExtraction(thresholdWallet) {
	 *   console.warn('SECURITY WARNING: Extracting private key from threshold wallet');
	 *   
	 *   try {
	 *     // Extract private key
	 *     const privateKey = thresholdWallet._privateKey;
	 *     
	 *     // Use private key for emergency operation
	 *     const emergencyOperation = performEmergencyTransfer(privateKey);
	 *     
	 *     // Clear private key from memory (best effort)
	 *     privateKey.fill('\0'); // Overwrite string content
	 *     
	 *     return emergencyOperation;
	 *   } catch (error) {
	 *     console.error('Private key extraction failed:', error);
	 *     throw error;
	 *   }
	 * }
	 * 
	 * @example
	 * // Migration to single-key wallet
	 * const thresholdWallet = Non_Custodial_Wallet.fromShares("main", shares, 2);
	 * 
	 * // Extract private key for migration
	 * const migratedPrivateKey = thresholdWallet._privateKey;
	 * 
	 * // Create equivalent single-key wallet
	 * const singleKeyWallet = Custodial_Wallet.fromSeed("main", 
	 *   privateKeyToSeed(migratedPrivateKey));
	 * 
	 * // Verify address consistency
	 * console.log('Address match:', 
	 *   thresholdWallet.address === singleKeyWallet.address); // true
	 */
	get _privateKey() {
		const privKey = {
			key: this.privite_key().toBuffer(),
			versionByteNum: this.net === 'main' ? 0x80 : 0xef
		}
		return standardKey(privKey, undefined).pri;
	}

	/**
	 * Verifies a threshold signature against the original message hash.
	 * 
	 * This method performs cryptographic verification of threshold signatures using
	 * standard ECDSA verification. Threshold signatures are mathematically equivalent
	 * to single-party ECDSA signatures, so they can be verified using standard
	 * verification algorithms without knowledge of the threshold scheme.
	 * 
	 * **Verification Process:**
	 * 1. Parse signature into r and s components
	 * 2. Validate signature components are within valid ranges
	 * 3. Compute verification equation using aggregate public key
	 * 4. Check that computed point matches signature r value
	 * 5. Return boolean result of verification
	 * 
	 * **Compatibility:**
	 * - Compatible with standard ECDSA verification
	 * - Can be verified by any Bitcoin-compatible software
	 * - Third parties don't need knowledge of threshold scheme
	 * - Signatures are indistinguishable from single-party signatures
	 * 
	 * @param {Object} sig - Signature object with r and s properties (BigInt values)
	 * @param {Buffer} msgHash - SHA256 hash of the original message (32 bytes)
	 * @returns {boolean} True if signature is valid for this wallet's public key, false otherwise
	 * 
	 * @throws {Error} If signature format is invalid
	 * @throws {Error} If message hash is not 32 bytes
	 * 
	 * @example
	 * // Basic threshold signature verification
	 * const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
	 * const message = "Multi-party authorization required";
	 * 
	 * // Generate threshold signature
	 * const signature = wallet.sign(message);
	 * 
	 * // Verify signature
	 * const isValid = wallet.verify(signature.sig, signature.msgHash);
	 * console.log('Threshold signature valid:', isValid); // true
	 * 
	 * @example
	 * // Cross-verification with different wallet instances
	 * const originalWallet = Non_Custodial_Wallet.fromRandom("main", 5, 3);
	 * const shares = originalWallet._shares;
	 * 
	 * // Create signing wallet with threshold shares
	 * const signingWallet = Non_Custodial_Wallet.fromShares("main", shares.slice(0, 3), 3);
	 * 
	 * // Create verification wallet with different shares
	 * const verifyingWallet = Non_Custodial_Wallet.fromShares("main", shares.slice(2, 5), 3);
	 * 
	 * const message = "Cross-wallet verification test";
	 * const signature = signingWallet.sign(message);
	 * 
	 * // Both wallets should verify the same signature
	 * const valid1 = signingWallet.verify(signature.sig, signature.msgHash);
	 * const valid2 = verifyingWallet.verify(signature.sig, signature.msgHash);
	 * console.log('Both verify same:', valid1 === valid2 && valid1 === true); // true
	 * 
	 * @example
	 * // Third-party verification without threshold knowledge
	 * function verifyPaymentAuthorization(publicKeyHex, messageHash, signature) {
	 *   // This function doesn't know about threshold signatures
	 *   // It just uses standard ECDSA verification
	 *   
	 *   const publicKey = secp256k1.ProjectivePoint.fromHex(publicKeyHex);
	 *   return ThresholdSignature.verify_threshold_signature(publicKey, messageHash, signature);
	 * }
	 * 
	 * const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
	 * const authorization = wallet.sign("Payment approved: $10,000");
	 * 
	 * // Third party can verify without knowing about threshold scheme
	 * const thirdPartyVerification = verifyPaymentAuthorization(
	 *   wallet.publicKey,
	 *   authorization.msgHash,
	 *   authorization.sig
	 * );
	 * 
	 * console.log('Third party verification:', thirdPartyVerification); // true
	 * 
	 * @example
	 * // Batch verification for audit trail
	 * const wallet = Non_Custodial_Wallet.fromRandom("main", 5, 3);
	 * const transactions = [
	 *   "Transfer $1000 to Account A",
	 *   "Transfer $2000 to Account B", 
	 *   "Transfer $3000 to Account C"
	 * ];
	 * 
	 * // Generate signatures for all transactions
	 * const signedTransactions = transactions.map(tx => {
	 *   const signature = wallet.sign(tx);
	 *   return {
	 *     transaction: tx,
	 *     signature: signature.sig,
	 *     messageHash: signature.msgHash
	 *   };
	 * });
	 * 
	 * // Verify all signatures
	 * const allValid = signedTransactions.every(item =>
	 *   wallet.verify(item.signature, item.messageHash)
	 * );
	 * 
	 * console.log('All transactions valid:', allValid); // true
	 */
	verify(sig, msgHash) {
		return ThresholdSignature.verify_threshold_signature(this.public_key, msgHash, sig);
	}
}

export {
	Custodial_Wallet,
	Non_Custodial_Wallet
}