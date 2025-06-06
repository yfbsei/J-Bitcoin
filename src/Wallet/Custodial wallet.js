/**
 * @fileoverview Custodial wallet implementation for J-Bitcoin library
 * 
 * This module implements traditional single-party control wallet using hierarchical deterministic 
 * key derivation (BIP32) with standard ECDSA signatures. Suitable for individual users and 
 * applications requiring simple key management.
 * 
 * @author yfbsei
 * @version 2.0.0
 * @since 1.0.0
 * 
 * @requires fromSeed
 * @requires derive
 * @requires bip39
 * @requires ecdsa
 * @requires standardKey
 * @requires address
 * 
 * @example
 * // Import custodial wallet
 * import Custodial_Wallet from './Custodial_Wallet.js';
 * 
 * // Create custodial wallet
 * const [mnemonic, custodialWallet] = Custodial_Wallet.fromRandom('main');
 */

import fromSeed from '../BIP32/From Seed.js';
import derive from '../BIP32/Derive.js';
import bip39 from '../BIP39/mnemonic.js';
import ecdsa from '../Signature Algorithms/Ecdsa.js';

import { standardKey, address } from '../Encoding utilities/Encode Keys.js';
import {
    BIP44_CONSTANTS,
    DERIVATION_PATHS,
    NETWORKS as BITCOIN_NETWORKS,
    ADDRESS_FORMATS,
    BIP_PURPOSES,
    generateDerivationPath,
    parseDerivationPath,
    isValidBitcoinPath,
    getNetworkByCoinType
} from '../Constants.js';

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
 * @property {string} derivationPath - The full BIP32 path used to derive this key
 * @property {Object} pathInfo - Parsed derivation path components
 * @example
 * // Child key at m/44'/0'/0'/0/0
 * const childInfo = {
 *   depth: 5,
 *   childIndex: 0,
 *   hdKey: { HDpri: "...", HDpub: "..." },
 *   keypair: { pri: "...", pub: "..." },
 *   address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
 *   derivationPath: "m/44'/0'/0'/0/0",
 *   pathInfo: { purpose: 44, coinType: 0, account: 0, change: 0, addressIndex: 0 }
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
 * - Integrated Bitcoin constants and utility functions
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
 * // Use integrated constants for standardized derivation
 * const wallet = Custodial_Wallet.fromRandom('main')[1];
 * 
 * // Generate standard Bitcoin addresses using built-in methods
 * wallet.deriveReceivingAddress(0);  // First receiving address
 * wallet.deriveChangeAddress(0);     // First change address
 * wallet.deriveTestnetAddress(0);    // Testnet address
 * 
 * console.log('Child keys:', Array.from(wallet.child_keys));
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
        // Validate network parameter
        if (net !== 'main' && net !== 'test') {
            throw new Error(`Invalid network: ${net}. Must be 'main' or 'test'`);
        }

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
         * Bitcoin network configuration for this wallet.
         * Contains network-specific parameters and constants.
         * 
         * @type {Object}
         * @readonly
         * @memberof Custodial_Wallet
         * @example
         * console.log(wallet.networkConfig.name);        // "Bitcoin" or "Bitcoin Testnet"
         * console.log(wallet.networkConfig.symbol);      // "BTC"
         * console.log(wallet.networkConfig.coinType);    // 0 or 1
         */
        this.networkConfig = getNetworkByCoinType(net === 'main' ? 0 : 1);

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
     * @throws {Error} If mnemonic checksum validation fails
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
     */
    derive(path = "m/0'", keyType = 'pri') {
        // Validate derivation path format
        if (!isValidBitcoinPath(path)) {
            console.warn(`⚠️  Non-standard derivation path: ${path}. Consider using Bitcoin standard paths.`);
        }

        const key = this.hdKey[keyType === 'pri' ? 'HDpri' : 'HDpub'];
        const [hdKey, serialization_format] = derive(path, key, this.#serialization_format);

        // Parse path information for additional metadata
        let pathInfo = null;
        try {
            pathInfo = parseDerivationPath(path);
        } catch (error) {
            // If path doesn't match standard format, store basic info
            pathInfo = { path, format: 'custom' };
        }

        this.child_keys.add({
            depth: serialization_format.depth,
            childIndex: serialization_format.childIndex,
            hdKey,
            keypair: standardKey(keyType !== 'pub' ? serialization_format.privKey : false, serialization_format.pubKey),
            address: address(serialization_format.versionByte.pubKey, serialization_format.pubKey.key),
            derivationPath: path,
            pathInfo
        });

        return this;
    }

    /**
     * Derives a Bitcoin receiving address using standard BIP44 path.
     * 
     * This convenience method generates a receiving address following BIP44 standard:
     * m/44'/coinType'/0'/0/addressIndex where coinType depends on network.
     * 
     * @param {number} [addressIndex=0] - Address index (0, 1, 2, ...)
     * @returns {Custodial_Wallet} Returns this wallet instance for method chaining
     * 
     * @example
     * const wallet = Custodial_Wallet.fromRandom('main')[1];
     * wallet.deriveReceivingAddress(0);  // First receiving address
     * wallet.deriveReceivingAddress(1);  // Second receiving address
     */
    deriveReceivingAddress(addressIndex = 0) {
        const path = generateDerivationPath({
            purpose: BIP44_CONSTANTS.PURPOSE,
            coinType: this.networkConfig.coinType,
            account: BIP44_CONSTANTS.ACCOUNT,
            change: BIP44_CONSTANTS.CHANGE.EXTERNAL,
            addressIndex
        });
        return this.derive(path, 'pri');
    }

    /**
     * Derives a Bitcoin change address using standard BIP44 path.
     * 
     * This convenience method generates a change address following BIP44 standard:
     * m/44'/coinType'/0'/1/addressIndex where coinType depends on network.
     * 
     * @param {number} [addressIndex=0] - Address index (0, 1, 2, ...)
     * @returns {Custodial_Wallet} Returns this wallet instance for method chaining
     * 
     * @example
     * const wallet = Custodial_Wallet.fromRandom('main')[1];
     * wallet.deriveChangeAddress(0);  // First change address
     * wallet.deriveChangeAddress(1);  // Second change address
     */
    deriveChangeAddress(addressIndex = 0) {
        const path = generateDerivationPath({
            purpose: BIP44_CONSTANTS.PURPOSE,
            coinType: this.networkConfig.coinType,
            account: BIP44_CONSTANTS.ACCOUNT,
            change: BIP44_CONSTANTS.CHANGE.INTERNAL,
            addressIndex
        });
        return this.derive(path, 'pri');
    }

    /**
     * Derives a testnet address regardless of current wallet network.
     * 
     * This convenience method generates a testnet address using BIP44 standard,
     * useful for testing or cross-network operations.
     * 
     * @param {number} [addressIndex=0] - Address index (0, 1, 2, ...)
     * @returns {Custodial_Wallet} Returns this wallet instance for method chaining
     * 
     * @example
     * const wallet = Custodial_Wallet.fromRandom('main')[1];
     * wallet.deriveTestnetAddress(0);  // Testnet address for testing
     */
    deriveTestnetAddress(addressIndex = 0) {
        const path = generateDerivationPath({
            purpose: BIP44_CONSTANTS.PURPOSE,
            coinType: BIP44_CONSTANTS.COIN_TYPES.BITCOIN_TESTNET,
            account: BIP44_CONSTANTS.ACCOUNT,
            change: BIP44_CONSTANTS.CHANGE.EXTERNAL,
            addressIndex
        });
        return this.derive(path, 'pri');
    }

    /**
     * Gets all child keys of a specific address type.
     * 
     * @param {string} [addressType='receiving'] - Type: 'receiving', 'change', or 'testnet'
     * @returns {Array<ChildKeyInfo>} Array of matching child keys
     * 
     * @example
     * const wallet = Custodial_Wallet.fromRandom('main')[1];
     * wallet.deriveReceivingAddress(0).deriveReceivingAddress(1).deriveChangeAddress(0);
     * 
     * const receivingAddresses = wallet.getChildKeysByType('receiving');
     * console.log(`Generated ${receivingAddresses.length} receiving addresses`);
     */
    getChildKeysByType(addressType = 'receiving') {
        return Array.from(this.child_keys).filter(child => {
            if (!child.pathInfo || child.pathInfo.format === 'custom') return false;

            switch (addressType) {
                case 'receiving':
                    return child.pathInfo.change === BIP44_CONSTANTS.CHANGE.EXTERNAL &&
                        child.pathInfo.coinType !== BIP44_CONSTANTS.COIN_TYPES.BITCOIN_TESTNET;
                case 'change':
                    return child.pathInfo.change === BIP44_CONSTANTS.CHANGE.INTERNAL &&
                        child.pathInfo.coinType !== BIP44_CONSTANTS.COIN_TYPES.BITCOIN_TESTNET;
                case 'testnet':
                    return child.pathInfo.coinType === BIP44_CONSTANTS.COIN_TYPES.BITCOIN_TESTNET;
                default:
                    return false;
            }
        });
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
     */
    verify(sig, msg) {
        return ecdsa.verify(sig, msg, this.#serialization_format.pubKey.key);
    }

    /**
     * Gets wallet summary information including network details and key counts.
     * 
     * @returns {Object} Wallet summary object
     * 
     * @example
     * const wallet = Custodial_Wallet.fromRandom('main')[1];
     * wallet.deriveReceivingAddress(0).deriveChangeAddress(0);
     * 
     * const summary = wallet.getSummary();
     * console.log(summary);
     * // {
     * //   network: "Bitcoin",
     * //   address: "1BvBM...",
     * //   derivedKeys: 2,
     * //   receivingAddresses: 1,
     * //   changeAddresses: 1,
     * //   testnetAddresses: 0
     * // }
     */
    getSummary() {
        return {
            network: this.networkConfig.name,
            address: this.address,
            derivedKeys: this.child_keys.size,
            receivingAddresses: this.getChildKeysByType('receiving').length,
            changeAddresses: this.getChildKeysByType('change').length,
            testnetAddresses: this.getChildKeysByType('testnet').length
        };
    }
}

export default Custodial_Wallet;