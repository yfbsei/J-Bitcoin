/**
 * @fileoverview Main entry point for J-Bitcoin cryptocurrency library
 * 
 * J-Bitcoin is a comprehensive JavaScript library for Bitcoin 
 * that provides both custodial and non-custodial wallet functionality with advanced
 * cryptographic features including threshold signatures and hierarchical deterministic keys.
 * 
 * @author yfbsei
 * @version 1.0.0
 * @license ISC
 * 
 * @example
 * // Import main wallet classes
 * import { Custodial_Wallet, Non_Custodial_Wallet } from 'j-bitcoin';
 * 
 * // Import address utilities
 * import { CASH_ADDR, BECH32 } from 'j-bitcoin';
 * 
 * // Import signature utilities  
 * import { schnorr_sig, ecdsa } from 'j-bitcoin';
 * 
 * @see {@link https://github.com/yfbsei/J-Bitcoin|GitHub Repository}
 */

// Core wallet implementations
import { Custodial_Wallet, Non_Custodial_Wallet } from './src/wallet.js';

// BIP32 hierarchical deterministic key derivation
import fromSeed from './src/BIP32/fromSeed.js';
import derive from './src/BIP32/derive.js';

// BIP39 mnemonic phrase handling
import bip39 from './src/BIP39/bip39.js';

// Cryptographic signature algorithms
import ecdsa from './src/ECDSA/ecdsa.js';

// Threshold signature scheme components
import Polynomial from './src/Threshold-signature/Polynomial.js';
import ThresholdSignature from './src/Threshold-signature/threshold_signature.js';

// Encoding and utility functions
import b58encode from './src/utilities/base58.js';
import { hdKey, standardKey, address } from './src/utilities/encodeKeys.js';
import rmd160 from './src/utilities/rmd160.js';

// Alternative address format support
import CASH_ADDR from './src/altAddress/BCH/cash_addr.js';
import BECH32 from './src/altAddress/BTC/bech32.js';

// Advanced signature schemes
import schnorr_sig from './src/Schnorr-signature/Schnorr_Signature.js';

// Key decoding utilities
import { privateKey_decode, legacyAddress_decode } from './src/utilities/decodeKeys.js';

/**
 * Main wallet classes for Bitcoin cryptocurrency operations
 * @namespace Wallets
 */

/**
 * @memberof Wallets
 * @see {@link Custodial_Wallet}
 */
export { Custodial_Wallet };

/**
 * @memberof Wallets  
 * @see {@link Non_Custodial_Wallet}
 */
export { Non_Custodial_Wallet };

/**
 * BIP32 hierarchical deterministic key derivation utilities
 * @namespace BIP32
 */

/**
 * Generates master keys from a seed according to BIP32 specification
 * @memberof BIP32
 * @function
 * @param {string} seed - Hex-encoded seed (typically from BIP39)
 * @param {string} net - Network type ('main' or 'test')
 * @returns {Array} Array containing HD keys and serialization format
 * @returns {HDKeys} returns.0 - HD key pair object
 * @returns {Object} returns.1 - Serialization format object
 * @example
 * const [hdKeys, format] = fromSeed("000102030405060708090a0b0c0d0e0f", "main");
 */
export { fromSeed };

/**
 * Derives child keys from parent keys using BIP32 derivation paths
 * @memberof BIP32
 * @function
 * @param {string} path - BIP32 derivation path (e.g., "m/0'/1")
 * @param {string} key - Parent key in xprv/xpub format
 * @param {Object} format - Serialization format from parent
 * @returns {Array} Array containing derived keys and new format
 * @returns {HDKeys} returns.0 - Derived HD key pair  
 * @returns {Object} returns.1 - Updated serialization format
 * @example
 * const [childKeys, childFormat] = derive("m/0'/1", parentKey, parentFormat);
 */
export { derive };

/**
 * BIP39 mnemonic phrase and seed generation utilities
 * @namespace BIP39
 */

/**
 * @memberof BIP39
 * @see {@link module:bip39}
 */
export { bip39 };

/**
 * Cryptographic signature algorithms
 * @namespace Signatures
 */

/**
 * ECDSA signature operations for Bitcoin
 * @memberof Signatures
 * @see {@link module:ecdsa}
 */
export { ecdsa };

/**
 * Schnorr signature operations (BIP340)
 * @memberof Signatures
 * @see {@link module:schnorr_sig}
 */
export { schnorr_sig };

/**
 * Threshold signature scheme components for distributed cryptography
 * @namespace ThresholdCrypto
 */

/**
 * Polynomial arithmetic for secret sharing
 * @memberof ThresholdCrypto
 * @see {@link Polynomial}
 */
export { Polynomial };

/**
 * Threshold signature scheme implementation
 * @memberof ThresholdCrypto
 * @see {@link ThresholdSignature}
 */
export { ThresholdSignature };

/**
 * Encoding and utility functions
 * @namespace Utilities
 */

/**
 * Base58Check encoding for Bitcoin addresses and keys
 * @memberof Utilities
 * @function
 * @param {Buffer} data - Data to encode
 * @returns {string} Base58Check encoded string
 */
export { b58encode };

/**
 * Generates hierarchical deterministic keys in standard format
 * @memberof Utilities
 * @function
 * @param {string} keyType - 'pri' for private key, 'pub' for public key
 * @param {Object} format - Key serialization format
 * @returns {string} Formatted HD key (xprv/xpub)
 */
export { hdKey };

/**
 * Generates standard format private/public key pair
 * @memberof Utilities
 * @function
 * @param {Object} privKey - Private key information
 * @param {Object} pubKey - Public key information
 * @returns {Object} Standard key pair {pri, pub}
 */
export { standardKey };

/**
 * Generates Bitcoin address from public key
 * @memberof Utilities
 * @function
 * @param {number} versionByte - Address version byte
 * @param {Buffer} pubKey - Public key buffer
 * @returns {string} Bitcoin address
 */
export { address };

/**
 * RIPEMD160 hash function implementation
 * @memberof Utilities
 * @function
 * @param {Buffer} data - Data to hash
 * @returns {Buffer} RIPEMD160 hash result
 */
export { rmd160 };

/**
 * Alternative address format support
 * @namespace AddressFormats
 */

/**
 * Bitcoin Bech32 SegWit address utilities
 * @memberof AddressFormats
 * @namespace
 * @example
 * // Convert legacy address to P2WPKH
 * const segwitAddr = BECH32.to_P2WPKH("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
 * // Returns: "bc1qhkfq3zahaqkkzx5mjnamwjsfpw3tvke7v6aaph"
 */
export { BECH32 };

/**
 * Key decoding utilities for various formats
 * @namespace KeyDecoding
 */

/**
 * Decodes WIF (Wallet Import Format) private keys
 * @memberof KeyDecoding
 * @function
 * @param {string} priKey - WIF-encoded private key
 * @returns {Uint8Array} Raw private key bytes
 */
export { privateKey_decode };

/**
 * Decodes legacy Bitcoin addresses to extract hash160
 * @memberof KeyDecoding
 * @function
 * @param {string} address - Legacy Bitcoin address
 * @returns {Uint8Array} Hash160 bytes
 */
export { legacyAddress_decode };

/**
 * @typedef {Object} WalletKeyPair
 * @property {string} pri - WIF-encoded private key
 * @property {string} pub - Hex-encoded public key
 */

/**
 * @typedef {Object} HDKeyPair
 * @property {string} HDpri - xprv-formatted hierarchical deterministic private key
 * @property {string} HDpub - xpub-formatted hierarchical deterministic public key
 */

/**
 * @typedef {Object} AddressInfo
 * @property {string} address - Bitcoin address string
 * @property {string} format - Address format ('legacy', 'segwit')
 * @property {string} network - Network type ('main', 'test')
 */

/**
 * Library feature support matrix
 * @readonly
 * @enum {boolean}
 */
export const FEATURES = {
    /** Hierarchical Deterministic Wallets (BIP32) */
    HD_WALLETS: true,
    /** Threshold Signature Schemes */
    THRESHOLD_SIGNATURES: true,
    /** ECDSA Signatures */
    ECDSA: true,
    /** Schnorr Signatures (BIP340) */
    SCHNORR: true,
    /** P2PKH Legacy Addresses */
    P2PKH: true,
    /** P2WPKH SegWit Addresses */
    P2WPKH: true,
    /** P2SH Script Hash Addresses */
    P2SH: false,
    /** P2WSH SegWit Script Hash */
    P2WSH: false,
    /** Transaction Building */
    TRANSACTIONS: false,
    /** SPV (Simplified Payment Verification) */
    SPV: false
};

/**
 * Supported cryptocurrency networks
 * @readonly
 * @enum {Object}
 */
export const NETWORKS = {
    /** Bitcoin mainnet */
    BTC_MAIN: { name: 'Bitcoin', symbol: 'BTC', network: 'main' },
    /** Bitcoin testnet */
    BTC_TEST: { name: 'Bitcoin Testnet', symbol: 'BTC', network: 'test' },
};