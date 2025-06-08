/**
 * @fileoverview Enhanced Bitcoin constants and configuration
 * 
 * This module provides centralized constants for Bitcoin operations including
 * network configurations, cryptographic parameters, BIP specifications,
 * and standard values used throughout the J-Bitcoin library.
 * 
 * FIXES APPLIED (v2.1.1):
 * - Added missing HASH256_LENGTH constant
 * - Fixed BIP32 constants consistency
 * - Added missing validation constants
 * 
 * @author yfbsei
 * @version 2.1.1
 */

/**
 * Bitcoin network version bytes for different key and address formats
 * @constant {Object}
 */
const NETWORK_VERSIONS = {
    MAINNET: {
        EXTENDED_PRIVATE_KEY: 0x0488ade4,
        EXTENDED_PUBLIC_KEY: 0x0488b21e,
        WIF_PRIVATE_KEY: 0x80,
        P2PKH_ADDRESS: 0x00,
        P2SH_ADDRESS: 0x05
    },
    TESTNET: {
        EXTENDED_PRIVATE_KEY: 0x04358394,
        EXTENDED_PUBLIC_KEY: 0x043587cf,
        WIF_PRIVATE_KEY: 0xef,
        P2PKH_ADDRESS: 0x6f,
        P2SH_ADDRESS: 0xc4
    }
};

/**
 * BIP44 hierarchical deterministic wallet constants
 * @namespace BIP44_CONSTANTS
 */
const BIP44_CONSTANTS = {
    /**
     * BIP44 purpose field - indicates BIP44 compliance
     * @constant {number}
     */
    PURPOSE: 44,

    /**
     * Bitcoin coin type identifiers for BIP44 derivation
     * @namespace COIN_TYPES
     */
    COIN_TYPES: {
        /** Bitcoin mainnet coin type */
        BITCOIN_MAINNET: 0,
        /** Bitcoin testnet coin type */
        BITCOIN_TESTNET: 1
    },

    /**
     * Default account index for new wallets
     * @constant {number}
     */
    DEFAULT_ACCOUNT: 0,

    /**
     * Change derivation constants following BIP44 specification
     * @namespace CHANGE_TYPES
     */
    CHANGE_TYPES: {
        /** External chain for receiving addresses */
        EXTERNAL_CHAIN: 0,
        /** Internal chain for change addresses */
        INTERNAL_CHAIN: 1
    }
};

/**
 * Standard Bitcoin derivation paths for common use cases
 * @namespace DERIVATION_PATHS
 */
const DERIVATION_PATHS = {
    /** Root path for Bitcoin mainnet accounts */
    BITCOIN_LEGACY_ROOT: "m/44'/0'/0'",
    /** Root path for Bitcoin testnet accounts */
    BITCOIN_TESTNET_ROOT: "m/44'/1'/0'",
    /** Standard receiving address path (mainnet) */
    BITCOIN_RECEIVING: "m/44'/0'/0'/0",
    /** Standard change address path (mainnet) */
    BITCOIN_CHANGE: "m/44'/0'/0'/1",
    /** First receiving address (mainnet) */
    BITCOIN_FIRST_RECEIVING: "m/44'/0'/0'/0/0",
    /** First change address (mainnet) */
    BITCOIN_FIRST_CHANGE: "m/44'/0'/0'/1/0",
    /** Testnet receiving address path */
    TESTNET_RECEIVING: "m/44'/1'/0'/0",
    /** Testnet change address path */
    TESTNET_CHANGE: "m/44'/1'/0'/1"
};

/**
 * Comprehensive Bitcoin network configuration details
 * @namespace BITCOIN_NETWORKS
 */
const BITCOIN_NETWORKS = {
    /**
     * Bitcoin mainnet configuration
     * @namespace MAINNET
     */
    MAINNET: {
        /** Human-readable network name */
        name: 'Bitcoin',
        /** Currency symbol */
        symbol: 'BTC',
        /** BIP44 coin type */
        coinType: 0,
        /** Bech32 address prefix */
        bech32Prefix: 'bc',
        /** Legacy P2PKH address prefix */
        legacyPrefix: '1',
        /** P2SH address prefix */
        p2shPrefix: '3',
        /** Network identifier */
        network: 'main',
        /** Version bytes for this network */
        versions: NETWORK_VERSIONS.MAINNET
    },

    /**
     * Bitcoin testnet configuration
     * @namespace TESTNET
     */
    TESTNET: {
        /** Human-readable network name */
        name: 'Bitcoin Testnet',
        /** Currency symbol */
        symbol: 'BTC',
        /** BIP44 coin type */
        coinType: 1,
        /** Bech32 address prefix */
        bech32Prefix: 'tb',
        /** Primary legacy address prefix */
        legacyPrefix: 'm',
        /** Alternative legacy prefix */
        legacyPrefixAlt: 'n',
        /** P2SH address prefix */
        p2shPrefix: '2',
        /** Network identifier */
        network: 'test',
        /** Version bytes for this network */
        versions: NETWORK_VERSIONS.TESTNET
    }
};

/**
 * Cryptographic constants for secp256k1 and Bitcoin operations
 * @namespace CRYPTO_CONSTANTS
 */
const CRYPTO_CONSTANTS = {
    /** secp256k1 curve order as hex string */
    SECP256K1_ORDER: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    /** Private key length in bytes */
    PRIVATE_KEY_LENGTH: 32,
    /** Compressed public key length in bytes */
    PUBLIC_KEY_COMPRESSED_LENGTH: 33,
    /** Uncompressed public key length in bytes */
    PUBLIC_KEY_UNCOMPRESSED_LENGTH: 65,
    /** Chain code length for BIP32 derivation */
    CHAIN_CODE_LENGTH: 32,
    /** Checksum length for Base58Check encoding */
    CHECKSUM_LENGTH: 4,
    /** Offset for hardened derivation in BIP32 */
    HARDENED_OFFSET: 0x80000000,
    /** Hash160 length (RIPEMD160 output) */
    HASH160_LENGTH: 20,
    /** SHA256 hash length */
    SHA256_LENGTH: 32,
    /** FIXED: Added missing HASH256_LENGTH constant */
    HASH256_LENGTH: 32
};

/**
 * BIP32 hierarchical deterministic wallet constants
 * @namespace BIP32_CONSTANTS
 */
const BIP32_CONSTANTS = {
    /** Master key depth in derivation tree */
    MASTER_KEY_DEPTH: 0,
    /** Parent fingerprint for master keys (all zeros) */
    ZERO_PARENT_FINGERPRINT: Buffer.alloc(4, 0),
    /** Child index for master keys */
    MASTER_CHILD_INDEX: 0,
    /** HMAC key for master key generation */
    MASTER_KEY_HMAC_KEY: "Bitcoin seed",
    /** Maximum derivation depth recommended */
    MAX_DERIVATION_DEPTH: 255,
    /** Extended key total length */
    EXTENDED_KEY_LENGTH: 78,
    /** FIXED: Added missing seed validation constants */
    MIN_SEED_BYTES: 16,
    MAX_SEED_BYTES: 64
};

/**
 * BIP39 mnemonic phrase constants
 * @namespace BIP39_CONSTANTS
 */
const BIP39_CONSTANTS = {
    /** Entropy bits for 12-word mnemonic */
    ENTROPY_BITS: 128,
    /** Checksum bits for validation */
    CHECKSUM_BITS: 4,
    /** Number of words in mnemonic */
    WORD_COUNT: 12,
    /** Bits per word in mnemonic encoding */
    BITS_PER_WORD: 11,
    /** PBKDF2 iteration count */
    PBKDF2_ITERATIONS: 2048,
    /** Derived seed length in bytes */
    SEED_LENGTH_BYTES: 64,
    /** Salt prefix for PBKDF2 */
    MNEMONIC_SALT_PREFIX: 'mnemonic'
};

/**
 * Address format identifiers
 * @namespace ADDRESS_FORMATS
 */
const ADDRESS_FORMATS = {
    /** Legacy P2PKH format */
    LEGACY: 'legacy',
    /** SegWit Bech32 format */
    SEGWIT: 'segwit',
    /** P2SH format */
    P2SH: 'p2sh',
    /** Taproot format */
    TAPROOT: 'taproot'
};

/**
 * Standard BIP purposes for different address types
 * @namespace BIP_PURPOSES
 */
const BIP_PURPOSES = {
    /** BIP44 - Legacy P2PKH addresses */
    LEGACY: 44,
    /** BIP49 - P2WPKH-nested-in-P2SH addresses */
    NESTED_SEGWIT: 49,
    /** BIP84 - Native SegWit P2WPKH addresses */
    NATIVE_SEGWIT: 84,
    /** BIP86 - Taproot P2TR addresses */
    TAPROOT: 86
};

/**
 * Base58 and Base32 encoding constants
 * @namespace ENCODING_CONSTANTS
 */
const ENCODING_CONSTANTS = {
    /** Base58 alphabet used by Bitcoin (excludes 0, O, I, l) */
    BASE58_ALPHABET: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    /** Base32 alphabet for Bech32 encoding */
    BASE32_ALPHABET: 'qpzry9x8gf2tvdw0s3jn54khce6mua7l',
    /** Bech32 encoding constants */
    BECH32_CONST: 1,
    BECH32M_CONST: 0x2bc830a3,
    /** Maximum Bech32 address length */
    BECH32_MAX_LENGTH: 90
};

/**
 * Threshold signature scheme constants
 * @namespace THRESHOLD_CONSTANTS
 */
const THRESHOLD_CONSTANTS = {
    /** Minimum participants for meaningful threshold scheme */
    MIN_PARTICIPANTS: 2,
    /** Minimum threshold for security */
    MIN_THRESHOLD: 2,
    /** Recommended maximum participants for practical use */
    MAX_RECOMMENDED_PARTICIPANTS: 15,
    /** Default polynomial order offset */
    POLYNOMIAL_ORDER_OFFSET: 1
};

/**
 * Generate a BIP44 derivation path for Bitcoin
 * @param {Object} options - Path generation options
 * @param {number} [options.purpose=44] - BIP purpose (44, 49, 84, 86)
 * @param {number} [options.coinType=0] - Coin type (0 for mainnet, 1 for testnet)
 * @param {number} [options.account=0] - Account index
 * @param {number} [options.change=0] - Change chain (0 for external, 1 for internal)
 * @param {number} [options.addressIndex=0] - Address index
 * @returns {string} Complete BIP44 derivation path
 * 
 * @example
 * // Generate standard Bitcoin receiving address path
 * const receivingPath = generateDerivationPath({
 *   purpose: BIP_PURPOSES.LEGACY,
 *   coinType: BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET,
 *   account: BIP44_CONSTANTS.DEFAULT_ACCOUNT,
 *   change: BIP44_CONSTANTS.CHANGE_TYPES.EXTERNAL_CHAIN,
 *   addressIndex: 0
 * });
 * // Returns: "m/44'/0'/0'/0/0"
 */
function generateDerivationPath({
    purpose = BIP_PURPOSES.LEGACY,
    coinType = BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET,
    account = BIP44_CONSTANTS.DEFAULT_ACCOUNT,
    change = BIP44_CONSTANTS.CHANGE_TYPES.EXTERNAL_CHAIN,
    addressIndex = 0
} = {}) {
    return `m/${purpose}'/${coinType}'/${account}'/${change}/${addressIndex}`;
}

/**
 * Parse a derivation path into its components
 * @param {string} derivationPath - BIP44 derivation path to parse
 * @returns {Object} Parsed path components
 * @returns {number} returns.purpose - Purpose field
 * @returns {number} returns.coinType - Coin type field
 * @returns {number} returns.account - Account field
 * @returns {number} returns.change - Change field
 * @returns {number} returns.addressIndex - Address index field
 * 
 * @throws {Error} If path format is invalid
 * 
 * @example
 * const pathComponents = parseDerivationPath("m/44'/0'/0'/0/5");
 * console.log(pathComponents);
 * // {
 * //   purpose: 44,
 * //   coinType: 0,
 * //   account: 0,
 * //   change: 0,
 * //   addressIndex: 5
 * // }
 */
function parseDerivationPath(derivationPath) {
    const BIP44_PATH_REGEX = /^m\/(\d+)'\/(\d+)'\/(\d+)'\/(\d+)\/(\d+)$/;
    const match = derivationPath.match(BIP44_PATH_REGEX);

    if (!match) {
        throw new Error(`Invalid BIP44 derivation path format: ${derivationPath}`);
    }

    return {
        purpose: parseInt(match[1], 10),
        coinType: parseInt(match[2], 10),
        account: parseInt(match[3], 10),
        change: parseInt(match[4], 10),
        addressIndex: parseInt(match[5], 10)
    };
}

/**
 * Validate if a derivation path is valid for Bitcoin
 * @param {string} derivationPath - Derivation path to validate
 * @returns {boolean} True if path is valid for Bitcoin
 * 
 * @example
 * console.log(isValidBitcoinPath("m/44'/0'/0'/0/0")); // true
 * console.log(isValidBitcoinPath("m/44'/145'/0'/0/0")); // false (BCH coin type)
 */
function isValidBitcoinPath(derivationPath) {
    try {
        const pathComponents = parseDerivationPath(derivationPath);
        const validCoinTypes = [
            BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET,
            BIP44_CONSTANTS.COIN_TYPES.BITCOIN_TESTNET
        ];
        return validCoinTypes.includes(pathComponents.coinType);
    } catch {
        return false;
    }
}

/**
 * Get network configuration by coin type
 * @param {number} coinType - BIP44 coin type (0 or 1)
 * @returns {Object} Network configuration
 * @throws {Error} If coin type is not supported
 * 
 * @example
 * const mainnetConfig = getNetworkConfiguration(0);
 * console.log(mainnetConfig.name); // "Bitcoin"
 */
function getNetworkConfiguration(coinType) {
    switch (coinType) {
        case BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET:
            return BITCOIN_NETWORKS.MAINNET;
        case BIP44_CONSTANTS.COIN_TYPES.BITCOIN_TESTNET:
            return BITCOIN_NETWORKS.TESTNET;
        default:
            throw new Error(
                `Unsupported coin type: ${coinType}. ` +
                `Only Bitcoin mainnet (${BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET}) ` +
                `and testnet (${BIP44_CONSTANTS.COIN_TYPES.BITCOIN_TESTNET}) are supported.`
            );
    }
}

/**
 * Validate network parameter
 * @param {string} network - Network identifier ('main' or 'test')
 * @returns {Object} Network configuration
 * @throws {Error} If network is not supported
 * 
 * @example
 * const config = validateAndGetNetwork('main');
 * console.log(config.name); // "Bitcoin"
 */
function validateAndGetNetwork(network) {
    switch (network) {
        case 'main':
            return BITCOIN_NETWORKS.MAINNET;
        case 'test':
            return BITCOIN_NETWORKS.TESTNET;
        default:
            throw new Error(
                `Invalid network: ${network}. Must be 'main' or 'test'.`
            );
    }
}

export {
    NETWORK_VERSIONS,
    BIP44_CONSTANTS,
    DERIVATION_PATHS,
    BITCOIN_NETWORKS,
    CRYPTO_CONSTANTS,
    BIP32_CONSTANTS,
    BIP39_CONSTANTS,
    ADDRESS_FORMATS,
    BIP_PURPOSES,
    ENCODING_CONSTANTS,
    THRESHOLD_CONSTANTS,
    generateDerivationPath,
    parseDerivationPath,
    isValidBitcoinPath,
    getNetworkConfiguration,
    validateAndGetNetwork
};