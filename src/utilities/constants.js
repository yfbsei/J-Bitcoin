/**
 * @fileoverview Bitcoin-specific constants and configuration
 * 
 * This module provides centralized constants for Bitcoin operations including
 * BIP44 derivation paths, network configurations, and standard values used
 * throughout the J-Bitcoin library.
 * 
 * @author yfbsei
 * @version 2.0.0
 */

/**
 * BIP44 derivation path constants for Bitcoin
 * @namespace BIP44_CONSTANTS
 */
export const BIP44_CONSTANTS = {
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
    ACCOUNT: 0,
    
    /**
     * Change derivation constants
     * @namespace CHANGE
     */
    CHANGE: {
        /** External chain for receiving addresses */
        EXTERNAL: 0,
        /** Internal chain for change addresses */
        INTERNAL: 1
    }
};

/**
 * Standard Bitcoin derivation paths for common use cases
 * @namespace DERIVATION_PATHS
 */
export const DERIVATION_PATHS = {
    /** Root path for Bitcoin mainnet accounts */
    BITCOIN_LEGACY: "m/44'/0'/0'",
    /** Root path for Bitcoin testnet accounts */
    BITCOIN_TESTNET: "m/44'/1'/0'",
    /** Standard receiving address path (mainnet) */
    BITCOIN_RECEIVING: "m/44'/0'/0'/0",
    /** Standard change address path (mainnet) */
    BITCOIN_CHANGE: "m/44'/0'/0'/1",
    /** First receiving address (mainnet) */
    BITCOIN_FIRST_ADDRESS: "m/44'/0'/0'/0/0",
    /** First change address (mainnet) */
    BITCOIN_FIRST_CHANGE: "m/44'/0'/0'/1/0",
    /** Testnet receiving address path */
    TESTNET_RECEIVING: "m/44'/1'/0'/0",
    /** Testnet change address path */
    TESTNET_CHANGE: "m/44'/1'/0'/1"
};

/**
 * Bitcoin network configuration details
 * @namespace NETWORKS
 */
export const NETWORKS = {
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
        addressPrefix: 'bc',
        /** Legacy address prefix */
        legacyPrefix: '1',
        /** P2SH address prefix */
        p2shPrefix: '3',
        /** Network identifier */
        network: 'main'
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
        addressPrefix: 'tb',
        /** Legacy address prefix */
        legacyPrefix: 'm',
        /** Alternative legacy prefix */
        legacyPrefixAlt: 'n',
        /** P2SH address prefix */
        p2shPrefix: '2',
        /** Network identifier */
        network: 'test'
    }
};

/**
 * Address format identifiers
 * @namespace ADDRESS_FORMATS
 */
export const ADDRESS_FORMATS = {
    /** Legacy P2PKH format */
    LEGACY: 'legacy',
    /** SegWit Bech32 format */
    SEGWIT: 'segwit',
    /** P2SH format */
    P2SH: 'p2sh'
};

/**
 * Standard BIP purposes for different address types
 * @namespace BIP_PURPOSES
 */
export const BIP_PURPOSES = {
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
 * Generate a derivation path for Bitcoin
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
 *   purpose: 44,
 *   coinType: 0,
 *   account: 0,
 *   change: 0,
 *   addressIndex: 0
 * });
 * // Returns: "m/44'/0'/0'/0/0"
 * 
 * @example
 * // Generate Bitcoin change address path
 * const changePath = generateDerivationPath({
 *   change: 1,
 *   addressIndex: 5
 * });
 * // Returns: "m/44'/0'/0'/1/5"
 * 
 * @example
 * // Generate testnet address path
 * const testnetPath = generateDerivationPath({
 *   coinType: 1,
 *   addressIndex: 10
 * });
 * // Returns: "m/44'/1'/0'/0/10"
 */
export function generateDerivationPath({
    purpose = 44,
    coinType = 0,
    account = 0,
    change = 0,
    addressIndex = 0
} = {}) {
    return `m/${purpose}'/${coinType}'/${account}'/${change}/${addressIndex}`;
}

/**
 * Parse a derivation path into its components
 * @param {string} path - BIP44 derivation path to parse
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
 * const pathInfo = parseDerivationPath("m/44'/0'/0'/0/5");
 * console.log(pathInfo);
 * // {
 * //   purpose: 44,
 * //   coinType: 0,
 * //   account: 0,
 * //   change: 0,
 * //   addressIndex: 5
 * // }
 */
export function parseDerivationPath(path) {
    const pathRegex = /^m\/(\d+)'\/(\d+)'\/(\d+)'\/(\d+)\/(\d+)$/;
    const match = path.match(pathRegex);
    
    if (!match) {
        throw new Error(`Invalid derivation path format: ${path}`);
    }
    
    return {
        purpose: parseInt(match[1]),
        coinType: parseInt(match[2]),
        account: parseInt(match[3]),
        change: parseInt(match[4]),
        addressIndex: parseInt(match[5])
    };
}

/**
 * Validate if a derivation path is valid for Bitcoin
 * @param {string} path - Derivation path to validate
 * @returns {boolean} True if path is valid for Bitcoin
 * 
 * @example
 * console.log(isValidBitcoinPath("m/44'/0'/0'/0/0")); // true
 * console.log(isValidBitcoinPath("m/44'/145'/0'/0/0")); // false (BCH coin type)
 */
export function isValidBitcoinPath(path) {
    try {
        const parsed = parseDerivationPath(path);
        return parsed.coinType === 0 || parsed.coinType === 1; // Bitcoin mainnet or testnet
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
 * const mainnetConfig = getNetworkByCoinType(0);
 * console.log(mainnetConfig.name); // "Bitcoin"
 */
export function getNetworkByCoinType(coinType) {
    switch (coinType) {
        case 0:
            return NETWORKS.MAINNET;
        case 1:
            return NETWORKS.TESTNET;
        default:
            throw new Error(`Unsupported coin type: ${coinType}. Only Bitcoin (0) and Bitcoin Testnet (1) are supported.`);
    }
}