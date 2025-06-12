/**
 * @fileoverview J-Bitcoin - Comprehensive Bitcoin Library
 * @version 2.0.0
 * @description Enterprise-grade Bitcoin library with HD wallets, threshold signatures,
 *              and full BIP compliance for secure cryptocurrency operations.
 * @author yfbsei
 * @license ISC
 */

// =============================================================================
// CORE WALLET IMPLEMENTATIONS
// =============================================================================

/**
 * Custodial wallet implementation for managed Bitcoin operations
 * @see {@link ./src/wallet/custodial.js}
 */
export { default as CustodialWallet } from './src/wallet/custodial.js';

/**
 * Non-custodial wallet with threshold signature support
 * @see {@link ./src/wallet/non-custodial.js}
 */
export { default as NonCustodialWallet } from './src/wallet/non-custodial.js';

// =============================================================================
// BIP STANDARD IMPLEMENTATIONS
// =============================================================================

/**
 * BIP32 Hierarchical Deterministic Key Derivation
 */
export {
  generateMasterKey as fromSeed,
  generateMasterKey
} from './src/bip/bip32/master-key.js';

export { derive } from './src/bip/bip32/derive.js';

/**
 * BIP39 Mnemonic Phrase Generation and Validation
 */
export { BIP39 } from './src/bip/bip39/mnemonic.js';

/**
 * BIP173/BIP350 Bech32 Address Encoding
 */
export { BECH32 } from './src/bip/BIP173-BIP350.js';

// =============================================================================
// CRYPTOGRAPHIC SIGNATURES
// =============================================================================

/**
 * ECDSA Signature Implementation
 */
export { default as ECDSA } from './src/core/crypto/signatures/ecdsa.js';

/**
 * Schnorr Signatures (BIP340) for Taproot
 */
export { default as SchnorrSignature } from './src/core/crypto/signatures/schnorr-BIP340.js';

/**
 * Threshold Signature Components
 */
export { default as Polynomial } from './src/core/crypto/signatures/threshold/polynomial.js';
export { default as ThresholdSignature } from './src/core/crypto/signatures/threshold/threshold-signature.js';

// =============================================================================
// ENCODING AND ADDRESS UTILITIES
// =============================================================================

/**
 * Base58 Encoding/Decoding for Bitcoin addresses and keys
 */
export * from './src/encoding/base58.js';

/**
 * Base32 Encoding/Decoding utilities
 */
export * from './src/encoding/base32.js';

/**
 * Address Encoding and Decoding Functions
 */
export * from './src/encoding/address/encode.js';
export * from './src/encoding/address/decode.js';

// =============================================================================
// VALIDATION AND UTILITIES
// =============================================================================

/**
 * Comprehensive validation utilities for Bitcoin operations
 */
export * from './src/utils/validation.js';

/**
 * Address helper functions and utilities
 */
export * from './src/utils/address-helpers.js';

/**
 * Core constants and configuration
 */
export * from './src/core/constants.js';

// =============================================================================
// TRANSACTION MANAGEMENT
// =============================================================================

/**
 * Transaction builder for creating Bitcoin transactions
 */
export * from './src/transaction/builder.js';

/**
 * UTXO management utilities
 */
export * from './src/transaction/utxo-manager.js';

// =============================================================================
// TAPROOT (BIP341) IMPLEMENTATION
// =============================================================================

/**
 * Taproot control block implementation
 */
export * from './src/core/taproot/control-block.js';

/**
 * Merkle tree utilities for Taproot
 */
export * from './src/core/taproot/merkle-tree.js';

/**
 * Tapscript interpreter for Taproot scripts
 */
export * from './src/core/taproot/tapscript-interpreter.js';

// =============================================================================
// LIBRARY CONFIGURATION
// =============================================================================

/**
 * Feature support matrix for the library
 * @readonly
 */
export const FEATURES = Object.freeze({
  /** Hierarchical Deterministic Wallets (BIP32) */
  HD_WALLETS: true,

  /** Threshold Signature Schemes */
  THRESHOLD_SIGNATURES: true,

  /** ECDSA Signatures */
  ECDSA: true,

  /** Schnorr Signatures (BIP340) */
  SCHNORR: true,

  /** Pay-to-Public-Key-Hash (Legacy) */
  P2PKH: true,

  /** Pay-to-Witness-Public-Key-Hash (SegWit) */
  P2WPKH: true,

  /** Pay-to-Script-Hash (Future implementation) */
  P2SH: false,

  /** Pay-to-Witness-Script-Hash (Future implementation) */
  P2WSH: false,

  /** Pay-to-Taproot (BIP341) */
  P2TR: true,

  /** Transaction Building and Broadcasting */
  TRANSACTIONS: true,

  /** Simplified Payment Verification (Future implementation) */
  SPV: false,

  /** Lightning Network (Future implementation) */
  LIGHTNING: false
});

/**
 * Supported Bitcoin networks configuration
 * @readonly
 */
export const NETWORKS = Object.freeze({
  /** Bitcoin Mainnet */
  BTC_MAIN: Object.freeze({
    name: 'Bitcoin',
    symbol: 'BTC',
    network: 'main',
    chainId: 0,
    bip44CoinType: 0
  }),

  /** Bitcoin Testnet */
  BTC_TEST: Object.freeze({
    name: 'Bitcoin Testnet',
    symbol: 'BTC',
    network: 'test',
    chainId: 1,
    bip44CoinType: 1
  })
});

/**
 * Library version and metadata
 * @readonly
 */
export const LIBRARY_INFO = Object.freeze({
  name: 'J-Bitcoin',
  version: '2.0.0',
  description: 'Comprehensive Bitcoin library with HD wallets and threshold signatures',
  author: 'yfbsei',
  license: 'ISC',
  repository: 'https://github.com/yfbsei/J-Bitcoin'
});

/**
 * BIP (Bitcoin Improvement Proposal) compliance matrix
 * @readonly
 */
export const BIP_COMPLIANCE = Object.freeze({
  /** Hierarchical Deterministic Wallets */
  BIP32: true,

  /** Mnemonic code for generating deterministic keys */
  BIP39: true,

  /** Multi-Account Hierarchy for Deterministic Wallets */
  BIP44: true,

  /** Derivation scheme for P2WPKH-nested-in-P2SH */
  BIP49: false,

  /** Derivation scheme for P2WPKH */
  BIP84: true,

  /** Key Derivation for Single Key P2TR Outputs */
  BIP86: true,

  /** Segregated Witness (Consensus layer) */
  BIP141: true,

  /** Transaction Signature Verification for Version 0 Witness Program */
  BIP143: true,

  /** Base32 address format for native v0-16 witness outputs */
  BIP173: true,

  /** Schnorr Signatures for secp256k1 */
  BIP340: true,

  /** Taproot: SegWit version 1 spending rules */
  BIP341: true,

  /** Validation of Taproot Scripts */
  BIP342: true,

  /** Base32 address format for native v1+ witness outputs */
  BIP350: true
});

// =============================================================================
// DEFAULT EXPORT
// =============================================================================

/**
 * Default export containing all major components
 */
export default {
  // Wallets
  CustodialWallet,
  NonCustodialWallet,

  // Cryptography
  ECDSA,
  SchnorrSignature,
  Polynomial,
  ThresholdSignature,

  // BIP implementations
  BIP39,
  BECH32,
  fromSeed,
  derive,

  // Configuration
  FEATURES,
  NETWORKS,
  LIBRARY_INFO,
  BIP_COMPLIANCE
};