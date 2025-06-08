/**
 * @fileoverview Main entry point for J-Bitcoin cryptocurrency library
 *
 * Provides convenient re-exports for wallet classes, cryptographic primitives
 * and utility functions. Version 2.0.0+ focuses exclusively on Bitcoin.
 */

// Wallet implementations
export { default as Custodial_Wallet } from './src/wallet/custodial.js';
export { default as Non_Custodial_Wallet } from './src/wallet/non-custodial.js';

// BIP32 key derivation
export { generateMasterKey as fromSeed } from './src/bip/bip32/master-key.js';
export { derive } from './src/bip/bip32/derive.js';

// BIP39 mnemonic utilities
export { BIP39 } from './src/bip/bip39/mnemonic.js';

// Signature algorithms
export { default as ecdsa } from './src/core/crypto/signatures/ecdsa.js';
export { default as schnorr_sig } from './src/core/crypto/signatures/schnorr-BIP340.js';
export { default as Polynomial } from './src/core/crypto/signatures/threshold/polynomial.js';
export { default as ThresholdSignature } from './src/core/crypto/signatures/threshold/threshold-signature.js';

// Address utilities and encodings
export * from './src/encoding/base58.js';
export * from './src/encoding/base32.js';
export * from './src/encoding/address/encode.js';
export * from './src/encoding/address/decode.js';
export { BECH32 } from './src/bip/BIP173-BIP350.js';

// Validation helpers and constants
export * from './src/utils/validation.js';
export * from './src/utils/address-helpers.js';
export * from './src/core/constants.js';

// Transaction and Taproot modules
export * from './src/transaction/builder.js';
export * from './src/transaction/utxo-manager.js';
export * from './src/core/taproot/control-block.js';
export * from './src/core/taproot/merkle-tree.js';
export * from './src/core/taproot/tapscript-interpreter.js';

/** Feature support matrix */
export const FEATURES = {
  HD_WALLETS: true,
  THRESHOLD_SIGNATURES: true,
  ECDSA: true,
  SCHNORR: true,
  P2PKH: true,
  P2WPKH: true,
  P2SH: false,
  P2WSH: false,
  TRANSACTIONS: true,
  SPV: false,
};

/** Supported networks */
export const NETWORKS = {
  BTC_MAIN: { name: 'Bitcoin', symbol: 'BTC', network: 'main' },
  BTC_TEST: { name: 'Bitcoin Testnet', symbol: 'BTC', network: 'test' },
};
