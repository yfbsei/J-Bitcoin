/**
 * @fileoverview J-Bitcoin - Comprehensive Bitcoin Library
 * @version 2.0.0
 * @description Enterprise-grade Bitcoin library with HD wallets, threshold signatures,
 *              and full BIP compliance for secure cryptocurrency operations.
 * @author yfbsei
 * @license ISC
 */

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// WALLETS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export { default as CustodialWallet, CustodialWalletError } from './src/wallet/custodial.js';
export {
  default as NonCustodialWallet,
  NonCustodialWalletError,
  ParticipantShare
} from './src/wallet/non-custodial.js';

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// BIP STANDARDS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// BIP32 - Hierarchical Deterministic Key Derivation
export { generateMasterKey, generateMasterKey as fromSeed } from './src/bip/bip32/master-key.js';
export { derive } from './src/bip/bip32/derive.js';

// BIP39 - Mnemonic Phrase Generation
export { BIP39 } from './src/bip/bip39/mnemonic.js';

// BIP173/BIP350 - Bech32 Address Encoding
export { BECH32 } from './src/bip/BIP173-BIP350.js';

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CRYPTOGRAPHY
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ECDSA Signatures
export { ECDSA } from './src/core/crypto/signatures/ecdsa.js';

// Schnorr Signatures (BIP340)
export { Schnorr, Schnorr as SchnorrSignature } from './src/core/crypto/signatures/schnorr-BIP340.js';

// Threshold Signatures (nChain TSS Protocol)
export {
  Polynomial,
  JVRSS,
  ThresholdSignatureScheme,
  createThresholdScheme,
  ADDSS,
  PROSS,
  INVSS
} from './src/core/crypto/signatures/threshold/index.js';

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ENCODING
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export * from './src/encoding/base58.js';
export * from './src/encoding/base32.js';
export * from './src/encoding/address/encode.js';
export * from './src/encoding/address/decode.js';

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// UTILITIES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export * from './src/utils/validation.js';
export * from './src/utils/address-helpers.js';
export * from './src/core/constants.js';

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// TRANSACTIONS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export * from './src/transaction/builder.js';
export * from './src/transaction/utxo-manager.js';
export * from './src/transaction/psbt.js';

// Sighash Calculation (BIP143, BIP341)
export {
  SighashCalculator,
  BIP143,
  BIP341,
  LegacySighash,
  SIGHASH
} from './src/transaction/sighash.js';

// Script Building
export {
  ScriptBuilder,
  OPCODES,
  OPCODE_NAMES,
  ScriptError
} from './src/transaction/script-builder.js';

// Witness Building
export {
  WitnessBuilder,
  WitnessError
} from './src/transaction/witness-builder.js';

// Transaction Parsing
export {
  TransactionParser,
  TransactionParseError
} from './src/transaction/parser.js';

// BIP322 Message Signing
export {
  BIP322,
  BIP322Error,
  BIP322_CONSTANTS
} from './src/transaction/message-signing.js';

// BIP49 - Wrapped SegWit
export { BIP49, BIP49_CONSTANTS } from './src/bip/bip49.js';

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// TAPROOT (BIP341)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export * from './src/core/taproot/control-block.js';
export * from './src/core/taproot/merkle-tree.js';
export * from './src/core/taproot/tapscript-interpreter.js';

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CONFIGURATION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/** Library feature support matrix */
export const FEATURES = Object.freeze({
  HD_WALLETS: true,
  THRESHOLD_SIGNATURES: true,
  ECDSA: true,
  SCHNORR: true,
  P2PKH: true,
  P2WPKH: true,
  P2SH: false,
  P2WSH: false,
  P2TR: true,
  TRANSACTIONS: true,
  SPV: false,
  LIGHTNING: false
});

/** Supported Bitcoin networks */
export const NETWORKS = Object.freeze({
  BTC_MAIN: Object.freeze({
    name: 'Bitcoin',
    symbol: 'BTC',
    network: 'main',
    chainId: 0,
    bip44CoinType: 0
  }),
  BTC_TEST: Object.freeze({
    name: 'Bitcoin Testnet',
    symbol: 'BTC',
    network: 'test',
    chainId: 1,
    bip44CoinType: 1
  })
});

/** Library metadata */
export const LIBRARY_INFO = Object.freeze({
  name: 'J-Bitcoin',
  version: '2.0.0',
  description: 'Comprehensive Bitcoin library with HD wallets and threshold signatures',
  author: 'yfbsei',
  license: 'ISC',
  repository: 'https://github.com/yfbsei/J-Bitcoin'
});

/** BIP compliance matrix */
export const BIP_COMPLIANCE = Object.freeze({
  BIP32: true,
  BIP39: true,
  BIP44: true,
  BIP49: true,
  BIP84: true,
  BIP86: true,
  BIP141: true,
  BIP143: true,
  BIP173: true,
  BIP340: true,
  BIP341: true,
  BIP342: true,
  BIP350: true
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DEFAULT EXPORT
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import CustodialWallet from './src/wallet/custodial.js';
import NonCustodialWallet from './src/wallet/non-custodial.js';
import { ECDSA } from './src/core/crypto/signatures/ecdsa.js';
import { Schnorr } from './src/core/crypto/signatures/schnorr-BIP340.js';
import {
  Polynomial,
  ThresholdSignatureScheme,
  JVRSS
} from './src/core/crypto/signatures/threshold/index.js';
import { BIP39 } from './src/bip/bip39/mnemonic.js';
import { BECH32 } from './src/bip/BIP173-BIP350.js';
import { generateMasterKey } from './src/bip/bip32/master-key.js';
import { derive } from './src/bip/bip32/derive.js';
import { TransactionBuilder } from './src/transaction/builder.js';
import { SighashCalculator, BIP143, BIP341 } from './src/transaction/sighash.js';
import { ScriptBuilder, OPCODES } from './src/transaction/script-builder.js';
import { WitnessBuilder } from './src/transaction/witness-builder.js';
import { PSBT } from './src/transaction/psbt.js';
import { UTXOManager } from './src/transaction/utxo-manager.js';

export default {
  // Wallets
  CustodialWallet,
  NonCustodialWallet,

  // Cryptography
  ECDSA,
  Schnorr,
  SchnorrSignature: Schnorr,
  Polynomial,
  ThresholdSignatureScheme,
  JVRSS,

  // BIP Implementations
  BIP39,
  BECH32,
  fromSeed: generateMasterKey,
  derive,

  // Transactions
  TransactionBuilder,
  SighashCalculator,
  BIP143,
  BIP341,
  ScriptBuilder,
  OPCODES,
  WitnessBuilder,
  PSBT,
  UTXOManager,

  // Configuration
  FEATURES,
  NETWORKS,
  LIBRARY_INFO,
  BIP_COMPLIANCE
};