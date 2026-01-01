/**
 * @fileoverview Non-Custodial Wallet with Threshold Signature Scheme
 * @description Implements a non-custodial wallet using the nChain TSS protocol
 *              for distributed key management and threshold signing.
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */


import { secp256k1 } from '@noble/curves/secp256k1';
import BN from 'bn.js';
import {
  ThresholdSignatureScheme,
  createThresholdScheme,
  Polynomial,
  CURVE_ORDER
} from '../core/crypto/signatures/threshold/index.js';

// HD Derivation imports
import { BIP39 } from '../bip/bip39/mnemonic.js';
import { generateMasterKey } from '../bip/bip32/master-key.js';
import { derive } from '../bip/bip32/derive.js';
import { BECH32 } from '../bip/BIP173-BIP350.js';
import { encodeP2PKH, encodeP2SH, encodeWIF, hash160 } from '../encoding/address/encode.js';
import { decodeWIFPrivateKey } from '../encoding/address/decode.js';
import { ScriptBuilder } from '../transaction/script-builder.js';
import { TransactionBuilder } from '../transaction/builder.js';
import { BIP322 } from '../transaction/message-signing.js';
import { ECDSA } from '../core/crypto/signatures/ecdsa.js';
import { THRESHOLD_CONSTANTS } from '../core/constants.js';

/**
 * Address type mapping to BIP purpose
 * @constant {Object}
 */
const ADDRESS_TYPE_PURPOSE = {
  legacy: 44,           // BIP44 - P2PKH
  'wrapped-segwit': 49, // BIP49 - P2SH-P2WPKH
  segwit: 84,           // BIP84 - P2WPKH
  taproot: 86           // BIP86 - P2TR
};

class NonCustodialWalletError extends Error {
  constructor(message, solution = 'Check threshold configuration') {
    super(message);
    this.name = 'NonCustodialWalletError';
    this.solution = solution;
    this.timestamp = new Date().toISOString();
  }
}

/**
 * Represents a participant's key share for export/import
 */
class ParticipantShare {
  constructor(index, keyShare, publicKeyShare = null) {
    this.index = index;
    this.keyShare = keyShare instanceof BN ? keyShare : new BN(keyShare, 'hex');
    this.publicKeyShare = publicKeyShare;
  }

  toJSON() {
    return {
      index: this.index,
      keyShare: this.keyShare.toString('hex'),
      publicKeyShare: this.publicKeyShare ? this.publicKeyShare.toString('hex') : null
    };
  }

  static fromJSON(json) {
    return new ParticipantShare(
      json.index,
      json.keyShare,
      json.publicKeyShare ? Buffer.from(json.publicKeyShare, 'hex') : null
    );
  }
}

/**
 * Non-Custodial Wallet using nChain Threshold Signature Scheme
 * 
 * This wallet distributes key management across multiple participants,
 * requiring a threshold number to sign transactions.
 * 
 * Parameters:
 * - n: Total number of participants
 * - t: Threshold polynomial degree (t+1 to reconstruct, 2t+1 to sign)
 * 
 * Common configurations:
 * - 2-of-3: n=3, t=1 (3 participants, 3 needed to sign)
 * - 3-of-5: n=5, t=2 (5 participants, 5 needed to sign)
 * 
 * Note: Due to the INVSS protocol, signing requires 2t+1 participants.
 */
class NonCustodialWallet {
  /**
   * Create a new non-custodial wallet
   * @param {string} network - 'main' or 'test'
   * @param {number} n - Total number of participants
   * @param {number} t - Threshold polynomial degree
   */
  constructor(network, n, t) {
    // Validate parameters
    if (n < 2) {
      throw new NonCustodialWalletError(
        'Need at least 2 participants',
        'Increase participant count'
      );
    }

    if (t < 1) {
      throw new NonCustodialWalletError(
        'Threshold degree must be at least 1',
        'Increase threshold'
      );
    }

    // Signing requires 2t+1 participants
    if (2 * t + 1 > n) {
      throw new NonCustodialWalletError(
        `Signing requires ${2 * t + 1} participants (2t+1), but only ${n} available`,
        'Increase participants or decrease threshold'
      );
    }

    if (n > THRESHOLD_CONSTANTS.MAX_PARTICIPANTS) {
      throw new NonCustodialWalletError(
        `Participants cannot exceed ${THRESHOLD_CONSTANTS.MAX_PARTICIPANTS}`,
        'Reduce participant count'
      );
    }

    this.network = network === 'main' ? 'main' : 'test';
    this.n = n;
    this.t = t;
    this.signingThreshold = 2 * t + 1;
    this.reconstructionThreshold = t + 1;

    // TSS scheme instance
    this.scheme = null;

    // Exported shares for backup/distribution
    this.exportedShares = [];

    // Aggregate public key
    this.aggregatePublicKey = null;

    // HD Wallet properties
    /** @type {Object|null} BIP32 master keys (extendedPrivateKey, extendedPublicKey) */
    this.masterKeys = null;
    /** @type {string|null} BIP39 mnemonic phrase */
    this.mnemonic = null;
    /** @type {Map<string, Object>} Cache of derived addresses */
    this.derivedAddresses = new Map();

    this.version = '2.0.0';
    this.created = Date.now();
  }

  /**
   * Create a new wallet with fresh key generation
   * @param {string} network - Network type
   * @param {number} n - Total participants (default 3)
   * @param {number} t - Threshold degree (default 1, meaning 3-of-3 for signing)
   * @param {number} ephemeralKeyCount - Pre-generated ephemeral keys
   * @returns {{wallet: NonCustodialWallet, shares: Array}} Wallet and shares
   */
  static createNew(network = 'main', n = 3, t = 1, ephemeralKeyCount = 10) {
    const wallet = new NonCustodialWallet(network, n, t);
    wallet.initialize(ephemeralKeyCount);
    return {
      wallet,
      shares: wallet.getShares(),
      config: wallet.getThresholdConfig()
    };
  }

  /**
   * Create a new HD wallet with fresh mnemonic and TSS key generation
   * @param {string} network - Network type ('main' or 'test')
   * @param {number} n - Total participants (default 3)
   * @param {number} t - Threshold degree (default 1)
   * @param {number} strength - Mnemonic strength (128, 160, 192, 224, 256)
   * @param {number} ephemeralKeyCount - Pre-generated ephemeral keys
   * @returns {{wallet: NonCustodialWallet, mnemonic: string, shares: Array, config: Object}}
   */
  static createNewHD(network = 'main', n = 3, t = 1, strength = 256, ephemeralKeyCount = 10) {
    try {
      const mnemonicResult = BIP39.generateMnemonic(strength);
      const mnemonic = mnemonicResult.mnemonic;
      const seed = BIP39.deriveSeed(mnemonic);
      const [masterKeys] = generateMasterKey(seed, network);

      const wallet = new NonCustodialWallet(network, n, t);
      wallet.masterKeys = masterKeys;
      wallet.mnemonic = mnemonic;
      wallet.initialize(ephemeralKeyCount);

      return {
        wallet,
        mnemonic,
        shares: wallet.getShares(),
        config: wallet.getThresholdConfig()
      };
    } catch (error) {
      throw new NonCustodialWalletError(
        `Failed to create HD wallet: ${error.message}`,
        'Ensure crypto module is available'
      );
    }
  }

  /**
   * Restore an HD wallet from a BIP39 mnemonic phrase
   * @param {string} network - Network type ('main' or 'test')
   * @param {string} mnemonic - BIP39 mnemonic phrase (12-24 words)
   * @param {number} n - Total participants
   * @param {number} t - Threshold degree
   * @param {string} passphrase - Optional BIP39 passphrase
   * @param {number} ephemeralKeyCount - Pre-generated ephemeral keys
   * @returns {NonCustodialWallet} Restored wallet
   */
  static fromMnemonic(network, mnemonic, n = 3, t = 1, passphrase = '', ephemeralKeyCount = 10) {
    try {
      if (!BIP39.validateChecksum(mnemonic)) {
        throw new Error('Invalid mnemonic checksum');
      }

      const seed = BIP39.deriveSeed(mnemonic, passphrase);
      const [masterKeys] = generateMasterKey(seed, network);

      const wallet = new NonCustodialWallet(network, n, t);
      wallet.masterKeys = masterKeys;
      wallet.mnemonic = mnemonic;
      wallet.initialize(ephemeralKeyCount);

      return wallet;
    } catch (error) {
      throw new NonCustodialWalletError(
        `Failed to restore wallet from mnemonic: ${error.message}`,
        'Verify mnemonic phrase is correct'
      );
    }
  }

  /**
   * Create an HD wallet from a raw seed
   * @param {string} network - Network type ('main' or 'test')
   * @param {string|Buffer} seed - 64-byte seed as hex string or Buffer
   * @param {number} n - Total participants
   * @param {number} t - Threshold degree
   * @param {number} ephemeralKeyCount - Pre-generated ephemeral keys
   * @returns {NonCustodialWallet} Wallet instance
   */
  static fromSeed(network, seed, n = 3, t = 1, ephemeralKeyCount = 10) {
    try {
      const [masterKeys] = generateMasterKey(seed, network);

      const wallet = new NonCustodialWallet(network, n, t);
      wallet.masterKeys = masterKeys;
      wallet.initialize(ephemeralKeyCount);

      return wallet;
    } catch (error) {
      throw new NonCustodialWalletError(
        `Failed to create wallet from seed: ${error.message}`,
        'Verify seed is valid hex string'
      );
    }
  }

  /**
   * Create a wallet from an extended key (xprv/xpub/tprv/tpub)
   * Note: TSS is still used for signing; HD is for address derivation only
   * @param {string} network - Network type ('main' or 'test')
   * @param {string} extendedKey - BIP32 extended key
   * @param {number} n - Total participants
   * @param {number} t - Threshold degree
   * @param {number} ephemeralKeyCount - Pre-generated ephemeral keys
   * @returns {NonCustodialWallet} Wallet instance
   */
  static fromExtendedKey(network, extendedKey, n = 3, t = 1, ephemeralKeyCount = 10) {
    try {
      const masterKeys = {
        extendedPrivateKey: extendedKey.startsWith('xprv') || extendedKey.startsWith('tprv')
          ? extendedKey
          : null,
        extendedPublicKey: extendedKey.startsWith('xpub') || extendedKey.startsWith('tpub')
          ? extendedKey
          : null
      };

      if (!masterKeys.extendedPrivateKey && !masterKeys.extendedPublicKey) {
        throw new Error('Invalid extended key format');
      }

      const wallet = new NonCustodialWallet(network, n, t);
      wallet.masterKeys = masterKeys;
      wallet.initialize(ephemeralKeyCount);

      return wallet;
    } catch (error) {
      throw new NonCustodialWalletError(
        `Failed to create wallet from extended key: ${error.message}`,
        'Verify extended key format'
      );
    }
  }

  /**
   * Create a wallet from a WIF private key (single-key mode for HD addresses)
   * Note: TSS is still used for aggregate key; WIF enables single-key HD derivation
   * @param {string} wif - WIF-encoded private key
   * @param {number} n - Total participants for TSS
   * @param {number} t - Threshold degree
   * @param {number} ephemeralKeyCount - Pre-generated ephemeral keys
   * @returns {NonCustodialWallet} Wallet instance
   */
  static fromWIF(wif, n = 3, t = 1, ephemeralKeyCount = 10) {
    try {
      const decoded = decodeWIFPrivateKey(wif);
      const wallet = new NonCustodialWallet(decoded.network, n, t);

      // Store single key info for single-key mode
      wallet.masterKeys = {
        extendedPrivateKey: null,
        extendedPublicKey: null,
        singlePrivateKey: decoded.privateKey,
        compressed: decoded.compressed
      };
      wallet._singleKeyMode = true;
      wallet.initialize(ephemeralKeyCount);

      return wallet;
    } catch (error) {
      throw new NonCustodialWalletError(
        `Failed to import WIF: ${error.message}`,
        'Verify WIF format is correct'
      );
    }
  }

  /**
   * Initialize the wallet with TSS key generation
   * @param {number} ephemeralKeyCount - Number of ephemeral keys to pre-generate
   */
  initialize(ephemeralKeyCount = 10) {
    // Create and initialize the threshold scheme
    this.scheme = createThresholdScheme(this.n, this.t, ephemeralKeyCount);
    this.aggregatePublicKey = this.scheme.getPublicKey();

    // Export shares for distribution
    this._exportShares();
  }

  /**
   * Export shares from the internal scheme for backup
   */
  _exportShares() {
    if (!this.scheme) return;

    this.exportedShares = this.scheme.privateKeyShares.map(share =>
      new ParticipantShare(
        share.index,
        share.keyShare,
        share.publicKeyShare
      )
    );
  }

  /**
   * Restore wallet from exported shares (limited functionality)
   * Note: Full signing requires the complete JVRSS state
   * @param {string} network - Network type
   * @param {Array} shares - Exported shares
   * @param {number} t - Threshold degree
   * @returns {NonCustodialWallet} Restored wallet
   */
  static fromShares(network, shares, t) {
    const n = shares.length;
    const wallet = new NonCustodialWallet(network, n, t);

    wallet.exportedShares = shares.map(s =>
      s instanceof ParticipantShare ? s : ParticipantShare.fromJSON(s)
    );

    // Reconstruct public key from shares
    wallet._reconstructPublicKey();

    return wallet;
  }

  /**
   * Reconstruct the aggregate public key from shares
   */
  _reconstructPublicKey() {
    if (this.exportedShares.length < this.reconstructionThreshold) {
      throw new NonCustodialWalletError(
        `Need at least ${this.reconstructionThreshold} shares to reconstruct`,
        'Provide more shares'
      );
    }

    const selectedShares = this.exportedShares.slice(0, this.reconstructionThreshold);
    const secret = Polynomial.reconstructSecret(
      selectedShares.map(s => ({ x: new BN(s.index), y: s.keyShare }))
    );

    const secretBuffer = secret.toArrayLike(Buffer, 'be', 32);
    this.aggregatePublicKey = Buffer.from(
      secp256k1.getPublicKey(secretBuffer, true)
    );
  }

  /**
   * Get wallet address
   * @param {string} type - 'segwit' or 'taproot'
   * @returns {string} Bitcoin address
   */
  getAddress(type = 'segwit') {
    if (!this.aggregatePublicKey) {
      throw new NonCustodialWalletError('Wallet not initialized');
    }

    const publicKeyHex = this.aggregatePublicKey.toString('hex');

    switch (type) {
      case 'taproot':
        const xOnlyPubKey = this.aggregatePublicKey.slice(1);
        return BECH32.to_P2TR(xOnlyPubKey, this.network);
      case 'segwit':
      default:
        return BECH32.to_P2WPKH(publicKeyHex, this.network);
    }
  }

  /**
   * Derive an HD address at the specified BIP path
   * Requires HD wallet initialization via createNewHD(), fromMnemonic(), or fromSeed()
   * @param {number} account - Account index (hardened)
   * @param {number} change - Change index (0=external/receiving, 1=internal/change)
   * @param {number} index - Address index
   * @param {string} type - Address type ('legacy', 'wrapped-segwit', 'segwit', 'taproot')
   * @returns {Object} Derived address details
   */
  deriveAddress(account = 0, change = 0, index = 0, type = 'segwit') {
    if (!this.masterKeys) {
      throw new NonCustodialWalletError(
        'HD derivation not available',
        'Use createNewHD(), fromMnemonic(), or fromSeed() for HD support'
      );
    }

    // Handle single-key mode (WIF import)
    if (this._singleKeyMode) {
      return this._deriveSingleKeyAddress(type);
    }

    const cacheKey = `${type}:${account}:${change}:${index}`;
    if (this.derivedAddresses.has(cacheKey)) {
      return this.derivedAddresses.get(cacheKey);
    }

    const purpose = ADDRESS_TYPE_PURPOSE[type] || ADDRESS_TYPE_PURPOSE.segwit;
    const coinType = this.network === 'main' ? 0 : 1;
    const path = `m/${purpose}'/${coinType}'/${account}'/${change}/${index}`;

    const derived = derive(path, this.masterKeys.extendedPrivateKey);
    const publicKeyHex = derived.publicKey.toString('hex');
    const pubkeyHash = hash160(derived.publicKey);

    let address, scriptPubKey, redeemScript = null;

    switch (type) {
      case 'legacy':
        address = encodeP2PKH(derived.publicKey, this.network);
        scriptPubKey = ScriptBuilder.createP2PKH(pubkeyHash);
        break;

      case 'wrapped-segwit':
        // BIP49: P2SH-P2WPKH
        const p2wpkhScript = ScriptBuilder.createP2WPKH(pubkeyHash);
        const scriptHash = hash160(p2wpkhScript);
        address = encodeP2SH(scriptHash, this.network);
        scriptPubKey = ScriptBuilder.createP2SH(scriptHash);
        redeemScript = p2wpkhScript;
        break;

      case 'taproot':
        const xOnlyPubKey = derived.publicKey.slice(1);
        address = BECH32.to_P2TR(xOnlyPubKey, this.network);
        scriptPubKey = ScriptBuilder.createP2TR(xOnlyPubKey);
        break;

      case 'segwit':
      default:
        address = BECH32.to_P2WPKH(publicKeyHex, this.network);
        scriptPubKey = ScriptBuilder.createP2WPKH(pubkeyHash);
    }

    const result = {
      address,
      publicKey: publicKeyHex,
      publicKeyBuffer: derived.publicKey,
      privateKey: derived.privateKey ? encodeWIF(derived.privateKey, this.network) : null,
      privateKeyBuffer: derived.privateKey || null,
      path,
      type,
      network: this.network,
      scriptPubKey,
      redeemScript
    };

    this.derivedAddresses.set(cacheKey, result);
    return result;
  }

  /**
   * Derive address for single-key mode (WIF import)
   * @private
   * @param {string} type - Address type
   * @returns {Object} Address details
   */
  _deriveSingleKeyAddress(type) {
    const privateKey = this.masterKeys.singlePrivateKey;
    const publicKey = ECDSA.getPublicKey(privateKey, this.masterKeys.compressed);
    const publicKeyHex = publicKey.toString('hex');
    const pubkeyHash = hash160(publicKey);

    let address, scriptPubKey, redeemScript = null;

    switch (type) {
      case 'legacy':
        address = encodeP2PKH(publicKey, this.network);
        scriptPubKey = ScriptBuilder.createP2PKH(pubkeyHash);
        break;

      case 'wrapped-segwit':
        const p2wpkhScript = ScriptBuilder.createP2WPKH(pubkeyHash);
        const scriptHash = hash160(p2wpkhScript);
        address = encodeP2SH(scriptHash, this.network);
        scriptPubKey = ScriptBuilder.createP2SH(scriptHash);
        redeemScript = p2wpkhScript;
        break;

      case 'taproot':
        const xOnlyPubKey = publicKey.slice(1);
        address = BECH32.to_P2TR(xOnlyPubKey, this.network);
        scriptPubKey = ScriptBuilder.createP2TR(xOnlyPubKey);
        break;

      case 'segwit':
      default:
        address = BECH32.to_P2WPKH(publicKeyHex, this.network);
        scriptPubKey = ScriptBuilder.createP2WPKH(pubkeyHash);
    }

    return {
      address,
      publicKey: publicKeyHex,
      publicKeyBuffer: publicKey,
      privateKey: encodeWIF(privateKey, this.network, this.masterKeys.compressed),
      privateKeyBuffer: privateKey,
      path: 'single-key',
      type,
      network: this.network,
      scriptPubKey,
      redeemScript
    };
  }

  /**
   * Get a receiving (external) address from HD derivation
   * @param {number} account - Account index
   * @param {number} index - Address index
   * @param {string} type - Address type
   * @returns {Object} Address details
   */
  getReceivingAddress(account = 0, index = 0, type = 'segwit') {
    return this.deriveAddress(account, 0, index, type);
  }

  /**
   * Get a change (internal) address from HD derivation
   * @param {number} account - Account index
   * @param {number} index - Address index
   * @param {string} type - Address type
   * @returns {Object} Address details
   */
  getChangeAddress(account = 0, index = 0, type = 'segwit') {
    return this.deriveAddress(account, 1, index, type);
  }

  /**
   * Get multiple addresses of a specific type for an account
   * @param {number} account - Account index
   * @param {string} type - Address type
   * @param {number} count - Number of addresses to generate
   * @returns {Array<Object>} Array of address details
   */
  getAddresses(account = 0, type = 'segwit', count = 20) {
    const addresses = [];
    for (let i = 0; i < count; i++) {
      addresses.push(this.getReceivingAddress(account, i, type));
    }
    return addresses;
  }

  /**
   * Check if HD derivation is available
   * @returns {boolean} True if HD is available
   */
  hasHD() {
    return !!this.masterKeys;
  }

  /**
   * Get the wallet's mnemonic phrase (if available)
   * @returns {string|null} Mnemonic phrase or null
   */
  getMnemonic() {
    return this.mnemonic;
  }

  /**
   * Get the extended public key (xpub/tpub)
   * @returns {string|null} Extended public key or null
   */
  getExtendedPublicKey() {
    return this.masterKeys?.extendedPublicKey || null;
  }

  /**
   * Get the extended private key (xprv/tprv)
   * @returns {string|null} Extended private key or null
   */
  getExtendedPrivateKey() {
    return this.masterKeys?.extendedPrivateKey || null;
  }

  /**
   * Get total count of derived addresses
   * @returns {number} Address count
   */
  getAddressCount() {
    return this.derivedAddresses.size;
  }

  /**
   * List all derived addresses
   * @returns {Array<Object>} Array of all derived address objects
   */
  listAddresses() {
    return Array.from(this.derivedAddresses.values());
  }

  /**
   * Clear the derived addresses cache
   */
  clearAddressCache() {
    this.derivedAddresses.clear();
  }

  // ============================================
  // Transaction Methods
  // ============================================

  /**
   * Create a new transaction builder
   * @returns {TransactionBuilder} Transaction builder instance
   */
  createTransaction() {
    return new TransactionBuilder(this.network);
  }

  /**
   * Sign a transaction with HD-derived wallet keys
   * Note: This signs using HD-derived keys, not TSS aggregate key
   * @param {TransactionBuilder} builder - Transaction builder with inputs added
   * @param {Array<Object>} inputInfo - Array of {account, change, index, type} for each input
   * @returns {Promise<TransactionBuilder>} Signed transaction builder
   */
  async signTransaction(builder, inputInfo) {
    if (!this.masterKeys) {
      throw new NonCustodialWalletError(
        'HD wallet not available for transaction signing',
        'Use createNewHD() or fromMnemonic() for transaction support'
      );
    }

    for (let i = 0; i < inputInfo.length; i++) {
      const info = inputInfo[i];
      const derived = this.deriveAddress(
        info.account ?? 0,
        info.change ?? 0,
        info.index ?? 0,
        info.type ?? 'segwit'
      );

      if (!derived.privateKeyBuffer) {
        throw new NonCustodialWalletError(
          `No private key for input ${i}`,
          'Wallet may be read-only'
        );
      }

      await builder.signInput(i, derived.privateKeyBuffer);
    }

    return builder;
  }

  /**
   * Sign a message using HD-derived key (legacy Bitcoin message format)
   * @param {string|Buffer} message - Message to sign
   * @param {number} account - Account index
   * @param {number} index - Address index
   * @param {string} type - Address type for signing
   * @returns {Object} Signature result
   */
  signMessageHD(message, account = 0, index = 0, type = 'segwit') {
    if (!this.masterKeys) {
      throw new NonCustodialWalletError(
        'HD wallet required for HD message signing',
        'Use createNewHD() or fromMnemonic()'
      );
    }

    const derived = this.deriveAddress(account, 0, index, type);
    if (!derived.privateKeyBuffer) {
      throw new NonCustodialWalletError('No private key available for signing');
    }

    return BIP322.signLegacy(message, derived.privateKeyBuffer);
  }

  /**
   * Sign a message using BIP322 (for SegWit/Taproot HD addresses)
   * @param {string|Buffer} message - Message to sign
   * @param {number} account - Account index
   * @param {number} index - Address index
   * @param {string} type - Address type ('segwit' or 'taproot')
   * @returns {Promise<Buffer>} BIP322 signature
   */
  async signMessageBIP322(message, account = 0, index = 0, type = 'segwit') {
    if (!this.masterKeys) {
      throw new NonCustodialWalletError(
        'HD wallet required for BIP322 signing',
        'Use createNewHD() or fromMnemonic()'
      );
    }

    const derived = this.deriveAddress(account, 0, index, type);
    if (!derived.privateKeyBuffer) {
      throw new NonCustodialWalletError('No private key available for signing');
    }

    const addressType = type === 'taproot' ? 'p2tr' : 'p2wpkh';
    return BIP322.sign(message, derived.privateKeyBuffer, addressType);
  }

  /**
   * Verify a signed message using HD public key
   * @param {string|Buffer} message - Original message
   * @param {Object} signature - Signature to verify
   * @param {string|Buffer} publicKey - Public key to verify against
   * @returns {boolean} True if signature is valid
   */
  verifyMessageHD(message, signature, publicKey) {
    return BIP322.verifyLegacy(message, signature, publicKey);
  }

  /**
   * Export HD-derived private key as WIF
   * @param {number} account - Account index
   * @param {number} change - Change index
   * @param {number} index - Address index
   * @param {string} type - Address type
   * @returns {string|null} WIF-encoded private key
   */
  exportWIF(account = 0, change = 0, index = 0, type = 'segwit') {
    if (!this.masterKeys) {
      return null;
    }
    const derived = this.deriveAddress(account, change, index, type);
    return derived.privateKey;
  }

  // ============================================
  // Utility Methods
  // ============================================

  /**
   * Get the wallet's network type
   * @returns {string} Network type ('main' or 'test')
   */
  getNetwork() {
    return this.network;
  }

  /**
   * Check if wallet can sign (has private key access)
   * @returns {boolean} True if wallet can sign
   */
  canSign() {
    const hasTSS = !!this.scheme;
    const hasHDPrivate = !!(this.masterKeys?.extendedPrivateKey || this.masterKeys?.singlePrivateKey);
    return hasTSS || hasHDPrivate;
  }

  /**
   * Check if HD wallet can sign (separate from TSS)
   * @returns {boolean} True if HD signing is available
   */
  canSignHD() {
    return !!(this.masterKeys?.extendedPrivateKey || this.masterKeys?.singlePrivateKey);
  }

  /**
   * Get all shares for distribution to participants
   * @returns {Array} Array of share objects
   */
  getShares() {
    return this.exportedShares.map(s => s.toJSON());
  }

  /**
   * Get a specific participant's share
   * @param {number} index - Participant index (1-indexed)
   * @returns {Object} Share data
   */
  getShare(index) {
    const share = this.exportedShares.find(s => s.index === index);
    if (!share) {
      throw new NonCustodialWalletError(`Share ${index} not found`);
    }
    return share.toJSON();
  }

  /**
   * Sign a message hash using threshold signature
   * @param {Buffer|string} messageHash - 32-byte message hash
   * @param {number[]} participantIndices - Indices of signing participants
   * @returns {Object} Signature {r, s, signature}
   */
  sign(messageHash, participantIndices = null) {
    if (!this.scheme) {
      throw new NonCustodialWalletError(
        'Full signing requires initialized scheme',
        'Use createNew() to create a signable wallet'
      );
    }

    // Default to first signingThreshold participants
    const indices = participantIndices ||
      Array.from({ length: this.signingThreshold }, (_, i) => i + 1);

    if (indices.length < this.signingThreshold) {
      throw new NonCustodialWalletError(
        `Need at least ${this.signingThreshold} participants to sign (2t+1)`,
        'Provide more participant indices'
      );
    }

    return this.scheme.sign(messageHash, indices);
  }

  /**
   * Sign a message (with Bitcoin message prefix)
   * @param {string|Buffer} message - Message to sign
   * @param {number[]} participantIndices - Signing participants
   * @returns {Object} Signature
   */
  signMessage(message, participantIndices = null) {
    if (!this.scheme) {
      throw new NonCustodialWalletError(
        'Full signing requires initialized scheme',
        'Use createNew() to create a signable wallet'
      );
    }

    return this.scheme.signMessage(message, participantIndices);
  }

  /**
   * Verify a signature
   * @param {Buffer|string} messageHash - Message hash
   * @param {Object|Buffer} signature - Signature to verify
   * @returns {boolean} True if valid
   */
  verify(messageHash, signature) {
    if (!this.aggregatePublicKey) {
      throw new NonCustodialWalletError('Wallet not initialized');
    }

    if (this.scheme) {
      return this.scheme.verify(messageHash, signature);
    }

    // Manual verification if scheme not available
    try {
      let r, s;
      if (Buffer.isBuffer(signature) && signature.length === 64) {
        r = new BN(signature.slice(0, 32));
        s = new BN(signature.slice(32, 64));
      } else if (signature.r && signature.s) {
        r = new BN(signature.r, 'hex');
        s = new BN(signature.s, 'hex');
      } else {
        return false;
      }

      const sig = new secp256k1.Signature(
        BigInt('0x' + r.toString('hex')),
        BigInt('0x' + s.toString('hex'))
      );

      let hash;
      if (typeof messageHash === 'string') {
        hash = Buffer.from(messageHash, 'hex');
      } else {
        hash = messageHash;
      }

      return secp256k1.verify(sig, hash, this.aggregatePublicKey);
    } catch {
      return false;
    }
  }

  /**
   * Get the aggregate public key
   * @returns {Buffer} Compressed public key
   */
  getPublicKey() {
    return this.aggregatePublicKey;
  }

  /**
   * Get threshold configuration
   * @returns {Object} Configuration details
   */
  getThresholdConfig() {
    return {
      n: this.n,
      t: this.t,
      reconstructionThreshold: this.reconstructionThreshold,
      signingThreshold: this.signingThreshold,
      sharesAvailable: this.exportedShares.length,
      ephemeralKeysAvailable: this.scheme?.getConfig()?.availableEphemeralKeys || 0
    };
  }

  /**
   * Generate more ephemeral keys for signing
   * @param {number} count - Number of keys to generate
   */
  generateEphemeralKeys(count = 10) {
    if (!this.scheme) {
      throw new NonCustodialWalletError('Scheme not initialized');
    }
    this.scheme.generateEphemeralKeys(count);
  }

  /**
   * Export wallet for serialization
   * @returns {Object} Serialized wallet data
   */
  toJSON() {
    return {
      network: this.network,
      version: this.version,
      created: this.created,
      n: this.n,
      t: this.t,
      signingThreshold: this.signingThreshold,
      reconstructionThreshold: this.reconstructionThreshold,
      aggregatePublicKey: this.aggregatePublicKey?.toString('hex'),
      sharesCount: this.exportedShares.length,
      // HD wallet info
      hasHD: this.hasHD(),
      extendedPublicKey: this.masterKeys?.extendedPublicKey || null,
      derivedAddressCount: this.derivedAddresses.size
    };
  }

  /**
   * Export shares for backup
   * @returns {Object} Exportable data
   */
  exportShares() {
    return {
      network: this.network,
      n: this.n,
      t: this.t,
      shares: this.getShares()
    };
  }

  /**
   * Import shares from backup
   * @param {Object} exportedData - Previously exported data
   * @returns {NonCustodialWallet} Restored wallet
   */
  static importShares(exportedData) {
    return NonCustodialWallet.fromShares(
      exportedData.network,
      exportedData.shares,
      exportedData.t
    );
  }

  /**
   * Clear sensitive data
   */
  clear() {
    if (this.scheme) {
      this.scheme.clear();
    }
    this.exportedShares = [];
    this.aggregatePublicKey = null;
    // Clear HD data
    this.mnemonic = null;
    this.masterKeys = null;
    this.derivedAddresses.clear();
  }

  /**
   * Securely clear all sensitive data (overwrites buffers)
   * @returns {void}
   */
  destroy() {
    // Clear TSS scheme
    if (this.scheme) {
      this.scheme.clear();
    }
    this.scheme = null;

    // Securely overwrite single private key if present
    if (this.masterKeys?.singlePrivateKey && Buffer.isBuffer(this.masterKeys.singlePrivateKey)) {
      this.masterKeys.singlePrivateKey.fill(0);
    }

    // Clear all sensitive properties
    this.mnemonic = null;
    this.masterKeys = null;
    this.exportedShares = [];
    this.aggregatePublicKey = null;
    this.derivedAddresses.clear();
    this._singleKeyMode = false;
  }
}

export { NonCustodialWallet, NonCustodialWalletError, ParticipantShare };
export default NonCustodialWallet;
