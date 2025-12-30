/**
 * @fileoverview Custodial Bitcoin Wallet implementation
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */


import { BIP39 } from '../bip/bip39/mnemonic.js';
import { generateMasterKey } from '../bip/bip32/master-key.js';
import { derive } from '../bip/bip32/derive.js';
import { BECH32 } from '../bip/BIP173-BIP350.js';
import { ECDSA } from '../core/crypto/signatures/ecdsa.js';
import { encodeP2PKH, encodeWIF, hash160 } from '../encoding/address/encode.js';
import { NETWORK_VERSIONS, BIP_PURPOSES } from '../core/constants.js';

/**
 * Custom error class for custodial wallet operations
 * @class CustodialWalletError
 * @extends Error
 */
class CustodialWalletError extends Error {
  /**
   * Create a custodial wallet error
   * @param {string} message - Error message
   * @param {string} [solution=''] - Suggested solution for the error
   */
  constructor(message, solution = '') {
    super(message);
    /** @type {string} */
    this.name = 'CustodialWalletError';
    /** @type {string} */
    this.solution = solution;
    /** @type {string} */
    this.timestamp = new Date().toISOString();
  }
}

/**
 * Custodial Bitcoin wallet with full key management
 * @class CustodialWallet
 * @description Implements a fully-featured custodial HD wallet supporting
 * BIP32/39/44/84/86 standards with legacy, SegWit, and Taproot address support.
 * 
 * @example
 * // Create a new wallet
 * const { wallet, mnemonic } = CustodialWallet.createNew('main');
 * console.log('Backup phrase:', mnemonic);
 * 
 * @example
 * // Restore from mnemonic
 * const wallet = CustodialWallet.fromMnemonic('main', 'abandon abandon...');
 * const address = wallet.getReceivingAddress();
 */
class CustodialWallet {
  /**
   * Create a custodial wallet instance
   * @param {string} network - Network type ('main' or 'test')
   * @param {Object} masterKeys - Master key pair
   * @param {string} masterKeys.extendedPrivateKey - BIP32 extended private key (xprv/tprv)
   * @param {string} masterKeys.extendedPublicKey - BIP32 extended public key (xpub/tpub)
   * @param {string|null} [mnemonic=null] - BIP39 mnemonic phrase
   */
  constructor(network, masterKeys, mnemonic = null) {
    /** @type {string} */
    this.network = network === 'main' ? 'main' : 'test';
    /** @type {Object} */
    this.masterKeys = masterKeys;
    /** @type {string|null} */
    this.mnemonic = mnemonic;
    /** @type {Map<string, Object>} */
    this.derivedAddresses = new Map();
    /** @type {string} */
    this.version = '1.0.0';
    /** @type {number} */
    this.created = Date.now();
  }

  /**
   * Create a new wallet with a fresh mnemonic
   * @static
   * @param {string} [network='main'] - Network type ('main' or 'test')
   * @returns {{wallet: CustodialWallet, mnemonic: string}} New wallet and backup mnemonic
   * @throws {CustodialWalletError} If wallet creation fails
   * @example
   * const { wallet, mnemonic } = CustodialWallet.createNew('main');
   */
  static createNew(network = 'main') {
    try {
      const mnemonicResult = BIP39.generateMnemonic();
      const mnemonic = mnemonicResult.mnemonic;
      const seed = BIP39.deriveSeed(mnemonic);
      const [masterKeys] = generateMasterKey(seed, network);

      const wallet = new CustodialWallet(network, masterKeys, mnemonic);
      return { wallet, mnemonic };
    } catch (error) {
      throw new CustodialWalletError(
        `Failed to create wallet: ${error.message}`,
        'Ensure crypto module is available'
      );
    }
  }

  /**
   * Restore a wallet from a BIP39 mnemonic phrase
   * @static
   * @param {string} network - Network type ('main' or 'test')
   * @param {string} mnemonic - BIP39 mnemonic phrase (12-24 words)
   * @returns {CustodialWallet} Restored wallet instance
   * @throws {CustodialWalletError} If mnemonic is invalid
   * @example
   * const wallet = CustodialWallet.fromMnemonic('main', 'abandon abandon abandon...');
   */
  static fromMnemonic(network, mnemonic) {
    try {
      if (!BIP39.validateChecksum(mnemonic)) {
        throw new Error('Invalid mnemonic checksum');
      }

      const seed = BIP39.deriveSeed(mnemonic);
      const [masterKeys] = generateMasterKey(seed, network);

      return new CustodialWallet(network, masterKeys, mnemonic);
    } catch (error) {
      throw new CustodialWalletError(
        `Failed to restore wallet: ${error.message}`,
        'Verify mnemonic phrase is correct'
      );
    }
  }

  /**
   * Create a wallet from a raw seed
   * @static
   * @param {string} network - Network type ('main' or 'test')
   * @param {string|Buffer} seed - 64-byte seed as hex string or Buffer
   * @returns {CustodialWallet} Wallet instance
   * @throws {CustodialWalletError} If seed is invalid
   * @example
   * const wallet = CustodialWallet.fromSeed('main', seedHex);
   */
  static fromSeed(network, seed) {
    try {
      const [masterKeys] = generateMasterKey(seed, network);
      return new CustodialWallet(network, masterKeys, null);
    } catch (error) {
      throw new CustodialWalletError(
        `Failed to create wallet from seed: ${error.message}`,
        'Verify seed is valid hex string'
      );
    }
  }

  /**
   * Create a wallet from an extended key (xprv/xpub/tprv/tpub)
   * @static
   * @param {string} network - Network type ('main' or 'test')
   * @param {string} extendedKey - BIP32 extended key
   * @returns {CustodialWallet} Wallet instance
   * @throws {CustodialWalletError} If extended key format is invalid
   * @example
   * const wallet = CustodialWallet.fromExtendedKey('main', 'xprv...');
   */
  static fromExtendedKey(network, extendedKey) {
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

      return new CustodialWallet(network, masterKeys, null);
    } catch (error) {
      throw new CustodialWalletError(
        `Failed to create wallet from extended key: ${error.message}`,
        'Verify extended key format'
      );
    }
  }

  /**
   * Derive a Bitcoin address at the specified path
   * @param {number} [account=0] - Account index (hardened)
   * @param {number} [change=0] - Change index (0=external, 1=internal)
   * @param {number} [index=0] - Address index
   * @param {string} [type='segwit'] - Address type ('legacy', 'segwit', 'taproot')
   * @returns {Object} Derived address details
   * @returns {string} returns.address - Bitcoin address
   * @returns {string} returns.publicKey - Compressed public key hex
   * @returns {string|null} returns.privateKey - WIF-encoded private key
   * @returns {string} returns.path - Full derivation path
   * @returns {string} returns.type - Address type
   * @returns {string} returns.network - Network type
   */
  deriveAddress(account = 0, change = 0, index = 0, type = 'segwit') {
    const cacheKey = `${type}:${account}:${change}:${index}`;

    if (this.derivedAddresses.has(cacheKey)) {
      return this.derivedAddresses.get(cacheKey);
    }

    let purpose;
    switch (type) {
      case 'legacy':
        purpose = BIP_PURPOSES.LEGACY;
        break;
      case 'taproot':
        purpose = BIP_PURPOSES.TAPROOT;
        break;
      case 'segwit':
      default:
        purpose = BIP_PURPOSES.NATIVE_SEGWIT;
    }

    const coinType = this.network === 'main' ? 0 : 1;
    const path = `m/${purpose}'/${coinType}'/${account}'/${change}/${index}`;

    const derived = derive(path, this.masterKeys.extendedPrivateKey);
    const publicKeyHex = derived.publicKey.toString('hex');

    let address;
    switch (type) {
      case 'legacy':
        address = encodeP2PKH(derived.publicKey, this.network);
        break;
      case 'taproot':
        const xOnlyPubKey = derived.publicKey.slice(1);
        address = BECH32.to_P2TR(xOnlyPubKey, this.network);
        break;
      case 'segwit':
      default:
        address = BECH32.to_P2WPKH(publicKeyHex, this.network);
    }

    const result = {
      address,
      publicKey: publicKeyHex,
      privateKey: derived.privateKey ? encodeWIF(derived.privateKey, this.network) : null,
      path,
      type,
      network: this.network
    };

    this.derivedAddresses.set(cacheKey, result);
    return result;
  }

  /**
   * Get a receiving (external) address
   * @param {number} [account=0] - Account index
   * @param {number} [index=0] - Address index
   * @param {string} [type='segwit'] - Address type
   * @returns {Object} Address details
   */
  getReceivingAddress(account = 0, index = 0, type = 'segwit') {
    return this.deriveAddress(account, 0, index, type);
  }

  /**
   * Get a change (internal) address
   * @param {number} [account=0] - Account index
   * @param {number} [index=0] - Address index
   * @param {string} [type='segwit'] - Address type
   * @returns {Object} Address details
   */
  getChangeAddress(account = 0, index = 0, type = 'segwit') {
    return this.deriveAddress(account, 1, index, type);
  }

  /**
   * Sign a message using Bitcoin message signing
   * @param {string|Buffer} message - Message to sign
   * @param {number} [account=0] - Account index
   * @param {number} [index=0] - Address index
   * @returns {Object} ECDSA signature
   * @throws {CustodialWalletError} If no private key available
   */
  signMessage(message, account = 0, index = 0) {
    const derived = this.deriveAddress(account, 0, index, 'segwit');

    if (!derived.privateKey) {
      throw new CustodialWalletError('No private key available for signing');
    }

    return ECDSA.signMessage(derived.privateKey, message);
  }

  /**
   * Verify a signed message
   * @param {string|Buffer} message - Original message
   * @param {Object} signature - Signature to verify
   * @param {string|Buffer} publicKey - Public key to verify against
   * @returns {boolean} True if signature is valid
   */
  verifyMessage(message, signature, publicKey) {
    return ECDSA.verifyMessage(signature, message, publicKey);
  }

  /**
   * Get the master extended public key (xpub/tpub)
   * @returns {string} Extended public key
   */
  getExtendedPublicKey() {
    return this.masterKeys.extendedPublicKey;
  }

  /**
   * Get the master extended private key (xprv/tprv)
   * @returns {string} Extended private key
   */
  getExtendedPrivateKey() {
    return this.masterKeys.extendedPrivateKey;
  }

  /**
   * Get the wallet's mnemonic phrase
   * @returns {string|null} Mnemonic phrase or null if not available
   */
  getMnemonic() {
    return this.mnemonic;
  }

  /**
   * Get the wallet's network type
   * @returns {string} Network type ('main' or 'test')
   */
  getNetwork() {
    return this.network;
  }

  /**
   * Serialize wallet to JSON (excludes sensitive data)
   * @returns {Object} JSON-serializable wallet data
   */
  toJSON() {
    return {
      network: this.network,
      version: this.version,
      created: this.created,
      extendedPublicKey: this.masterKeys.extendedPublicKey,
      addressCount: this.derivedAddresses.size
    };
  }

  /**
   * Clear the derived addresses cache
   * @returns {void}
   */
  clearCache() {
    this.derivedAddresses.clear();
  }
}

export { CustodialWallet, CustodialWalletError };
export default CustodialWallet;
