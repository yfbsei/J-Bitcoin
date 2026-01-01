/**
 * @fileoverview Custodial Bitcoin Wallet implementation
 * @description Full-featured HD wallet with all address types and transaction signing
 * @version 2.0.0
 * @author yfbsei
 * @license ISC
 */

import { BIP39 } from '../bip/bip39/mnemonic.js';
import { generateMasterKey } from '../bip/bip32/master-key.js';
import { derive } from '../bip/bip32/derive.js';
import { BECH32 } from '../bip/BIP173-BIP350.js';
import { ECDSA } from '../core/crypto/signatures/ecdsa.js';
import { encodeP2PKH, encodeP2SH, encodeWIF, hash160 } from '../encoding/address/encode.js';
import { decodeWIFPrivateKey } from '../encoding/address/decode.js';
import { NETWORK_VERSIONS, BIP_PURPOSES } from '../core/constants.js';
import { TransactionBuilder } from '../transaction/builder.js';
import { ScriptBuilder } from '../transaction/script-builder.js';
import { BIP322 } from '../transaction/message-signing.js';

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
 * Address type mapping to BIP purpose
 * @constant {Object}
 */
const ADDRESS_TYPE_PURPOSE = {
  legacy: 44,      // BIP44 - P2PKH
  'wrapped-segwit': 49,  // BIP49 - P2SH-P2WPKH
  segwit: 84,      // BIP84 - P2WPKH
  taproot: 86      // BIP86 - P2TR
};

/**
 * Custodial Bitcoin wallet with full key management
 * @class CustodialWallet
 * @description Implements a fully-featured custodial HD wallet supporting
 * BIP32/39/44/49/84/86 standards with legacy, wrapped SegWit, native SegWit, 
 * and Taproot address support.
 * 
 * @example
 * // Create a new wallet
 * const { wallet, mnemonic } = CustodialWallet.createNew('main');
 * console.log('Backup phrase:', mnemonic);
 * 
 * @example
 * // Get different address types
 * const legacy = wallet.getReceivingAddress(0, 0, 'legacy');     // 1...
 * const wrapped = wallet.getReceivingAddress(0, 0, 'wrapped-segwit'); // 3...
 * const native = wallet.getReceivingAddress(0, 0, 'segwit');     // bc1q...
 * const taproot = wallet.getReceivingAddress(0, 0, 'taproot');   // bc1p...
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
    this.version = '2.0.0';
    /** @type {number} */
    this.created = Date.now();
  }

  /**
   * Create a new wallet with a fresh mnemonic
   * @static
   * @param {string} [network='main'] - Network type ('main' or 'test')
   * @param {number} [strength=256] - Mnemonic strength (128, 160, 192, 224, 256)
   * @returns {{wallet: CustodialWallet, mnemonic: string}} New wallet and backup mnemonic
   * @throws {CustodialWalletError} If wallet creation fails
   * @example
   * const { wallet, mnemonic } = CustodialWallet.createNew('main');
   */
  static createNew(network = 'main', strength = 256) {
    try {
      const mnemonicResult = BIP39.generateMnemonic(strength);
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
   * @param {string} [passphrase=''] - Optional BIP39 passphrase
   * @returns {CustodialWallet} Restored wallet instance
   * @throws {CustodialWalletError} If mnemonic is invalid
   * @example
   * const wallet = CustodialWallet.fromMnemonic('main', 'abandon abandon abandon...');
   */
  static fromMnemonic(network, mnemonic, passphrase = '') {
    try {
      if (!BIP39.validateChecksum(mnemonic)) {
        throw new Error('Invalid mnemonic checksum');
      }

      const seed = BIP39.deriveSeed(mnemonic, passphrase);
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
   * Create a wallet from a WIF private key
   * @static
   * @param {string} wif - WIF-encoded private key
   * @returns {CustodialWallet} Wallet instance (single-key, no derivation)
   * @throws {CustodialWalletError} If WIF is invalid
   */
  static fromWIF(wif) {
    try {
      const decoded = decodeWIFPrivateKey(wif);
      // For WIF import, create a minimal wallet structure
      const wallet = new CustodialWallet(decoded.network, {
        extendedPrivateKey: null,
        extendedPublicKey: null,
        singlePrivateKey: decoded.privateKey,
        compressed: decoded.compressed
      }, null);
      wallet._singleKeyMode = true;
      return wallet;
    } catch (error) {
      throw new CustodialWalletError(
        `Failed to import WIF: ${error.message}`,
        'Verify WIF format is correct'
      );
    }
  }

  /**
   * Derive a Bitcoin address at the specified path
   * @param {number} [account=0] - Account index (hardened)
   * @param {number} [change=0] - Change index (0=external, 1=internal)
   * @param {number} [index=0] - Address index
   * @param {string} [type='segwit'] - Address type ('legacy', 'wrapped-segwit', 'segwit', 'taproot')
   * @returns {Object} Derived address details
   * @returns {string} returns.address - Bitcoin address
   * @returns {string} returns.publicKey - Compressed public key hex
   * @returns {string|null} returns.privateKey - WIF-encoded private key
   * @returns {Buffer|null} returns.privateKeyBuffer - Raw private key buffer
   * @returns {string} returns.path - Full derivation path
   * @returns {string} returns.type - Address type
   * @returns {string} returns.network - Network type
   * @returns {Buffer} returns.scriptPubKey - Output script
   * @returns {Buffer|null} returns.redeemScript - Redeem script (for P2SH types)
   */
  deriveAddress(account = 0, change = 0, index = 0, type = 'segwit') {
    const cacheKey = `${type}:${account}:${change}:${index}`;

    if (this.derivedAddresses.has(cacheKey)) {
      return this.derivedAddresses.get(cacheKey);
    }

    // Handle single-key mode (WIF import)
    if (this._singleKeyMode) {
      return this._deriveSingleKeyAddress(type);
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
   * Create a new transaction builder
   * @returns {TransactionBuilder} Transaction builder instance
   */
  createTransaction() {
    return new TransactionBuilder(this.network);
  }

  /**
   * Sign a transaction with wallet keys
   * @param {TransactionBuilder} builder - Transaction builder with inputs added
   * @param {Array<Object>} inputInfo - Array of {account, change, index, type} for each input
   * @returns {Promise<TransactionBuilder>} Signed transaction builder
   */
  async signTransaction(builder, inputInfo) {
    for (let i = 0; i < inputInfo.length; i++) {
      const info = inputInfo[i];
      const derived = this.deriveAddress(
        info.account ?? 0,
        info.change ?? 0,
        info.index ?? 0,
        info.type ?? 'segwit'
      );

      if (!derived.privateKeyBuffer) {
        throw new CustodialWalletError(
          `No private key for input ${i}`,
          'Wallet may be read-only'
        );
      }

      await builder.signInput(i, derived.privateKeyBuffer);
    }

    return builder;
  }

  /**
   * Sign a message using Bitcoin message signing
   * @param {string|Buffer} message - Message to sign
   * @param {number} [account=0] - Account index
   * @param {number} [index=0] - Address index
   * @param {string} [type='segwit'] - Address type for signing
   * @returns {Object} Signature result
   * @throws {CustodialWalletError} If no private key available
   */
  signMessage(message, account = 0, index = 0, type = 'segwit') {
    const derived = this.deriveAddress(account, 0, index, type);

    if (!derived.privateKeyBuffer) {
      throw new CustodialWalletError('No private key available for signing');
    }

    // Use legacy Bitcoin message format
    return BIP322.signLegacy(message, derived.privateKeyBuffer);
  }

  /**
   * Sign a message using BIP322 (for SegWit/Taproot addresses)
   * @param {string|Buffer} message - Message to sign
   * @param {number} [account=0] - Account index
   * @param {number} [index=0] - Address index
   * @param {string} [type='segwit'] - Address type
   * @returns {Promise<Buffer>} BIP322 signature
   */
  async signMessageBIP322(message, account = 0, index = 0, type = 'segwit') {
    const derived = this.deriveAddress(account, 0, index, type);

    if (!derived.privateKeyBuffer) {
      throw new CustodialWalletError('No private key available for signing');
    }

    const addressType = type === 'taproot' ? 'p2tr' : 'p2wpkh';
    return BIP322.sign(message, derived.privateKeyBuffer, addressType);
  }

  /**
   * Verify a signed message
   * @param {string|Buffer} message - Original message
   * @param {Object} signature - Signature to verify
   * @param {string|Buffer} publicKey - Public key to verify against
   * @returns {boolean} True if signature is valid
   */
  verifyMessage(message, signature, publicKey) {
    return BIP322.verifyLegacy(message, signature, publicKey);
  }

  /**
   * Export private key as WIF
   * @param {number} [account=0] - Account index
   * @param {number} [change=0] - Change index
   * @param {number} [index=0] - Address index
   * @param {string} [type='segwit'] - Address type
   * @returns {string|null} WIF-encoded private key
   */
  exportWIF(account = 0, change = 0, index = 0, type = 'segwit') {
    const derived = this.deriveAddress(account, change, index, type);
    return derived.privateKey;
  }

  /**
   * Get all addresses of a specific type for an account
   * @param {number} [account=0] - Account index
   * @param {string} [type='segwit'] - Address type
   * @param {number} [count=20] - Number of addresses to generate
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
   * Check if wallet has private key access
   * @returns {boolean} True if wallet can sign
   */
  canSign() {
    return !!(this.masterKeys.extendedPrivateKey || this.masterKeys.singlePrivateKey);
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
      addressCount: this.derivedAddresses.size,
      canSign: this.canSign()
    };
  }

  /**
   * Clear the derived addresses cache
   * @returns {void}
   */
  clearCache() {
    this.derivedAddresses.clear();
  }

  /**
   * Securely clear all sensitive data
   * @returns {void}
   */
  destroy() {
    if (this.masterKeys.singlePrivateKey) {
      this.masterKeys.singlePrivateKey.fill(0);
    }
    this.mnemonic = null;
    this.masterKeys = { extendedPrivateKey: null, extendedPublicKey: null };
    this.derivedAddresses.clear();
  }
}

export { CustodialWallet, CustodialWalletError };
export default CustodialWallet;

