/**
 * @fileoverview Custodial Bitcoin Wallet implementation
 * @version 2.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';
import { BIP39 } from '../bip/bip39/mnemonic.js';
import { generateMasterKey } from '../bip/bip32/master-key.js';
import { derive } from '../bip/bip32/derive.js';
import { BECH32 } from '../bip/BIP173-BIP350.js';
import { ECDSA } from '../core/crypto/signatures/ecdsa.js';
import { encodeP2PKH, encodeWIF, hash160 } from '../encoding/address/encode.js';
import { NETWORK_VERSIONS, BIP_PURPOSES, generateDerivationPath } from '../core/constants.js';

class CustodialWalletError extends Error {
  constructor(message, solution = '') {
    super(message);
    this.name = 'CustodialWalletError';
    this.solution = solution;
    this.timestamp = new Date().toISOString();
  }
}

class CustodialWallet {
  constructor(network, masterKeys, mnemonic = null) {
    this.network = network === 'main' ? 'main' : 'test';
    this.masterKeys = masterKeys;
    this.mnemonic = mnemonic;
    this.derivedAddresses = new Map();
    this.version = '2.0.0';
    this.created = Date.now();
  }

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

  getReceivingAddress(account = 0, index = 0, type = 'segwit') {
    return this.deriveAddress(account, 0, index, type);
  }

  getChangeAddress(account = 0, index = 0, type = 'segwit') {
    return this.deriveAddress(account, 1, index, type);
  }

  signMessage(message, account = 0, index = 0) {
    const derived = this.deriveAddress(account, 0, index, 'segwit');

    if (!derived.privateKey) {
      throw new CustodialWalletError('No private key available for signing');
    }

    return ECDSA.signMessage(derived.privateKey, message);
  }

  verifyMessage(message, signature, publicKey) {
    return ECDSA.verifyMessage(signature, message, publicKey);
  }

  getExtendedPublicKey() {
    return this.masterKeys.extendedPublicKey;
  }

  getExtendedPrivateKey() {
    return this.masterKeys.extendedPrivateKey;
  }

  getMnemonic() {
    return this.mnemonic;
  }

  getNetwork() {
    return this.network;
  }

  toJSON() {
    return {
      network: this.network,
      version: this.version,
      created: this.created,
      extendedPublicKey: this.masterKeys.extendedPublicKey,
      addressCount: this.derivedAddresses.size
    };
  }

  clearCache() {
    this.derivedAddresses.clear();
  }
}

export { CustodialWallet, CustodialWalletError };
export default CustodialWallet;
