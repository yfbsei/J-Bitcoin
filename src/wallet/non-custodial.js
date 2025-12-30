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


import { BECH32 } from '../bip/BIP173-BIP350.js';
import { THRESHOLD_CONSTANTS } from '../core/constants.js';

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

    this.version = '1.0.0';
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
      sharesCount: this.exportedShares.length
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
  }
}

export { NonCustodialWallet, NonCustodialWalletError, ParticipantShare };
export default NonCustodialWallet;
