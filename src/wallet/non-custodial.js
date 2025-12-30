/**
 * @fileoverview Non-Custodial Wallet with Threshold Signature Scheme
 * @version 2.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import BN from 'bn.js';
import { ThresholdSignature, FeldmanCommitments } from '../core/crypto/signatures/threshold/threshold-signature.js';
import { Polynomial } from '../core/crypto/signatures/threshold/polynomial.js';
import { Schnorr } from '../core/crypto/signatures/schnorr-BIP340.js';
import { ECDSA } from '../core/crypto/signatures/ecdsa.js';
import { BECH32 } from '../bip/BIP173-BIP350.js';
import { CRYPTO_CONSTANTS, THRESHOLD_CONSTANTS } from '../core/constants.js';

class NonCustodialWalletError extends Error {
  constructor(message, solution = 'Check threshold configuration') {
    super(message);
    this.name = 'NonCustodialWalletError';
    this.solution = solution;
    this.timestamp = new Date().toISOString();
  }
}

class ParticipantShare {
  constructor(index, x, y, publicKey = null) {
    this.index = index;
    this.x = x instanceof BN ? x : new BN(x, 'hex');
    this.y = y instanceof BN ? y : new BN(y, 'hex');
    this.publicKey = publicKey;
  }

  toJSON() {
    return {
      index: this.index,
      x: this.x.toString('hex'),
      y: this.y.toString('hex'),
      publicKey: this.publicKey ? this.publicKey.toString('hex') : null
    };
  }

  static fromJSON(json) {
    return new ParticipantShare(
      json.index,
      json.x,
      json.y,
      json.publicKey ? Buffer.from(json.publicKey, 'hex') : null
    );
  }
}

class NonCustodialWallet {
  constructor(network, participants, threshold) {
    if (threshold < THRESHOLD_CONSTANTS.MIN_THRESHOLD) {
      throw new NonCustodialWalletError(
        `Threshold must be at least ${THRESHOLD_CONSTANTS.MIN_THRESHOLD}`,
        'Increase threshold value'
      );
    }

    if (participants > THRESHOLD_CONSTANTS.MAX_PARTICIPANTS) {
      throw new NonCustodialWalletError(
        `Participants cannot exceed ${THRESHOLD_CONSTANTS.MAX_PARTICIPANTS}`,
        'Reduce participant count'
      );
    }

    if (threshold > participants) {
      throw new NonCustodialWalletError(
        'Threshold cannot exceed participants',
        'Adjust threshold or participant count'
      );
    }

    this.network = network === 'main' ? 'main' : 'test';
    this.participants = participants;
    this.threshold = threshold;
    this.shares = [];
    this.aggregatePublicKey = null;
    this.commitments = null;
    this.version = '2.0.0';
    this.created = Date.now();
  }

  static createNew(network = 'main', participants = 3, threshold = 2) {
    const wallet = new NonCustodialWallet(network, participants, threshold);
    wallet.generateShares();
    return { wallet, shares: wallet.getShares() };
  }

  static fromShares(network, shares, threshold) {
    const participants = shares.length;
    const wallet = new NonCustodialWallet(network, participants, threshold);

    wallet.shares = shares.map(s =>
      s instanceof ParticipantShare ? s : ParticipantShare.fromJSON(s)
    );

    wallet._reconstructPublicKey();
    return wallet;
  }

  generateShares(secret = null) {
    const thresholdSig = new ThresholdSignature(this.threshold, this.participants);
    const result = thresholdSig.generateShares(secret);

    this.shares = result.shares.map(s => new ParticipantShare(
      s.index,
      s.x,
      s.y
    ));

    this.commitments = result.commitments;
    this.aggregatePublicKey = result.publicKey;

    return this.shares;
  }

  _reconstructPublicKey() {
    if (this.shares.length < this.threshold) {
      throw new NonCustodialWalletError(
        `Need at least ${this.threshold} shares to reconstruct`,
        'Provide more shares'
      );
    }

    const selectedShares = this.shares.slice(0, this.threshold);
    const secret = Polynomial.reconstructSecret(
      selectedShares.map(s => ({ x: s.x, y: s.y }))
    );

    const secretBuffer = secret.toBuffer('be', 32);
    this.aggregatePublicKey = Buffer.from(
      secp256k1.getPublicKey(secretBuffer, true)
    );
  }

  getAddress(type = 'segwit') {
    if (!this.aggregatePublicKey) {
      this._reconstructPublicKey();
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

  getShares() {
    return this.shares.map(s => s.toJSON());
  }

  getShare(index) {
    const share = this.shares.find(s => s.index === index);
    if (!share) {
      throw new NonCustodialWalletError(`Share ${index} not found`);
    }
    return share.toJSON();
  }

  verifyShare(share) {
    if (!this.commitments) {
      throw new NonCustodialWalletError('Commitments not available');
    }

    const feldman = new FeldmanCommitments({ getCoefficients: () => [] });
    feldman.commitments = this.commitments.map(c =>
      secp256k1.ProjectivePoint.fromHex(c)
    );

    return feldman.verifyShare({
      x: new BN(share.x, 'hex'),
      y: new BN(share.y, 'hex')
    });
  }

  async signMessage(messageHash, participantIndices = null) {
    const indices = participantIndices || this.shares.slice(0, this.threshold).map(s => s.index);

    if (indices.length < this.threshold) {
      throw new NonCustodialWalletError(
        `Need at least ${this.threshold} participants to sign`,
        'Provide more participant indices'
      );
    }

    const selectedShares = indices.map(i => {
      const share = this.shares.find(s => s.index === i);
      if (!share) {
        throw new NonCustodialWalletError(`Share ${i} not found`);
      }
      return share;
    });

    const partialSigs = selectedShares.map(share =>
      ThresholdSignature.generatePartialSignature(
        { y: share.y, index: share.index },
        messageHash
      )
    );

    return ThresholdSignature.combinePartialSignatures(partialSigs, this.threshold);
  }

  async verifySignature(messageHash, signature) {
    if (!this.aggregatePublicKey) {
      this._reconstructPublicKey();
    }

    return ThresholdSignature.verifyThresholdSignature(
      this.aggregatePublicKey,
      messageHash,
      signature
    );
  }

  getPublicKey() {
    if (!this.aggregatePublicKey) {
      this._reconstructPublicKey();
    }
    return this.aggregatePublicKey;
  }

  getThresholdConfig() {
    return {
      threshold: this.threshold,
      participants: this.participants,
      sharesAvailable: this.shares.length
    };
  }

  toJSON() {
    return {
      network: this.network,
      version: this.version,
      created: this.created,
      threshold: this.threshold,
      participants: this.participants,
      aggregatePublicKey: this.aggregatePublicKey?.toString('hex'),
      sharesCount: this.shares.length
    };
  }

  exportShares() {
    return {
      network: this.network,
      threshold: this.threshold,
      participants: this.participants,
      shares: this.getShares(),
      commitments: this.commitments?.map(c => c.toString('hex'))
    };
  }

  static importShares(exportedData) {
    const wallet = NonCustodialWallet.fromShares(
      exportedData.network,
      exportedData.shares,
      exportedData.threshold
    );

    if (exportedData.commitments) {
      wallet.commitments = exportedData.commitments.map(c => Buffer.from(c, 'hex'));
    }

    return wallet;
  }
}

export { NonCustodialWallet, NonCustodialWalletError, ParticipantShare };
export default NonCustodialWallet;
