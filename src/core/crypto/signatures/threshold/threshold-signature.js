/**
 * @fileoverview Threshold signature implementation with JVRSS and Feldman commitments
 * @version 2.1.0
 * @author yfbsei
 * @license ISC
 */

import { randomBytes, createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import BN from 'bn.js';
import { Polynomial, CURVE_ORDER } from './polynomial.js';
import { CRYPTO_CONSTANTS, THRESHOLD_CONSTANTS } from '../../../constants.js';

class ThresholdError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'ThresholdError';
    this.code = code;
    this.details = details;
  }
}

const G = secp256k1.ProjectivePoint.BASE;

class FeldmanCommitments {
  constructor(polynomial) {
    this.commitments = [];

    for (const coeff of polynomial.getCoefficients()) {
      const coeffBuffer = coeff.toBuffer('be', 32);
      const commitment = G.multiply(BigInt('0x' + coeffBuffer.toString('hex')));
      this.commitments.push(commitment);
    }
  }

  verifyShare(share) {
    const { x, y } = share;
    const xBN = x instanceof BN ? x : new BN(x);
    const yBN = y instanceof BN ? y : new BN(y);

    let expectedPoint = this.commitments[0];
    let xPower = xBN.clone();

    for (let i = 1; i < this.commitments.length; i++) {
      const term = this.commitments[i].multiply(BigInt('0x' + xPower.toString('hex')));
      expectedPoint = expectedPoint.add(term);
      xPower = xPower.mul(xBN).umod(CURVE_ORDER);
    }

    const yBuffer = yBN.toBuffer('be', 32);
    const actualPoint = G.multiply(BigInt('0x' + yBuffer.toString('hex')));

    return expectedPoint.equals(actualPoint);
  }

  getCommitments() {
    return this.commitments.map(c => Buffer.from(c.toRawBytes(true)));
  }
}

class ThresholdSignature {
  constructor(threshold, participants) {
    if (threshold < THRESHOLD_CONSTANTS.MIN_THRESHOLD) {
      throw new ThresholdError(
        `Threshold must be at least ${THRESHOLD_CONSTANTS.MIN_THRESHOLD}`,
        'INVALID_THRESHOLD'
      );
    }

    if (participants > THRESHOLD_CONSTANTS.MAX_PARTICIPANTS) {
      throw new ThresholdError(
        `Participants cannot exceed ${THRESHOLD_CONSTANTS.MAX_PARTICIPANTS}`,
        'TOO_MANY_PARTICIPANTS'
      );
    }

    if (threshold > participants) {
      throw new ThresholdError(
        'Threshold cannot exceed number of participants',
        'THRESHOLD_EXCEEDS_PARTICIPANTS'
      );
    }

    this.threshold = threshold;
    this.participants = participants;
    this.polynomial = null;
    this.shares = [];
    this.commitments = null;
    this.publicKey = null;
  }

  generateShares(secret = null) {
    this.polynomial = new Polynomial(this.threshold - 1, secret);
    this.shares = this.polynomial.generateShares(this.participants);
    this.commitments = new FeldmanCommitments(this.polynomial);

    const secretBuffer = this.polynomial.getSecret().toBuffer('be', 32);
    this.publicKey = Buffer.from(
      secp256k1.getPublicKey(secretBuffer, true)
    );

    return {
      shares: this.shares.map(s => ({
        x: s.x.toString('hex'),
        y: s.y.toString('hex'),
        index: s.index
      })),
      commitments: this.commitments.getCommitments(),
      publicKey: this.publicKey
    };
  }

  verifyShare(share) {
    if (!this.commitments) {
      throw new ThresholdError('Commitments not initialized', 'NO_COMMITMENTS');
    }

    return this.commitments.verifyShare({
      x: new BN(share.x, 'hex'),
      y: new BN(share.y, 'hex')
    });
  }

  static generatePartialSignature(share, messageHash) {
    const k = new BN(randomBytes(32)).umod(CURVE_ORDER);
    const kBuffer = k.toBuffer('be', 32);
    const R = G.multiply(BigInt('0x' + kBuffer.toString('hex')));
    const r = new BN(R.toAffine().x.toString(16), 'hex').umod(CURVE_ORDER);

    if (r.isZero()) {
      throw new ThresholdError('Invalid nonce generated', 'ZERO_R');
    }

    const shareY = share.y instanceof BN ? share.y : new BN(share.y, 'hex');
    const hash = new BN(messageHash, 'hex');

    const s = k.invm(CURVE_ORDER)
      .mul(hash.add(r.mul(shareY)))
      .umod(CURVE_ORDER);

    return {
      r: r.toString('hex'),
      s: s.toString('hex'),
      R: Buffer.from(R.toRawBytes(true)),
      index: share.index
    };
  }

  static combinePartialSignatures(partialSigs, threshold) {
    if (partialSigs.length < threshold) {
      throw new ThresholdError(
        `Need at least ${threshold} signatures, got ${partialSigs.length}`,
        'INSUFFICIENT_SIGNATURES'
      );
    }

    const selectedSigs = partialSigs.slice(0, threshold);
    const xCoords = selectedSigs.map(s => new BN(s.index));

    let combinedS = new BN(0);

    for (let i = 0; i < selectedSigs.length; i++) {
      const li = Polynomial.lagrangeCoefficient(i, xCoords, new BN(0));
      const si = new BN(selectedSigs[i].s, 'hex');
      combinedS = combinedS.add(si.mul(li)).umod(CURVE_ORDER);
    }

    const r = new BN(selectedSigs[0].r, 'hex');

    return {
      r: r.toString('hex'),
      s: combinedS.toString('hex'),
      signature: Buffer.concat([
        r.toBuffer('be', 32),
        combinedS.toBuffer('be', 32)
      ])
    };
  }

  static verifyThresholdSignature(publicKey, messageHash, signature) {
    try {
      const r = signature.r instanceof BN ? signature.r : new BN(signature.r, 'hex');
      const s = signature.s instanceof BN ? signature.s : new BN(signature.s, 'hex');

      const hash = new BN(messageHash, 'hex');
      const sInv = s.invm(CURVE_ORDER);

      const u1 = hash.mul(sInv).umod(CURVE_ORDER);
      const u2 = r.mul(sInv).umod(CURVE_ORDER);

      const u1Buffer = u1.toBuffer('be', 32);
      const u2Buffer = u2.toBuffer('be', 32);

      const point1 = G.multiply(BigInt('0x' + u1Buffer.toString('hex')));
      const pubKeyPoint = secp256k1.ProjectivePoint.fromHex(publicKey);
      const point2 = pubKeyPoint.multiply(BigInt('0x' + u2Buffer.toString('hex')));

      const R = point1.add(point2);
      const recoveredR = new BN(R.toAffine().x.toString(16), 'hex').umod(CURVE_ORDER);

      return r.eq(recoveredR);
    } catch {
      return false;
    }
  }

  sign(messageHash) {
    if (!this.shares || this.shares.length < this.threshold) {
      throw new ThresholdError('Insufficient shares for signing', 'INSUFFICIENT_SHARES');
    }

    const partialSigs = this.shares
      .slice(0, this.threshold)
      .map(share => ThresholdSignature.generatePartialSignature(share, messageHash));

    return ThresholdSignature.combinePartialSignatures(partialSigs, this.threshold);
  }

  getPublicKey() {
    return this.publicKey;
  }

  getThresholdConfig() {
    return {
      threshold: this.threshold,
      participants: this.participants
    };
  }

  clear() {
    if (this.polynomial) {
      this.polynomial.clear();
    }
    this.shares = [];
    this.commitments = null;
    this.publicKey = null;
  }
}

export { ThresholdSignature, FeldmanCommitments, ThresholdError };
export default ThresholdSignature;
