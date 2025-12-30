/**
 * @fileoverview Threshold Signature Scheme implementation
 * @description Full implementation of the nChain Threshold Signature protocol
 *              as specified in Section 4 of the whitepaper.
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 * @see Threshold-Signatures-whitepaper-nchain.pdf Section 4
 */

import { createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import BN from 'bn.js';
import { Polynomial, CURVE_ORDER } from './polynomial.js';
import { JVRSS } from './jvrss.js';
import { INVSS } from './mpc-operations.js';


/** secp256k1 generator point G */
const G = secp256k1.ProjectivePoint.BASE;

/**
 * Error class for threshold signature operations
 */
class ThresholdSignatureError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'ThresholdSignatureError';
    this.code = code;
    this.details = details;
  }
}

/**
 * Threshold Signature Scheme class
 * 
 * Implements a (t+1, n) threshold signature scheme where:
 * - n participants hold key shares
 * - t+1 participants can reconstruct the secret (but we don't)
 * - 2t+1 participants are required to create a signature (due to INVSS)
 * 
 * This follows the nChain whitepaper's protocol exactly.
 */
class ThresholdSignatureScheme {
  /**
   * Create a threshold signature scheme
   * @param {number} n - Total participants (N)
   * @param {number} t - Threshold degree (t+1 shares to reconstruct, 2t+1 to sign)
   */
  constructor(n, t) {
    // Validate: need 2t+1 <= n for signing
    if (2 * t + 1 > n) {
      throw new ThresholdSignatureError(
        `Signing requires 2t+1=${2 * t + 1} participants, but n=${n}`,
        'INSUFFICIENT_PARTICIPANTS'
      );
    }

    this.n = n;
    this.t = t;
    this.signingThreshold = 2 * t + 1;
    this.reconstructionThreshold = t + 1;

    // Private key JVRSS instance
    this.privateKeyJVRSS = null;

    // Shared public key (a · G)
    this.sharedPublicKey = null;

    // Private key shares (a_i for each participant)
    this.privateKeyShares = [];

    // Pre-computed ephemeral keys: [{r, inverseKShares, kJVRSS, bJVRSS}, ...]
    this.ephemeralKeys = [];
  }

  /**
   * Section 4.1: Generate shared private key using JVRSS
   * All participants run JVRSS to create shared private key a
   * @returns {Buffer} Shared public key
   */
  generateSharedPrivateKey() {
    this.privateKeyJVRSS = new JVRSS(this.n, this.t);
    const result = this.privateKeyJVRSS.runProtocol();

    this.sharedPublicKey = result.publicKey;
    this.privateKeyShares = result.shares;

    return this.sharedPublicKey;
  }

  /**
   * Section 4.2: Generate ephemeral key shares
   * Pre-compute (r, k_i^-1) tuples for efficient signing
   * @param {number} count - Number of ephemeral keys to generate
   */
  generateEphemeralKeys(count = 1) {
    for (let i = 0; i < count; i++) {
      // Generate ephemeral key k using JVRSS
      const kJVRSS = new JVRSS(this.n, this.t);
      kJVRSS.runProtocol();
      const kShares = kJVRSS.getSharesForInterpolation();

      // Generate blinding value b using JVRSS
      const bJVRSS = new JVRSS(this.n, this.t);
      bJVRSS.runProtocol();
      const bShares = bJVRSS.getSharesForInterpolation();

      // Calculate k^-1 shares using INVSS
      const { inverseShares: inverseKShares } = INVSS(kShares, bShares, this.t);

      // Calculate r from k·G using obfuscated coefficients
      // (x, y) = Σ (k_i0 · G)
      let kG = null;
      for (let j = 1; j <= this.n; j++) {
        const coeffs = kJVRSS.obfuscatedCoefficients.get(j);
        const zerothCoeff = secp256k1.ProjectivePoint.fromHex(coeffs[0]);

        if (kG === null) {
          kG = zerothCoeff;
        } else {
          kG = kG.add(zerothCoeff);
        }
      }

      // r = x mod n
      const affine = kG.toAffine();
      const r = new BN(affine.x.toString(16), 'hex').umod(CURVE_ORDER);

      // Check r is non-zero (very unlikely but must check)
      if (r.isZero()) {
        // Regenerate (recursive, but extremely rare)
        i--;
        continue;
      }

      this.ephemeralKeys.push({
        r,
        inverseKShares,
        used: false
      });
    }
  }

  /**
   * Get next unused ephemeral key
   * @returns {{r: BN, inverseKShares: Array}|null} Next ephemeral key
   */
  getNextEphemeralKey() {
    const key = this.ephemeralKeys.find(k => !k.used);
    if (key) {
      key.used = true;
      return { r: key.r, inverseKShares: key.inverseKShares };
    }
    return null;
  }

  /**
   * Section 4.3: Generate threshold signature
   * 
   * @param {Buffer|string} messageHash - 32-byte message hash (e)
   * @param {number[]} participantIndices - Indices of signing participants (1-indexed)
   * @returns {{r: string, s: string, signature: Buffer}} Signature
   */
  sign(messageHash, participantIndices = null) {
    // Default to first 2t+1 participants
    if (!participantIndices) {
      participantIndices = [];
      for (let i = 1; i <= this.signingThreshold; i++) {
        participantIndices.push(i);
      }
    }

    if (participantIndices.length < this.signingThreshold) {
      throw new ThresholdSignatureError(
        `Need ${this.signingThreshold} participants (2t+1), got ${participantIndices.length}`,
        'INSUFFICIENT_SIGNERS'
      );
    }

    // Get message hash as BN
    let e;
    if (typeof messageHash === 'string') {
      e = new BN(messageHash, 'hex');
    } else {
      e = new BN(messageHash);
    }

    // Step 2: Get ephemeral key (auto-generate if needed)
    let ephemeralKey = this.getNextEphemeralKey();
    if (!ephemeralKey) {
      this.generateEphemeralKeys(1);
      ephemeralKey = this.getNextEphemeralKey();
    }

    const { r, inverseKShares } = ephemeralKey;

    // Step 4: Each participant generates signature share
    // s_i = k_i^-1 * (e + a_i * r)
    const signatureShares = [];

    for (const idx of participantIndices) {
      // Get private key share a_i
      const shareData = this.privateKeyShares.find(s => s.index === idx);
      if (!shareData) {
        throw new ThresholdSignatureError(
          `No key share for participant ${idx}`,
          'MISSING_KEY_SHARE'
        );
      }
      const a_i = shareData.keyShare;

      // Get inverse ephemeral share k_i^-1
      const kInvShare = inverseKShares.find(s => s.x.eqn(idx));
      if (!kInvShare) {
        throw new ThresholdSignatureError(
          `No ephemeral share for participant ${idx}`,
          'MISSING_EPHEMERAL_SHARE'
        );
      }
      const k_i_inv = kInvShare.y;

      // s_i = k_i^-1 * (e + a_i * r) mod n
      const aiR = a_i.mul(r).umod(CURVE_ORDER);
      const ePlusAiR = e.add(aiR).umod(CURVE_ORDER);
      const s_i = k_i_inv.mul(ePlusAiR).umod(CURVE_ORDER);

      signatureShares.push({
        x: new BN(idx),
        y: s_i,
        index: idx
      });
    }

    // Step 6: Combine signature shares via Lagrange interpolation
    // s = interpolate(s_1, ..., s_{2t+1})
    const s = Polynomial.interpolate(signatureShares, new BN(0));

    // Enforce low-S (BIP-62)
    let sFinal = s;
    const halfOrder = CURVE_ORDER.shrn(1);
    if (s.gt(halfOrder)) {
      sFinal = CURVE_ORDER.sub(s);
    }

    // Create signature buffer
    const rBuffer = r.toArrayLike(Buffer, 'be', 32);
    const sBuffer = sFinal.toArrayLike(Buffer, 'be', 32);
    const signature = Buffer.concat([rBuffer, sBuffer]);

    return {
      r: r.toString('hex').padStart(64, '0'),
      s: sFinal.toString('hex').padStart(64, '0'),
      signature
    };
  }

  /**
   * Verify a signature using standard ECDSA verification
   * @param {Buffer|string} messageHash - 32-byte message hash
   * @param {{r: string, s: string}|Buffer} signature - Signature to verify
   * @param {Buffer} publicKey - Public key (optional, uses shared key if not provided)
   * @returns {boolean} True if signature is valid
   */
  verify(messageHash, signature, publicKey = null) {
    const pubKey = publicKey || this.sharedPublicKey;
    if (!pubKey) {
      throw new ThresholdSignatureError('No public key available', 'NO_PUBLIC_KEY');
    }

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

      // Get message hash as BN
      let e;
      if (typeof messageHash === 'string') {
        e = new BN(messageHash, 'hex');
      } else {
        e = new BN(messageHash);
      }

      // ECDSA verification:
      // 1. Calculate s^-1
      const sInv = s.invm(CURVE_ORDER);

      // 2. j1 = e * s^-1 mod n
      const j1 = e.mul(sInv).umod(CURVE_ORDER);

      // 3. j2 = r * s^-1 mod n
      const j2 = r.mul(sInv).umod(CURVE_ORDER);

      // 4. Q = j1·G + j2·(a·G)
      const j1Buffer = j1.toArrayLike(Buffer, 'be', 32);
      const j2Buffer = j2.toArrayLike(Buffer, 'be', 32);

      const point1 = G.multiply(BigInt('0x' + j1Buffer.toString('hex')));
      const pubKeyPoint = secp256k1.ProjectivePoint.fromHex(pubKey);
      const point2 = pubKeyPoint.multiply(BigInt('0x' + j2Buffer.toString('hex')));

      const Q = point1.add(point2);

      // 5. Check Q != O (point at infinity)
      if (Q.equals(secp256k1.ProjectivePoint.ZERO)) {
        return false;
      }

      // 6. u = Q.x mod n, verify u == r
      const u = new BN(Q.toAffine().x.toString(16), 'hex').umod(CURVE_ORDER);
      return r.eq(u);
    } catch {
      return false;
    }
  }

  /**
   * Sign a message (with Bitcoin message prefix and double SHA256)
   * @param {string|Buffer} message - Message to sign
   * @param {number[]} participantIndices - Signing participants
   * @returns {Object} Signature
   */
  signMessage(message, participantIndices = null) {
    const messageBuffer = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
    const prefix = Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8');
    const lengthBuffer = Buffer.from([messageBuffer.length]);

    const fullMessage = Buffer.concat([prefix, lengthBuffer, messageBuffer]);
    const messageHash = createHash('sha256')
      .update(createHash('sha256').update(fullMessage).digest())
      .digest();

    return this.sign(messageHash, participantIndices);
  }

  /**
   * Get the shared public key
   * @returns {Buffer} Shared public key
   */
  getPublicKey() {
    return this.sharedPublicKey;
  }

  /**
   * Get configuration details
   * @returns {Object} Configuration
   */
  getConfig() {
    return {
      n: this.n,
      t: this.t,
      reconstructionThreshold: this.reconstructionThreshold,
      signingThreshold: this.signingThreshold,
      availableEphemeralKeys: this.ephemeralKeys.filter(k => !k.used).length
    };
  }

  /**
   * Clear all sensitive data
   */
  clear() {
    if (this.privateKeyJVRSS) {
      this.privateKeyJVRSS.clear();
    }
    this.privateKeyShares = [];
    this.ephemeralKeys = [];
    this.sharedPublicKey = null;
  }
}

/**
 * Create and initialize a threshold signature scheme
 * Convenience function for quick setup
 * @param {number} n - Total participants
 * @param {number} t - Threshold degree
 * @param {number} ephemeralKeyCount - Number of ephemeral keys to pre-generate
 * @returns {ThresholdSignatureScheme} Initialized scheme
 */
function createThresholdScheme(n, t, ephemeralKeyCount = 5) {
  const scheme = new ThresholdSignatureScheme(n, t);
  scheme.generateSharedPrivateKey();
  scheme.generateEphemeralKeys(ephemeralKeyCount);
  return scheme;
}

export { ThresholdSignatureScheme, ThresholdSignatureError, createThresholdScheme };
export default ThresholdSignatureScheme;
