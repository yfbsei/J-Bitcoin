/**
 * @fileoverview Participant class for threshold signature scheme
 * @description Represents an individual participant in the TSS protocol,
 *              managing their private polynomial, key shares, and signature generation.
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 * @see Threshold-Signatures-whitepaper-nchain.pdf Sections 2.1, 4.3
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import BN from 'bn.js';
import { Polynomial, CURVE_ORDER } from './polynomial.js';

/** secp256k1 generator point G */
const G = secp256k1.ProjectivePoint.BASE;

/**
 * Error class for participant operations
 */
class ParticipantError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'ParticipantError';
        this.code = code;
        this.details = details;
    }
}

/**
 * Participant class representing a single party in the threshold scheme
 */
class Participant {
    /**
     * Create a new participant
     * @param {number} index - Unique participant label i (1-indexed, must be > 0)
     * @param {number} threshold - Threshold t (t+1 shares needed to reconstruct)
     */
    constructor(index, threshold) {
        if (index <= 0) {
            throw new ParticipantError('Participant index must be positive', 'INVALID_INDEX');
        }
        if (threshold < 1) {
            throw new ParticipantError('Threshold must be at least 1', 'INVALID_THRESHOLD');
        }

        this.index = index;
        this.threshold = threshold;

        // Private polynomial f_i(x) of degree t
        this.privatePolynomial = null;

        // Private key share a_i = Σ f_j(i) for all participants j
        this.privateKeyShare = null;

        // Blinding value share b_i for INVSS
        this.blindingShare = null;

        // Pre-computed ephemeral key inverse shares (r, k_i^-1)
        this.ephemeralKeys = [];

        // Obfuscated coefficients a_ik · G for verification
        this.obfuscatedCoefficients = null;

        // Received polynomial points from other participants
        this.receivedPoints = new Map();
    }

    /**
     * Step 1 of JVRSS: Generate private polynomial f_i(x) with random coefficients
     * f_i(x) = a_i0 + a_i1*x + ... + a_it*x^t
     * @param {BN|null} secret - Optional secret for a_i0 (typically random)
     */
    generatePolynomial(secret = null) {
        this.privatePolynomial = new Polynomial(this.threshold, secret);
    }

    /**
     * Evaluate private polynomial at point x
     * Used for sending f_i(j) to participant j
     * @param {number} x - Evaluation point
     * @returns {BN} f_i(x)
     */
    evaluateAt(x) {
        if (!this.privatePolynomial) {
            throw new ParticipantError('Private polynomial not generated', 'NO_POLYNOMIAL');
        }
        return this.privatePolynomial.evaluate(x);
    }

    /**
     * Get polynomial point to send to participant j
     * @param {number} j - Target participant index
     * @returns {{fromIndex: number, toIndex: number, value: BN}} Point data
     */
    getPolynomialPointFor(j) {
        return {
            fromIndex: this.index,
            toIndex: j,
            value: this.evaluateAt(j)
        };
    }

    /**
     * Receive polynomial point from another participant
     * Store f_j(i) where j is the sender and i is this participant
     * @param {number} fromIndex - Sender participant index j
     * @param {BN} value - f_j(i) value
     */
    receivePolynomialPoint(fromIndex, value) {
        const valueBN = value instanceof BN ? value : new BN(value);
        this.receivedPoints.set(fromIndex, valueBN);
    }

    /**
     * Step 3 of JVRSS: Calculate private key share
     * a_i = Σ f_j(i) for all participants j
     * @param {number} totalParticipants - Total number of participants N
     */
    calculateKeyShare(totalParticipants) {
        // Include our own point f_i(i)
        let sum = this.evaluateAt(this.index);

        // Add all received points f_j(i)
        for (let j = 1; j <= totalParticipants; j++) {
            if (j === this.index) continue;

            const point = this.receivedPoints.get(j);
            if (!point) {
                throw new ParticipantError(
                    `Missing polynomial point from participant ${j}`,
                    'MISSING_POINT'
                );
            }
            sum = sum.add(point).umod(CURVE_ORDER);
        }

        this.privateKeyShare = sum;
        return this.privateKeyShare;
    }

    /**
     * Step 4 of JVRSS: Get obfuscated coefficients for verification
     * Returns a_ik · G for k = 0, ..., t
     * @returns {Buffer[]} Array of compressed public key points
     */
    getObfuscatedCoefficients() {
        if (!this.privatePolynomial) {
            throw new ParticipantError('Private polynomial not generated', 'NO_POLYNOMIAL');
        }

        const coeffs = this.privatePolynomial.getCoefficients();
        this.obfuscatedCoefficients = coeffs.map(coeff => {
            const coeffBuffer = coeff.toArrayLike(Buffer, 'be', 32);
            const point = G.multiply(BigInt('0x' + coeffBuffer.toString('hex')));
            return Buffer.from(point.toRawBytes(true));
        });

        return this.obfuscatedCoefficients;
    }

    /**
     * Step 5 of JVRSS: Verify a polynomial point from participant j
     * Check that f_j(i) · G == Σ i^k * (a_jk · G)
     * @param {number} fromIndex - Sender participant index j
     * @param {BN} pointValue - f_j(i) received value
     * @param {Buffer[]} obfuscatedCoeffs - Obfuscated coefficients a_jk · G
     * @returns {boolean} True if verification passes
     */
    verifyPolynomialPoint(fromIndex, pointValue, obfuscatedCoeffs) {
        try {
            // Calculate expected: Σ i^k * (a_jk · G) for k = 0, ..., t
            let expectedPoint = secp256k1.ProjectivePoint.fromHex(obfuscatedCoeffs[0]);
            let iPower = new BN(this.index);

            for (let k = 1; k < obfuscatedCoeffs.length; k++) {
                const coeffPoint = secp256k1.ProjectivePoint.fromHex(obfuscatedCoeffs[k]);
                const scalar = BigInt('0x' + iPower.toArrayLike(Buffer, 'be', 32).toString('hex'));
                const term = coeffPoint.multiply(scalar);
                expectedPoint = expectedPoint.add(term);
                iPower = iPower.mul(new BN(this.index)).umod(CURVE_ORDER);
            }

            // Calculate actual: f_j(i) · G
            const pointBuffer = pointValue.toArrayLike(Buffer, 'be', 32);
            const actualPoint = G.multiply(BigInt('0x' + pointBuffer.toString('hex')));

            return expectedPoint.equals(actualPoint);
        } catch {
            return false;
        }
    }

    /**
     * Get public key corresponding to this participant's key share
     * @returns {Buffer} a_i · G compressed
     */
    getKeySharePublicKey() {
        if (!this.privateKeyShare) {
            throw new ParticipantError('Key share not calculated', 'NO_KEY_SHARE');
        }

        const shareBuffer = this.privateKeyShare.toArrayLike(Buffer, 'be', 32);
        const point = G.multiply(BigInt('0x' + shareBuffer.toString('hex')));
        return Buffer.from(point.toRawBytes(true));
    }

    /**
     * Store an ephemeral key for later signing
     * @param {BN} r - The r value (x-coordinate of k·G mod n)
     * @param {BN} inverseKShare - This participant's inverse ephemeral share k_i^-1
     */
    storeEphemeralKey(r, inverseKShare) {
        this.ephemeralKeys.push({
            r: r.clone(),
            inverseKShare: inverseKShare.clone(),
            used: false
        });
    }

    /**
     * Get next unused ephemeral key
     * @returns {{r: BN, inverseKShare: BN}|null} Next ephemeral key or null if none available
     */
    getNextEphemeralKey() {
        const key = this.ephemeralKeys.find(k => !k.used);
        if (key) {
            key.used = true;
            return { r: key.r, inverseKShare: key.inverseKShare };
        }
        return null;
    }

    /**
     * Section 4.3: Generate signature share s_i
     * s_i = k_i^-1 * (e + a_i * r) mod n
     * @param {BN} r - The r value from ephemeral key
     * @param {BN} e - Message hash
     * @param {BN} inverseKShare - k_i^-1 share
     * @returns {{r: BN, s: BN, index: number}} Signature share
     */
    generateSignatureShare(r, e, inverseKShare) {
        if (!this.privateKeyShare) {
            throw new ParticipantError('Key share not calculated', 'NO_KEY_SHARE');
        }

        const rBN = r instanceof BN ? r : new BN(r);
        const eBN = e instanceof BN ? e : new BN(e);
        const kInvBN = inverseKShare instanceof BN ? inverseKShare : new BN(inverseKShare);

        // s_i = k_i^-1 * (e + a_i * r) mod n
        const aiR = this.privateKeyShare.mul(rBN).umod(CURVE_ORDER);
        const ePlusAiR = eBN.add(aiR).umod(CURVE_ORDER);
        const si = kInvBN.mul(ePlusAiR).umod(CURVE_ORDER);

        return {
            r: rBN,
            s: si,
            index: this.index
        };
    }

    /**
     * Get the private key share value
     * @returns {BN} The key share a_i
     */
    getKeyShare() {
        return this.privateKeyShare ? this.privateKeyShare.clone() : null;
    }

    /**
     * Set a blinding share for INVSS operations
     * @param {BN} blindingShare - The blinding value share b_i
     */
    setBlindingShare(blindingShare) {
        this.blindingShare = blindingShare instanceof BN ? blindingShare.clone() : new BN(blindingShare);
    }

    /**
     * Get blinding share
     * @returns {BN|null} The blinding share or null
     */
    getBlindingShare() {
        return this.blindingShare ? this.blindingShare.clone() : null;
    }

    /**
     * Clear all sensitive data
     */
    clear() {
        if (this.privatePolynomial) {
            this.privatePolynomial.clear();
        }
        this.privateKeyShare = null;
        this.blindingShare = null;
        this.ephemeralKeys = [];
        this.receivedPoints.clear();
        this.obfuscatedCoefficients = null;
    }
}

export { Participant, ParticipantError };
export default Participant;

