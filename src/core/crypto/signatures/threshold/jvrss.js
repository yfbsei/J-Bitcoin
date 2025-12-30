/**
 * @fileoverview Joint Verifiable Random Secret Sharing (JVRSS) implementation
 * @description Implements the JVRSS protocol from Section 2.1 of the nChain whitepaper
 *              for distributed generation of shared secrets with Feldman verification.
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 * @see Threshold-Signatures-whitepaper-nchain.pdf Section 2.1
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import BN from 'bn.js';
import { Participant } from './participant.js';
import { Polynomial, CURVE_ORDER } from './polynomial.js';

/** secp256k1 generator point G */
const G = secp256k1.ProjectivePoint.BASE;

/**
 * Error class for JVRSS operations
 */
class JVRSSError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'JVRSSError';
        this.code = code;
        this.details = details;
    }
}

/**
 * JVRSS class orchestrating the distributed key generation protocol
 */
class JVRSS {
    /**
     * Create a JVRSS instance
     * @param {number} n - Total number of participants (N)
     * @param {number} t - Threshold degree (t+1 shares needed to reconstruct)
     */
    constructor(n, t) {
        if (n < 2) {
            throw new JVRSSError('Need at least 2 participants', 'INSUFFICIENT_PARTICIPANTS');
        }
        if (t < 1) {
            throw new JVRSSError('Threshold must be at least 1', 'INVALID_THRESHOLD');
        }
        if (t >= n) {
            throw new JVRSSError('Threshold must be less than number of participants', 'THRESHOLD_TOO_HIGH');
        }

        this.n = n;
        this.t = t;
        this.participants = [];
        this.obfuscatedCoefficients = new Map();
        this.sharedPublicKey = null;

        // Create participants
        for (let i = 1; i <= n; i++) {
            this.participants.push(new Participant(i, t));
        }
    }

    /**
     * Get participant by index (1-indexed)
     * @param {number} index - Participant index
     * @returns {Participant} The participant
     */
    getParticipant(index) {
        return this.participants[index - 1];
    }

    /**
     * Step 1: Each participant generates their private polynomial
     */
    generatePolynomials() {
        for (const participant of this.participants) {
            participant.generatePolynomial();
        }
    }

    /**
     * Step 2: Distribute polynomial points securely between participants
     * f_i(j) is sent from participant i to participant j
     */
    distributePolynomialPoints() {
        for (const sender of this.participants) {
            for (const receiver of this.participants) {
                if (sender.index === receiver.index) continue;

                // Sender evaluates f_i(j) and sends to receiver
                const point = sender.getPolynomialPointFor(receiver.index);
                receiver.receivePolynomialPoint(point.fromIndex, point.value);
            }
        }
    }

    /**
     * Step 3: Each participant calculates their key share
     * a_i = Σ f_j(i) for all j
     */
    calculateShares() {
        for (const participant of this.participants) {
            participant.calculateKeyShare(this.n);
        }
    }

    /**
     * Step 4: Each participant broadcasts obfuscated coefficients
     * Broadcasts a_ik · G for verification
     */
    broadcastObfuscatedCoefficients() {
        for (const participant of this.participants) {
            const coeffs = participant.getObfuscatedCoefficients();
            this.obfuscatedCoefficients.set(participant.index, coeffs);
        }
    }

    /**
     * Step 5: Each participant verifies received polynomial points
     * @returns {{valid: boolean, invalidPairs: Array}} Verification result
     */
    verifyAllShares() {
        const invalidPairs = [];

        for (const verifier of this.participants) {
            for (const sender of this.participants) {
                if (verifier.index === sender.index) continue;

                const pointValue = verifier.receivedPoints.get(sender.index);
                const obfuscatedCoeffs = this.obfuscatedCoefficients.get(sender.index);

                if (!verifier.verifyPolynomialPoint(sender.index, pointValue, obfuscatedCoeffs)) {
                    invalidPairs.push({
                        verifier: verifier.index,
                        sender: sender.index
                    });
                }
            }
        }

        return {
            valid: invalidPairs.length === 0,
            invalidPairs
        };
    }

    /**
     * Calculate the shared public key using Method 2
     * a · G = Σ (a_i0 · G)
     * @returns {Buffer} Shared public key (compressed)
     */
    calculateSharedPublicKey() {
        // Sum the zeroth-order obfuscated coefficients
        let sharedPoint = null;

        for (let i = 1; i <= this.n; i++) {
            const coeffs = this.obfuscatedCoefficients.get(i);
            const zerothCoeff = secp256k1.ProjectivePoint.fromHex(coeffs[0]);

            if (sharedPoint === null) {
                sharedPoint = zerothCoeff;
            } else {
                sharedPoint = sharedPoint.add(zerothCoeff);
            }
        }

        this.sharedPublicKey = Buffer.from(sharedPoint.toRawBytes(true));
        return this.sharedPublicKey;
    }

    /**
     * Run the complete JVRSS protocol
     * @returns {{shares: Array, publicKey: Buffer, verified: boolean}} Protocol result
     */
    runProtocol() {
        // Step 1: Generate polynomials
        this.generatePolynomials();

        // Step 2: Distribute polynomial points
        this.distributePolynomialPoints();

        // Step 3: Calculate key shares
        this.calculateShares();

        // Step 4: Broadcast obfuscated coefficients
        this.broadcastObfuscatedCoefficients();

        // Step 5: Verify all shares
        const verification = this.verifyAllShares();
        if (!verification.valid) {
            throw new JVRSSError(
                'Share verification failed',
                'VERIFICATION_FAILED',
                { invalidPairs: verification.invalidPairs }
            );
        }

        // Calculate shared public key
        const publicKey = this.calculateSharedPublicKey();

        // Collect shares
        const shares = this.participants.map(p => ({
            index: p.index,
            keyShare: p.getKeyShare(),
            publicKeyShare: p.getKeySharePublicKey()
        }));

        return {
            shares,
            publicKey,
            verified: true
        };
    }

    /**
     * Get shares for interpolation (useful for product/inverse calculations)
     * @returns {Array<{x: BN, y: BN}>} Array of shares in interpolation format
     */
    getSharesForInterpolation() {
        return this.participants.map(p => ({
            x: new BN(p.index),
            y: p.getKeyShare()
        }));
    }

    /**
     * Reconstruct the secret (for testing/verification only)
     * WARNING: In production, the secret should never be reconstructed!
     * @returns {BN} The reconstructed shared secret
     */
    reconstructSecret() {
        const shares = this.getSharesForInterpolation();
        // Only need t+1 shares
        const minShares = shares.slice(0, this.t + 1);
        return Polynomial.reconstructSecret(minShares);
    }

    /**
     * Clear all sensitive data
     */
    clear() {
        for (const participant of this.participants) {
            participant.clear();
        }
        this.obfuscatedCoefficients.clear();
        this.sharedPublicKey = null;
    }
}

/**
 * Run a standalone JVRSS protocol and return results
 * Convenience function for generating a shared secret
 * @param {number} n - Number of participants
 * @param {number} t - Threshold
 * @returns {Object} JVRSS result with shares and public key
 */
function runJVRSS(n, t) {
    const jvrss = new JVRSS(n, t);
    return {
        ...jvrss.runProtocol(),
        jvrss
    };
}

export { JVRSS, JVRSSError, runJVRSS };
export default JVRSS;

