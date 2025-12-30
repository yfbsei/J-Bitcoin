/**
 * @fileoverview Multi-Party Computation operations for threshold cryptography
 * @description Implements ADDSS, PROSS, and INVSS from Sections 2.2-2.4 of the nChain whitepaper.
 *              These operations allow computation on shared secrets without revealing them.
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 * @see Threshold-Signatures-whitepaper-nchain.pdf Sections 2.2, 2.3, 2.4
 */

import BN from 'bn.js';
import { Polynomial, CURVE_ORDER } from './polynomial.js';


/**
 * Error class for MPC operations
 */
class MPCError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'MPCError';
        this.code = code;
        this.details = details;
    }
}

/**
 * Section 2.2: Addition of Shared Secrets (ADDSS)
 * 
 * Given shares of two secrets a and b, computes a + b.
 * Each participant calculates ν_i = a_i + b_i, then interpolates.
 * 
 * @param {Array<{x: BN, y: BN}>} aShares - Shares of secret a
 * @param {Array<{x: BN, y: BN}>} bShares - Shares of secret b
 * @param {number} threshold - Required threshold (t+1)
 * @returns {BN} The sum a + b
 */
function ADDSS(aShares, bShares, threshold) {
    if (aShares.length < threshold || bShares.length < threshold) {
        throw new MPCError(
            `Need at least ${threshold} shares, got ${Math.min(aShares.length, bShares.length)}`,
            'INSUFFICIENT_SHARES'
        );
    }

    // Step 3: Each participant calculates additive share ν_i = a_i + b_i
    const additiveShares = [];
    for (let i = 0; i < Math.min(aShares.length, bShares.length); i++) {
        const a_i = aShares[i].y instanceof BN ? aShares[i].y : new BN(aShares[i].y);
        const b_i = bShares[i].y instanceof BN ? bShares[i].y : new BN(bShares[i].y);
        const x = aShares[i].x instanceof BN ? aShares[i].x : new BN(aShares[i].x);

        additiveShares.push({
            x: x,
            y: a_i.add(b_i).umod(CURVE_ORDER)
        });
    }

    // Step 5: Interpolate over at least (t+1) shares to get ν = a + b
    const sharesToUse = additiveShares.slice(0, threshold);
    return Polynomial.interpolate(sharesToUse, new BN(0));
}

/**
 * Calculate additive shares without interpolation
 * Returns shares that can be used for further MPC operations
 * 
 * @param {Array<{x: BN, y: BN}>} aShares - Shares of secret a
 * @param {Array<{x: BN, y: BN}>} bShares - Shares of secret b
 * @returns {Array<{x: BN, y: BN}>} Additive shares ν_i = a_i + b_i
 */
function computeAdditiveShares(aShares, bShares) {
    const shares = [];
    for (let i = 0; i < Math.min(aShares.length, bShares.length); i++) {
        const a_i = aShares[i].y instanceof BN ? aShares[i].y : new BN(aShares[i].y);
        const b_i = bShares[i].y instanceof BN ? bShares[i].y : new BN(bShares[i].y);
        const x = aShares[i].x instanceof BN ? aShares[i].x : new BN(aShares[i].x);

        shares.push({
            x: x,
            y: a_i.add(b_i).umod(CURVE_ORDER)
        });
    }
    return shares;
}

/**
 * Section 2.3: Product of Shared Secrets (PROSS)
 * 
 * Given shares of two secrets a and b, computes a * b.
 * Each participant calculates μ_i = a_i * b_i, then interpolates.
 * 
 * NOTE: The product polynomial has order 2t, so 2t+1 shares are needed!
 * 
 * @param {Array<{x: BN, y: BN}>} aShares - Shares of secret a (order t polynomial)
 * @param {Array<{x: BN, y: BN}>} bShares - Shares of secret b (order t polynomial)
 * @param {number} productThreshold - Required threshold for product (2t+1)
 * @returns {BN} The product a * b
 */
function PROSS(aShares, bShares, productThreshold) {
    if (aShares.length < productThreshold || bShares.length < productThreshold) {
        throw new MPCError(
            `PROSS needs at least ${productThreshold} shares (2t+1), got ${Math.min(aShares.length, bShares.length)}`,
            'INSUFFICIENT_SHARES'
        );
    }

    // Step 3: Each participant calculates multiplicative share μ_i = a_i * b_i
    const multiplicativeShares = [];
    for (let i = 0; i < productThreshold; i++) {
        const a_i = aShares[i].y instanceof BN ? aShares[i].y : new BN(aShares[i].y);
        const b_i = bShares[i].y instanceof BN ? bShares[i].y : new BN(bShares[i].y);
        const x = aShares[i].x instanceof BN ? aShares[i].x : new BN(aShares[i].x);

        multiplicativeShares.push({
            x: x,
            y: a_i.mul(b_i).umod(CURVE_ORDER)
        });
    }

    // Step 5: Interpolate over 2t+1 shares to get μ = a * b
    return Polynomial.interpolate(multiplicativeShares, new BN(0));
}

/**
 * Calculate multiplicative shares without interpolation
 * 
 * @param {Array<{x: BN, y: BN}>} aShares - Shares of secret a
 * @param {Array<{x: BN, y: BN}>} bShares - Shares of secret b
 * @returns {Array<{x: BN, y: BN}>} Multiplicative shares μ_i = a_i * b_i
 */
function computeMultiplicativeShares(aShares, bShares) {
    const shares = [];
    for (let i = 0; i < Math.min(aShares.length, bShares.length); i++) {
        const a_i = aShares[i].y instanceof BN ? aShares[i].y : new BN(aShares[i].y);
        const b_i = bShares[i].y instanceof BN ? bShares[i].y : new BN(bShares[i].y);
        const x = aShares[i].x instanceof BN ? aShares[i].x : new BN(aShares[i].x);

        shares.push({
            x: x,
            y: a_i.mul(b_i).umod(CURVE_ORDER)
        });
    }
    return shares;
}

/**
 * Section 2.4: Inverse of a Shared Secret (INVSS)
 * 
 * Computes shares of a^-1 using a blinding value b.
 * 
 * Process:
 * 1. Calculate μ = a * b using PROSS
 * 2. Calculate μ^-1 = (a * b)^-1 (this is known to all)
 * 3. Each participant calculates a_i^-1 = μ^-1 * b_i
 * 
 * The inverse shares can then be used in further calculations.
 * Interpolating over them would give a^-1, but we typically use them
 * in products like k^-1 * (e + a*r).
 * 
 * @param {Array<{x: BN, y: BN}>} aShares - Shares of secret a
 * @param {Array<{x: BN, y: BN}>} bShares - Shares of blinding value b
 * @param {number} t - Threshold degree (polynomials are order t)
 * @returns {{mu: BN, muInverse: BN, inverseShares: Array<{x: BN, y: BN}>}} INVSS result
 */
function INVSS(aShares, bShares, t) {
    const productThreshold = 2 * t + 1;

    if (aShares.length < productThreshold || bShares.length < productThreshold) {
        throw new MPCError(
            `INVSS needs at least ${productThreshold} shares (2t+1), got ${Math.min(aShares.length, bShares.length)}`,
            'INSUFFICIENT_SHARES'
        );
    }

    // Step 1: Calculate product μ = a * b using PROSS
    const mu = PROSS(aShares, bShares, productThreshold);

    // Step 2: Calculate modular inverse μ^-1 = (ab)^-1
    const muInverse = mu.invm(CURVE_ORDER);

    // Step 3: Each participant calculates inverse share a_i^-1 = μ^-1 * b_i
    const inverseShares = [];
    for (let i = 0; i < aShares.length; i++) {
        const b_i = bShares[i].y instanceof BN ? bShares[i].y : new BN(bShares[i].y);
        const x = aShares[i].x instanceof BN ? aShares[i].x : new BN(aShares[i].x);

        // a_i^-1 = μ^-1 * b_i
        inverseShares.push({
            x: x,
            y: muInverse.mul(b_i).umod(CURVE_ORDER)
        });
    }

    return {
        mu,
        muInverse,
        inverseShares
    };
}

/**
 * Generate ephemeral key inverse shares for threshold signing
 * 
 * This implements Section 4.2 of the whitepaper:
 * 1. Generate shared ephemeral key k using JVRSS
 * 2. Generate blinding value b using JVRSS
 * 3. Calculate k^-1 shares using INVSS
 * 4. Calculate r = x mod n from k·G
 * 
 * @param {number} n - Number of participants
 * @param {number} t - Threshold degree
 * @returns {{r: BN, inverseKShares: Array, kJVRSS: JVRSS, bJVRSS: JVRSS}} Ephemeral key data
 */
function generateEphemeralKeyShares(n, t) {


    // Step 1: Generate ephemeral key k using JVRSS
    const kJVRSS = new JVRSS(n, t);
    kJVRSS.runProtocol();
    const kShares = kJVRSS.getSharesForInterpolation();

    // Generate blinding value b using JVRSS
    const bJVRSS = new JVRSS(n, t);
    bJVRSS.runProtocol();
    const bShares = bJVRSS.getSharesForInterpolation();

    // Step 2: Calculate k^-1 shares using INVSS
    const { inverseShares: inverseKShares } = INVSS(kShares, bShares, t);

    // Step 3: Calculate r from k·G using obfuscated coefficients
    // (x, y) = Σ (k_i0 · G)
    let kG = null;
    for (let i = 1; i <= n; i++) {
        const coeffs = kJVRSS.obfuscatedCoefficients.get(i);
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

    return {
        r,
        inverseKShares,
        kJVRSS,
        bJVRSS
    };
}

export {
    ADDSS,
    PROSS,
    INVSS,
    computeAdditiveShares,
    computeMultiplicativeShares,
    generateEphemeralKeyShares,
    MPCError
};

