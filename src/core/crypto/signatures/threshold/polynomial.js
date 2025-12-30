/**
 * @fileoverview Polynomial operations for threshold cryptography
 * @description Implements polynomial arithmetic over finite fields for Shamir's Secret Sharing
 *              and Lagrange interpolation as specified in the nChain TSS whitepaper.
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 * @see Threshold-Signatures-whitepaper-nchain.pdf Section 2.1
 */

import { randomBytes } from 'node:crypto';
import BN from 'bn.js';
import { CRYPTO_CONSTANTS } from '../../../constants.js';

/** secp256k1 curve order n */
const CURVE_ORDER = new BN(CRYPTO_CONSTANTS.SECP256K1_ORDER, 'hex');

/**
 * Error class for polynomial operations
 */
class PolynomialError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'PolynomialError';
    this.code = code;
    this.details = details;
  }
}

/**
 * Generate a cryptographically secure random element in Z_n
 * @param {number} bytes - Number of bytes for randomness
 * @returns {BN} Random element in [1, n-1]
 */
function generateSecureRandom(bytes = 32) {
  let value;
  do {
    const buffer = randomBytes(bytes);
    value = new BN(buffer).umod(CURVE_ORDER);
  } while (value.isZero()); // Ensure non-zero
  return value;
}

/**
 * Polynomial class for threshold cryptography
 * Represents a polynomial f(x) = a_0 + a_1*x + ... + a_t*x^t over Z_n
 */
class Polynomial {
  /**
   * Create a polynomial of given degree with random coefficients
   * @param {number} degree - Polynomial degree (t)
   * @param {BN|null} secret - Optional secret value for a_0 (zeroth coefficient)
   */
  constructor(degree, secret = null) {
    if (typeof degree !== 'number' || degree < 0) {
      throw new PolynomialError('Degree must be a non-negative integer', 'INVALID_DEGREE');
    }

    this.degree = degree;
    this.coefficients = new Array(degree + 1);

    // a_0 is the secret (or random if not provided)
    if (secret !== null) {
      this.coefficients[0] = secret instanceof BN ? secret.clone() : new BN(secret);
    } else {
      this.coefficients[0] = generateSecureRandom();
    }

    // Generate random coefficients a_1, ..., a_t
    for (let i = 1; i <= degree; i++) {
      this.coefficients[i] = generateSecureRandom();
    }
  }

  /**
   * Evaluate polynomial at point x using Horner's method
   * f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_t*x^t
   * @param {number|BN} x - Evaluation point (must be non-zero for secret sharing)
   * @returns {BN} f(x) mod n
   */
  evaluate(x) {
    const xBN = x instanceof BN ? x : new BN(x);

    // Use Horner's method for efficiency: a_0 + x*(a_1 + x*(a_2 + ...))
    let result = this.coefficients[this.degree].clone();
    for (let i = this.degree - 1; i >= 0; i--) {
      result = result.mul(xBN).add(this.coefficients[i]).umod(CURVE_ORDER);
    }

    return result;
  }

  /**
   * Get the secret (zeroth coefficient)
   * @returns {BN} The secret a_0
   */
  getSecret() {
    return this.coefficients[0].clone();
  }

  /**
   * Get all coefficients (cloned for safety)
   * @returns {BN[]} Array of coefficients [a_0, a_1, ..., a_t]
   */
  getCoefficients() {
    return this.coefficients.map(c => c.clone());
  }

  /**
   * Generate shares for n participants
   * Share for participant i is the point (i, f(i))
   * @param {number} n - Number of participants
   * @returns {Array<{x: BN, y: BN, index: number}>} Array of shares
   */
  generateShares(n) {
    if (n <= this.degree) {
      throw new PolynomialError(
        `Need more participants (${n}) than polynomial degree (${this.degree})`,
        'INSUFFICIENT_PARTICIPANTS'
      );
    }

    const shares = [];
    for (let i = 1; i <= n; i++) {
      shares.push({
        x: new BN(i),
        y: this.evaluate(i),
        index: i
      });
    }

    return shares;
  }

  /**
   * Calculate Lagrange basis polynomial coefficient L_i(x)
   * L_i(x) = Π_{j≠i} (x - x_j) / (x_i - x_j)
   * 
   * @param {number} i - Index in the xCoords array
   * @param {BN[]} xCoords - Array of x-coordinates
   * @param {BN} x - Point to evaluate at (default 0 for secret reconstruction)
   * @returns {BN} Lagrange coefficient
   */
  static lagrangeCoefficient(i, xCoords, x = new BN(0)) {
    let numerator = new BN(1);
    let denominator = new BN(1);

    const xi = xCoords[i] instanceof BN ? xCoords[i] : new BN(xCoords[i]);

    for (let j = 0; j < xCoords.length; j++) {
      if (i === j) continue;

      const xj = xCoords[j] instanceof BN ? xCoords[j] : new BN(xCoords[j]);

      // numerator *= (x - x_j)
      numerator = numerator.mul(x.sub(xj)).umod(CURVE_ORDER);
      // denominator *= (x_i - x_j)
      denominator = denominator.mul(xi.sub(xj)).umod(CURVE_ORDER);
    }

    // Handle negative modular arithmetic
    if (numerator.isNeg()) {
      numerator = numerator.add(CURVE_ORDER);
    }
    if (denominator.isNeg()) {
      denominator = denominator.add(CURVE_ORDER);
    }

    // Return numerator * denominator^-1 mod n
    const denominatorInv = denominator.invm(CURVE_ORDER);
    return numerator.mul(denominatorInv).umod(CURVE_ORDER);
  }

  /**
   * Lagrange interpolation to reconstruct polynomial value at x
   * f(x) = Σ y_i * L_i(x)
   * 
   * @param {Array<{x: BN, y: BN}>} shares - Array of shares (points on polynomial)
   * @param {BN} x - Point to interpolate at (default 0 for secret)
   * @returns {BN} Interpolated value f(x)
   */
  static interpolate(shares, x = new BN(0)) {
    if (!Array.isArray(shares) || shares.length === 0) {
      throw new PolynomialError('Shares array is required', 'INVALID_SHARES');
    }

    const xCoords = shares.map(s => s.x instanceof BN ? s.x : new BN(s.x));
    let result = new BN(0);

    for (let i = 0; i < shares.length; i++) {
      const yi = shares[i].y instanceof BN ? shares[i].y : new BN(shares[i].y);
      const li = this.lagrangeCoefficient(i, xCoords, x);
      const term = yi.mul(li).umod(CURVE_ORDER);
      result = result.add(term).umod(CURVE_ORDER);
    }

    return result;
  }

  /**
   * Reconstruct the secret (f(0)) from shares
   * Shorthand for interpolate(shares, 0)
   * 
   * @param {Array<{x: BN, y: BN}>} shares - Array of shares
   * @returns {BN} The reconstructed secret
   */
  static reconstructSecret(shares) {
    return this.interpolate(shares, new BN(0));
  }

  /**
   * Clear sensitive data from memory
   */
  clear() {
    for (let i = 0; i < this.coefficients.length; i++) {
      this.coefficients[i] = new BN(0);
    }
    this.coefficients = [];
    this.degree = 0;
  }
}

export { Polynomial, PolynomialError, generateSecureRandom, CURVE_ORDER };
export default Polynomial;

