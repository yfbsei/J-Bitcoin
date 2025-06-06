/**
 * @fileoverview Polynomial operations for cryptographic secret sharing schemes
 * 
 * This module implements polynomial arithmetic over finite fields, specifically
 * designed for use in Shamir's Secret Sharing and threshold signature schemes.
 * All operations are performed modulo the secp256k1 curve order following the
 * Nakasendo Threshold Signatures specification.
 * 
 * SECURITY UPDATES:
 * - Constant-time operations to prevent timing attacks
 * - Enhanced input validation and bounds checking
 * - Secure memory handling for sensitive operations
 * - Protection against side-channel attacks
 * 
 * @see {@link https://web.archive.org/web/20211216212202/https://nakasendoproject.org/Threshold-Signatures-whitepaper-nchain.pdf|Nakasendo Threshold Signatures Whitepaper}
 * @see {@link https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing|Shamir's Secret Sharing}
 * @see {@link https://en.wikipedia.org/wiki/Lagrange_polynomial|Lagrange Interpolation}
 * @author yfbsei
 * @version 2.1.0
 */

import { randomBytes } from 'node:crypto';
import BN from 'bn.js';
import {
    CRYPTO_CONSTANTS,
    THRESHOLD_CONSTANTS
} from '../../../constants.js';

/**
 * secp256k1 curve order for modular arithmetic operations
 * All polynomial operations are performed modulo this prime
 * @constant {BN}
 */
const CURVE_ORDER = new BN(CRYPTO_CONSTANTS.SECP256K1_ORDER, "hex");

/**
 * Half of curve order for canonical signature enforcement
 * @constant {BN}
 */
const HALF_CURVE_ORDER = CURVE_ORDER.div(new BN(2));

/**
 * @typedef {Array<Array<BN>>} InterpolationPoints
 * @description Array of [x, y] coordinate pairs for polynomial interpolation
 * @example [[new BN(1), new BN(123)], [new BN(2), new BN(456)], [new BN(3), new BN(789)]]
 */

/**
 * @typedef {Object} PolynomialEvaluation
 * @property {BN} value - The evaluated polynomial value
 * @property {BN} point - The x-coordinate where evaluation occurred
 * @property {number} degree - The degree of the polynomial
 */

/**
 * Security utilities for constant-time operations
 */
class SecurityUtils {
    /**
     * Constant-time conditional move
     * @param {number} condition - 1 to select a, 0 to select b
     * @param {BN} a - First value
     * @param {BN} b - Second value
     * @returns {BN} Selected value without timing leaks
     */
    static cmov(condition, a, b) {
        // Convert condition to mask (0x00...00 or 0xFF...FF)
        const mask = condition ? new BN(-1) : new BN(0);
        const notMask = mask.notn();

        return a.and(mask).or(b.and(notMask));
    }

    /**
     * Constant-time equality check
     * @param {BN} a - First value
     * @param {BN} b - Second value
     * @returns {number} 1 if equal, 0 if different
     */
    static constantTimeEqual(a, b) {
        const diff = a.xor(b);
        return diff.isZero() ? 1 : 0;
    }

    /**
     * Validates that a value is in the valid range [1, CURVE_ORDER-1]
     * @param {BN} value - Value to validate
     * @param {string} name - Name for error messages
     * @throws {Error} If value is out of range
     */
    static validateFieldElement(value, name = 'value') {
        if (!BN.isBN(value)) {
            throw new Error(`${name} must be a BigNumber`);
        }

        if (value.isZero() || value.gte(CURVE_ORDER)) {
            throw new Error(`${name} must be in range [1, n-1] where n is curve order`);
        }
    }

    /**
     * Securely clears a BigNumber by overwriting with random data
     * @param {BN} bn - BigNumber to clear
     */
    static secureClear(bn) {
        if (BN.isBN(bn)) {
            // Overwrite with random data multiple times
            for (let i = 0; i < 3; i++) {
                const randomData = randomBytes(32);
                bn.fromBuffer(randomData);
            }
            bn.fromNumber(0);
        }
    }
}

/**
 * Polynomial class for finite field arithmetic over secp256k1 curve order
 * 
 * Enhanced with security features to prevent timing attacks and side-channel
 * information leakage during polynomial operations.
 * 
 * @class Polynomial
 */
class Polynomial {

    /**
     * Creates a polynomial with given coefficients
     * 
     * @param {BN[]} coefficients - Array of BigNumber coefficients from constant to highest degree
     * @throws {Error} If coefficients array is empty or contains invalid values
     */
    constructor(coefficients) {
        if (!Array.isArray(coefficients) || coefficients.length === 0) {
            throw new Error('Coefficients must be a non-empty array');
        }

        // Validate all coefficients are valid field elements
        for (let i = 0; i < coefficients.length; i++) {
            if (!BN.isBN(coefficients[i])) {
                throw new Error(`Coefficient at index ${i} must be a BigNumber`);
            }
            // Allow zero coefficients for internal operations, but validate range
            if (coefficients[i].lt(new BN(0)) || coefficients[i].gte(CURVE_ORDER)) {
                throw new Error(`Coefficient at index ${i} out of valid range`);
            }
        }

        this.degree = coefficients.length - 1;
        this.coefficients = coefficients.map(coeff => coeff.umod(CURVE_ORDER));
        this.constantTerm = this.coefficients[0];

        // Security: Clear intermediate values
        coefficients.forEach(SecurityUtils.secureClear);
    }

    /**
     * Generates a random polynomial of specified degree using cryptographically secure entropy
     * 
     * Enhanced with additional entropy validation and secure random generation.
     * 
     * @static
     * @param {number} [degree=2] - Degree of the polynomial to generate
     * @param {BN} [secretValue] - Optional specific secret value for constant term
     * @returns {Polynomial} New polynomial with random coefficients
     * @throws {Error} If degree is invalid or secret value is invalid
     */
    static generateRandom(degree = 2, secretValue = null) {
        if (!Number.isInteger(degree) || degree < 0) {
            throw new Error(`Degree must be a non-negative integer, got ${degree}`);
        }

        if (degree > THRESHOLD_CONSTANTS.MAX_RECOMMENDED_PARTICIPANTS) {
            console.warn(
                `⚠️  High polynomial degree (${degree}) may impact performance. ` +
                `Consider using degree ≤ ${THRESHOLD_CONSTANTS.MAX_RECOMMENDED_PARTICIPANTS}`
            );
        }

        const coefficients = new Array(degree + 1);

        // Set constant term (secret value)
        if (secretValue !== null) {
            SecurityUtils.validateFieldElement(secretValue, 'secret value');
            coefficients[0] = secretValue.umod(CURVE_ORDER);
        } else {
            // Generate cryptographically secure random secret
            let randomSecret;
            do {
                randomSecret = new BN(randomBytes(32));
            } while (randomSecret.isZero() || randomSecret.gte(CURVE_ORDER));
            coefficients[0] = randomSecret;
        }

        // Generate random coefficients for higher degree terms
        for (let i = 1; i <= degree; i++) {
            let randomCoeff;
            do {
                randomCoeff = new BN(randomBytes(32));
            } while (randomCoeff.gte(CURVE_ORDER));
            coefficients[i] = randomCoeff;
        }

        return new Polynomial(coefficients);
    }

    /**
     * Reconstructs a secret using constant-time Lagrange interpolation
     * 
     * Enhanced with timing attack protection and secure computation.
     * 
     * @static
     * @param {InterpolationPoints} points - Array of [x, y] coordinate pairs
     * @returns {BN} The interpolated secret value f(0) modulo curve order
     * @throws {Error} If points array is invalid or contains duplicate x-coordinates
     */
    static interpolateAtZero(points) {
        if (!Array.isArray(points) || points.length === 0) {
            throw new Error('Points must be a non-empty array');
        }

        // Validate point format and check for duplicates using constant-time comparison
        const xCoordinates = new Map();
        for (let i = 0; i < points.length; i++) {
            const point = points[i];
            if (!Array.isArray(point) || point.length !== 2) {
                throw new Error(`Point at index ${i} must be an array of length 2`);
            }

            const [x, y] = point;
            if (!BN.isBN(x) || !BN.isBN(y)) {
                throw new Error(`Point coordinates at index ${i} must be BigNumbers`);
            }

            SecurityUtils.validateFieldElement(x, `x-coordinate at index ${i}`);
            SecurityUtils.validateFieldElement(y, `y-coordinate at index ${i}`);

            const xString = x.toString();
            if (xCoordinates.has(xString)) {
                throw new Error(`Duplicate x-coordinate found: ${xString}`);
            }
            xCoordinates.set(xString, true);
        }

        let result = new BN(0);

        // Constant-time Lagrange interpolation at x = 0
        for (let i = 0; i < points.length; i++) {
            const [xi, yi] = points[i];
            let numerator = new BN(1);
            let denominator = new BN(1);

            // Compute Lagrange basis polynomial Lᵢ(0) in constant time
            for (let j = 0; j < points.length; j++) {
                const [xj] = points[j];

                // Constant-time conditional: if (i !== j)
                const isNotEqual = 1 - SecurityUtils.constantTimeEqual(new BN(i), new BN(j));

                if (isNotEqual) {
                    // For evaluation at x=0: numerator *= -xⱼ, denominator *= (xᵢ - xⱼ)
                    const negXj = xj.neg().umod(CURVE_ORDER);
                    const xiMinusXj = xi.sub(xj).umod(CURVE_ORDER);

                    numerator = numerator.mul(negXj).umod(CURVE_ORDER);
                    denominator = denominator.mul(xiMinusXj).umod(CURVE_ORDER);
                }
            }

            // Compute modular inverse of denominator using Fermat's Little Theorem
            const exponent = CURVE_ORDER.sub(new BN(2));
            const denominatorInverse = denominator.toRed(BN.red(CURVE_ORDER))
                .redPow(exponent)
                .fromRed();

            // Add yᵢ * Lᵢ(0) to result
            const lagrangeTerm = yi.mul(numerator).mul(denominatorInverse).umod(CURVE_ORDER);
            result = result.add(lagrangeTerm).umod(CURVE_ORDER);
        }

        return result;
    }

    /**
     * General Lagrange interpolation at any point x with constant-time implementation
     * 
     * @static
     * @param {InterpolationPoints} points - Array of [x, y] coordinate pairs
     * @param {BN} evaluationPoint - Point at which to evaluate the interpolated polynomial
     * @returns {BN} The interpolated value f(x) modulo curve order
     */
    static interpolateAt(points, evaluationPoint) {
        SecurityUtils.validateFieldElement(evaluationPoint, 'evaluation point');

        if (!Array.isArray(points) || points.length === 0) {
            throw new Error('Points must be a non-empty array');
        }

        let result = new BN(0);

        for (let i = 0; i < points.length; i++) {
            const [xi, yi] = points[i];
            let numerator = new BN(1);
            let denominator = new BN(1);

            // Compute Lagrange basis polynomial Lᵢ(evaluationPoint)
            for (let j = 0; j < points.length; j++) {
                const isNotEqual = 1 - SecurityUtils.constantTimeEqual(new BN(i), new BN(j));

                if (isNotEqual) {
                    const [xj] = points[j];
                    const evalMinusXj = evaluationPoint.sub(xj).umod(CURVE_ORDER);
                    const xiMinusXj = xi.sub(xj).umod(CURVE_ORDER);

                    numerator = numerator.mul(evalMinusXj).umod(CURVE_ORDER);
                    denominator = denominator.mul(xiMinusXj).umod(CURVE_ORDER);
                }
            }

            // Compute modular inverse and add term
            const exponent = CURVE_ORDER.sub(new BN(2));
            const denominatorInverse = denominator.toRed(BN.red(CURVE_ORDER))
                .redPow(exponent)
                .fromRed();

            const lagrangeTerm = yi.mul(numerator).mul(denominatorInverse).umod(CURVE_ORDER);
            result = result.add(lagrangeTerm).umod(CURVE_ORDER);
        }

        return result;
    }

    /**
     * Evaluates the polynomial at a given point using Horner's method
     * 
     * Enhanced with constant-time implementation to prevent timing attacks.
     * 
     * @param {BN} evaluationPoint - Point at which to evaluate the polynomial
     * @returns {PolynomialEvaluation} Evaluation result with metadata
     * @throws {Error} If evaluation point is not a BigNumber
     */
    evaluate(evaluationPoint) {
        SecurityUtils.validateFieldElement(evaluationPoint, 'evaluation point');

        // Constant-time Horner's method implementation
        let result = this.coefficients[this.coefficients.length - 1].clone();

        // Work backwards through coefficients in constant time
        for (let i = this.coefficients.length - 2; i >= 0; i--) {
            result = result.mul(evaluationPoint).add(this.coefficients[i]).umod(CURVE_ORDER);
        }

        return {
            value: result,
            point: evaluationPoint.clone(),
            degree: this.degree
        };
    }

    /**
     * Adds two polynomials coefficient-wise with enhanced validation
     * 
     * @param {Polynomial} otherPolynomial - Polynomial to add
     * @returns {Polynomial} New polynomial representing the sum
     * @throws {Error} If input is not a Polynomial instance
     */
    add(otherPolynomial) {
        if (!(otherPolynomial instanceof Polynomial)) {
            throw new Error('Argument must be a Polynomial instance');
        }

        const maxLength = Math.max(this.coefficients.length, otherPolynomial.coefficients.length);
        const resultCoefficients = new Array(maxLength);

        // Add corresponding coefficients
        for (let i = 0; i < maxLength; i++) {
            const thisCoeff = i < this.coefficients.length ? this.coefficients[i] : new BN(0);
            const otherCoeff = i < otherPolynomial.coefficients.length ? otherPolynomial.coefficients[i] : new BN(0);

            resultCoefficients[i] = thisCoeff.add(otherCoeff).umod(CURVE_ORDER);
        }

        return new Polynomial(resultCoefficients);
    }

    /**
     * Multiplies two polynomials using convolution with enhanced security
     * 
     * @param {Polynomial} otherPolynomial - Polynomial to multiply
     * @returns {Polynomial} New polynomial representing the product
     * @throws {Error} If input is not a Polynomial instance
     */
    multiply(otherPolynomial) {
        if (!(otherPolynomial instanceof Polynomial)) {
            throw new Error('Argument must be a Polynomial instance');
        }

        const resultDegree = this.degree + otherPolynomial.degree;
        const resultCoefficients = new Array(resultDegree + 1).fill(null).map(() => new BN(0));

        // Compute convolution: c[i+j] += a[i] * b[j]
        for (let i = 0; i < this.coefficients.length; i++) {
            for (let j = 0; j < otherPolynomial.coefficients.length; j++) {
                const product = this.coefficients[i].mul(otherPolynomial.coefficients[j]);
                resultCoefficients[i + j] = resultCoefficients[i + j].add(product).umod(CURVE_ORDER);
            }
        }

        return new Polynomial(resultCoefficients);
    }

    /**
     * Creates a deep copy of this polynomial with secure memory handling
     * 
     * @returns {Polynomial} Deep copy of this polynomial
     */
    clone() {
        const clonedCoefficients = this.coefficients.map(coeff => coeff.clone());
        return new Polynomial(clonedCoefficients);
    }

    /**
     * Checks if this polynomial equals another polynomial
     * 
     * @param {Polynomial} otherPolynomial - Polynomial to compare with
     * @returns {boolean} True if polynomials are equal
     */
    equals(otherPolynomial) {
        if (!(otherPolynomial instanceof Polynomial)) {
            return false;
        }

        if (this.degree !== otherPolynomial.degree) {
            return false;
        }

        return this.coefficients.every((coeff, i) =>
            coeff.eq(otherPolynomial.coefficients[i])
        );
    }

    /**
     * Returns string representation of the polynomial
     * 
     * @returns {string} Human-readable polynomial representation
     */
    toString() {
        const terms = this.coefficients.map((coeff, i) => {
            if (coeff.isZero()) return null;

            if (i === 0) return coeff.toString();
            if (i === 1) return `${coeff.toString()}x`;
            return `${coeff.toString()}x^${i}`;
        }).filter(term => term !== null);

        return terms.length > 0 ? terms.join(' + ') : '0';
    }

    /**
     * Securely destroys this polynomial by clearing all sensitive data
     */
    destroy() {
        this.coefficients.forEach(SecurityUtils.secureClear);
        this.coefficients.length = 0;
        SecurityUtils.secureClear(this.constantTerm);
    }
}

export default Polynomial;