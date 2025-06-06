/**
 * @fileoverview Polynomial operations for cryptographic secret sharing schemes
 * 
 * This module implements polynomial arithmetic over finite fields, specifically
 * designed for use in Shamir's Secret Sharing and threshold signature schemes.
 * All operations are performed modulo the secp256k1 curve order following the
 * Nakasendo Threshold Signatures specification.
 * 
 * @see {@link https://web.archive.org/web/20211216212202/https://nakasendoproject.org/Threshold-Signatures-whitepaper-nchain.pdf|Nakasendo Threshold Signatures Whitepaper}
 * @see {@link https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing|Shamir's Secret Sharing}
 * @see {@link https://en.wikipedia.org/wiki/Lagrange_polynomial|Lagrange Interpolation}
 * @author yfbsei
 * @version 2.0.0
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
 * Polynomial class for finite field arithmetic over secp256k1 curve order
 * 
 * Provides polynomial operations essential for cryptographic secret sharing:
 * - Random polynomial generation for secret distribution
 * - Polynomial evaluation at specific points (share generation)
 * - Lagrange interpolation for secret reconstruction
 * - Polynomial arithmetic (addition, multiplication)
 * 
 * All coefficients are BigNumbers reduced modulo the secp256k1 curve order,
 * ensuring compatibility with elliptic curve cryptographic operations.
 * 
 * **Mathematical Foundation:**
 * Based on Shamir's Secret Sharing scheme where a secret is encoded as the
 * constant term of a random polynomial of degree t-1, where t is the threshold.
 * Any t points on the polynomial can reconstruct the secret using Lagrange
 * interpolation, but t-1 or fewer points reveal no information about the secret.
 * 
 * @class Polynomial
 * @example
 * // Create a random degree-2 polynomial for 3-of-5 threshold scheme
 * const polynomial = Polynomial.generateRandom(2);
 * 
 * // Evaluate at points 1,2,3,4,5 to generate shares
 * const shares = [1,2,3,4,5].map(x => [new BN(x), polynomial.evaluate(new BN(x))]);
 * 
 * // Reconstruct secret using any 3 shares
 * const secret = Polynomial.interpolateAtZero(shares.slice(0,3));
 * console.log('Reconstructed secret:', secret.toString());
 */
class Polynomial {

    /**
     * Creates a polynomial with given coefficients
     * 
     * The polynomial is represented as: f(x) = a₀ + a₁x + a₂x² + ... + aₙxⁿ
     * where coefficients[0] = a₀ (constant term), coefficients[1] = a₁, etc.
     * 
     * **Security Note:** The constant term (coefficients[0]) typically contains
     * the secret value in threshold cryptography applications.
     * 
     * @param {BN[]} coefficients - Array of BigNumber coefficients from constant to highest degree
     * @throws {Error} If coefficients array is empty or contains invalid values
     * 
     * @example
     * // Create polynomial f(x) = 5 + 3x + 2x²
     * const coefficients = [new BN(5), new BN(3), new BN(2)];
     * const polynomial = new Polynomial(coefficients);
     * console.log('Degree:', polynomial.degree); // 2
     * console.log('Secret (constant term):', polynomial.constantTerm.toString()); // "5"
     */
    constructor(coefficients) {
        if (!Array.isArray(coefficients) || coefficients.length === 0) {
            throw new Error('Coefficients must be a non-empty array');
        }

        // Validate all coefficients are BigNumbers
        for (let i = 0; i < coefficients.length; i++) {
            if (!BN.isBN(coefficients[i])) {
                throw new Error(`Coefficient at index ${i} must be a BigNumber`);
            }
        }

        /**
         * Polynomial degree (highest power of x)
         * @type {number}
         * @readonly
         */
        this.degree = coefficients.length - 1;

        /**
         * Array of polynomial coefficients as BigNumbers (modulo curve order)
         * @type {BN[]}
         * @readonly
         */
        this.coefficients = coefficients.map(coeff => coeff.umod(CURVE_ORDER));

        /**
         * The constant term (secret value in threshold schemes)
         * @type {BN}
         * @readonly
         */
        this.constantTerm = this.coefficients[0];
    }

    /**
     * Generates a random polynomial of specified degree using cryptographically secure entropy
     * 
     * Each coefficient is generated using 32 bytes of secure random data,
     * ensuring unpredictability suitable for cryptographic applications.
     * The constant term (coefficients[0]) becomes the secret to be shared.
     * 
     * **Cryptographic Properties:**
     * - Uses cryptographically secure random number generation
     * - All coefficients are uniformly distributed over the finite field
     * - The polynomial is statistically indistinguishable from random
     * - Suitable for threshold cryptography applications
     * 
     * @static
     * @param {number} [degree=2] - Degree of the polynomial to generate
     * @param {BN} [secretValue] - Optional specific secret value for constant term
     * @returns {Polynomial} New polynomial with random coefficients
     * @throws {Error} If degree is invalid or secret value is invalid
     * 
     * @example
     * // Generate random polynomial for 2-of-3 threshold (degree = threshold - 1)
     * const polynomial = Polynomial.generateRandom(2);
     * 
     * // Generate shares by evaluating at points 1, 2, 3
     * const share1 = polynomial.evaluate(new BN(1));
     * const share2 = polynomial.evaluate(new BN(2));
     * const share3 = polynomial.evaluate(new BN(3));
     * 
     * // Any 2 shares can reconstruct the secret (coefficients[0])
     * const reconstructed = Polynomial.interpolateAtZero([
     *   [new BN(1), share1],
     *   [new BN(2), share2]
     * ]);
     * 
     * @example
     * // Generate polynomial with specific secret
     * const mySecret = new BN('deadbeef', 'hex');
     * const polynomial = Polynomial.generateRandom(3, mySecret);
     * console.log('Secret embedded:', polynomial.constantTerm.eq(mySecret)); // true
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
            if (!BN.isBN(secretValue)) {
                throw new Error('Secret value must be a BigNumber');
            }
            coefficients[0] = secretValue.umod(CURVE_ORDER);
        } else {
            coefficients[0] = new BN(randomBytes(32)).umod(CURVE_ORDER);
        }

        // Generate random coefficients for higher degree terms
        for (let i = 1; i <= degree; i++) {
            coefficients[i] = new BN(randomBytes(32)).umod(CURVE_ORDER);
        }

        return new Polynomial(coefficients);
    }

    /**
     * Reconstructs a secret using Lagrange interpolation from coordinate points
     * 
     * Implements Lagrange interpolation to evaluate a polynomial at x=0 (the secret)
     * given sufficient coordinate pairs. This is the core operation for
     * reconstructing secrets in Shamir's Secret Sharing.
     * 
     * **Mathematical Algorithm:**
     * The algorithm computes: f(0) = Σᵢ yᵢ * Lᵢ(0)
     * where Lᵢ(0) = Πⱼ≠ᵢ (-xⱼ) / (xᵢ - xⱼ)
     * 
     * **Security Properties:**
     * - Requires exactly threshold number of points for reconstruction
     * - Information-theoretic security: < threshold points reveal nothing
     * - Computationally efficient for practical threshold values
     * 
     * @static
     * @param {InterpolationPoints} points - Array of [x, y] coordinate pairs
     * @returns {BN} The interpolated secret value f(0) modulo curve order
     * @throws {Error} If points array is invalid or contains duplicate x-coordinates
     * 
     * @example
     * // Reconstruct secret from threshold shares
     * const shares = [
     *   [new BN(1), new BN("123")], 
     *   [new BN(2), new BN("456")], 
     *   [new BN(3), new BN("789")]
     * ];
     * const secret = Polynomial.interpolateAtZero(shares);
     * console.log('Reconstructed secret:', secret.toString());
     * 
     * @example
     * // Verify polynomial evaluation consistency
     * const originalPoly = Polynomial.generateRandom(2);
     * const testPoints = [
     *   [new BN(1), originalPoly.evaluate(new BN(1))],
     *   [new BN(2), originalPoly.evaluate(new BN(2))],
     *   [new BN(3), originalPoly.evaluate(new BN(3))]
     * ];
     * const reconstructedSecret = Polynomial.interpolateAtZero(testPoints);
     * console.log('Secrets match:', reconstructedSecret.eq(originalPoly.constantTerm)); // true
     */
    static interpolateAtZero(points) {
        if (!Array.isArray(points) || points.length === 0) {
            throw new Error('Points must be a non-empty array');
        }

        // Validate point format and check for duplicates
        const xCoordinates = new Set();
        for (let i = 0; i < points.length; i++) {
            const point = points[i];
            if (!Array.isArray(point) || point.length !== 2) {
                throw new Error(`Point at index ${i} must be an array of length 2`);
            }

            const [x, y] = point;
            if (!BN.isBN(x) || !BN.isBN(y)) {
                throw new Error(`Point coordinates at index ${i} must be BigNumbers`);
            }

            const xString = x.toString();
            if (xCoordinates.has(xString)) {
                throw new Error(`Duplicate x-coordinate found: ${xString}`);
            }
            xCoordinates.add(xString);

            // x-coordinate cannot be zero for evaluation at zero
            if (x.isZero()) {
                throw new Error('x-coordinate cannot be zero for interpolation at zero');
            }
        }

        let result = new BN(0);

        // Compute Lagrange interpolation at x = 0
        for (let i = 0; i < points.length; i++) {
            const [xi, yi] = points[i];
            let numerator = new BN(1);
            let denominator = new BN(1);

            // Compute Lagrange basis polynomial Lᵢ(0)
            for (let j = 0; j < points.length; j++) {
                if (i !== j) {
                    const [xj] = points[j];
                    // For evaluation at x=0: numerator *= -xⱼ, denominator *= (xᵢ - xⱼ)
                    numerator = numerator.mul(xj.neg()).umod(CURVE_ORDER);
                    denominator = denominator.mul(xi.sub(xj)).umod(CURVE_ORDER);
                }
            }

            // Compute modular inverse of denominator
            const denominatorInverse = denominator.invm(CURVE_ORDER);

            // Add yᵢ * Lᵢ(0) to result
            const lagrangeTerm = yi.mul(numerator).mul(denominatorInverse).umod(CURVE_ORDER);
            result = result.add(lagrangeTerm).umod(CURVE_ORDER);
        }

        return result;
    }

    /**
     * General Lagrange interpolation at any point x
     * 
     * @static
     * @param {InterpolationPoints} points - Array of [x, y] coordinate pairs
     * @param {BN} evaluationPoint - Point at which to evaluate the interpolated polynomial
     * @returns {BN} The interpolated value f(x) modulo curve order
     * 
     * @example
     * const points = [[new BN(1), new BN(2)], [new BN(2), new BN(5)], [new BN(3), new BN(10)]];
     * const valueAt5 = Polynomial.interpolateAt(points, new BN(5));
     */
    static interpolateAt(points, evaluationPoint) {
        if (!BN.isBN(evaluationPoint)) {
            throw new Error('Evaluation point must be a BigNumber');
        }

        // Validate inputs using same logic as interpolateAtZero
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
                if (i !== j) {
                    const [xj] = points[j];
                    numerator = numerator.mul(evaluationPoint.sub(xj)).umod(CURVE_ORDER);
                    denominator = denominator.mul(xi.sub(xj)).umod(CURVE_ORDER);
                }
            }

            // Compute modular inverse and add term
            const denominatorInverse = denominator.invm(CURVE_ORDER);
            const lagrangeTerm = yi.mul(numerator).mul(denominatorInverse).umod(CURVE_ORDER);
            result = result.add(lagrangeTerm).umod(CURVE_ORDER);
        }

        return result;
    }

    /**
     * Evaluates the polynomial at a given point using Horner's method
     * 
     * Efficiently computes f(x) = a₀ + a₁x + a₂x² + ... + aₙxⁿ
     * using Horner's method: f(x) = a₀ + x(a₁ + x(a₂ + x(a₃ + ...)))
     * 
     * This method is used to generate shares in secret sharing schemes
     * by evaluating the polynomial at participant indices.
     * 
     * **Performance:** O(n) where n is the polynomial degree
     * **Numerical Stability:** Horner's method minimizes rounding errors
     * 
     * @param {BN} evaluationPoint - Point at which to evaluate the polynomial
     * @returns {PolynomialEvaluation} Evaluation result with metadata
     * @throws {Error} If evaluation point is not a BigNumber
     * 
     * @example
     * // Generate shares for a 3-of-5 threshold scheme
     * const secret = new BN("deadbeef", 'hex');
     * const polynomial = Polynomial.generateRandom(2, secret);
     * 
     * // Generate 5 shares
     * const shares = [];
     * for (let i = 1; i <= 5; i++) {
     *   const evaluation = polynomial.evaluate(new BN(i));
     *   shares.push([new BN(i), evaluation.value]);
     * }
     * 
     * // Any 3 shares can reconstruct the secret
     * const reconstructed = Polynomial.interpolateAtZero(shares.slice(0, 3));
     * console.log('Secrets match:', reconstructed.eq(secret)); // true
     */
    evaluate(evaluationPoint) {
        if (!BN.isBN(evaluationPoint)) {
            throw new Error('Evaluation point must be a BigNumber');
        }

        // Horner's method: start with highest degree coefficient
        let result = this.coefficients[this.coefficients.length - 1];

        // Work backwards through coefficients
        for (let i = this.coefficients.length - 2; i >= 0; i--) {
            result = result.mul(evaluationPoint).add(this.coefficients[i]).umod(CURVE_ORDER);
        }

        return {
            value: result,
            point: evaluationPoint,
            degree: this.degree
        };
    }

    /**
     * Adds two polynomials coefficient-wise
     * 
     * Performs polynomial addition: (f + g)(x) = f(x) + g(x)
     * The resulting polynomial has degree max(deg(f), deg(g))
     * 
     * This operation is useful in cryptographic protocols that require
     * linear combinations of shared secrets.
     * 
     * @param {Polynomial} otherPolynomial - Polynomial to add
     * @returns {Polynomial} New polynomial representing the sum
     * @throws {Error} If input is not a Polynomial instance
     * 
     * @example
     * // Add two random polynomials
     * const poly1 = Polynomial.generateRandom(2); // f(x) = a₀ + a₁x + a₂x²
     * const poly2 = Polynomial.generateRandom(2); // g(x) = b₀ + b₁x + b₂x²
     * const sum = poly1.add(poly2);              // h(x) = (a₀+b₀) + (a₁+b₁)x + (a₂+b₂)x²
     * 
     * // Verify addition property: h(5) = f(5) + g(5)
     * const x = new BN(5);
     * const sumAtX = sum.evaluate(x).value;
     * const directSum = poly1.evaluate(x).value.add(poly2.evaluate(x).value).umod(CURVE_ORDER);
     * console.log('Addition verified:', sumAtX.eq(directSum)); // true
     */
    add(otherPolynomial) {
        if (!(otherPolynomial instanceof Polynomial)) {
            throw new Error('Argument must be a Polynomial instance');
        }

        // Determine which polynomial has more coefficients
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
     * Multiplies two polynomials using convolution
     * 
     * Performs polynomial multiplication: (f * g)(x) = f(x) * g(x)
     * The resulting polynomial has degree deg(f) + deg(g)
     * 
     * Uses the standard convolution algorithm where each coefficient of the result
     * is the sum of products of coefficients whose indices sum to that position.
     * 
     * @param {Polynomial} otherPolynomial - Polynomial to multiply
     * @returns {Polynomial} New polynomial representing the product
     * @throws {Error} If input is not a Polynomial instance
     * 
     * @example
     * // Multiply two polynomials: (2 + 3x) * (1 + 4x) = 2 + 11x + 12x²
     * const poly1 = new Polynomial([new BN(2), new BN(3)]);     // 2 + 3x
     * const poly2 = new Polynomial([new BN(1), new BN(4)]);     // 1 + 4x
     * const product = poly1.multiply(poly2);                    // 2 + 11x + 12x²
     * 
     * // Verify: coefficients should be [2, 11, 12]
     * console.log('Constant term:', product.coefficients[0].toNumber()); // 2
     * console.log('Linear term:', product.coefficients[1].toNumber());   // 11  
     * console.log('Quadratic term:', product.coefficients[2].toNumber()); // 12
     */
    multiply(otherPolynomial) {
        if (!(otherPolynomial instanceof Polynomial)) {
            throw new Error('Argument must be a Polynomial instance');
        }

        // Initialize result coefficients array with zeros
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
     * Creates a copy of this polynomial
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
}

export default Polynomial;