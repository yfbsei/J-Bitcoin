/**
 * @fileoverview Polynomial operations for cryptographic secret sharing schemes
 * 
 * This module implements polynomial arithmetic over finite fields, specifically
 * designed for use in Shamir's Secret Sharing and threshold signature schemes.
 * All operations are performed modulo the secp256k1 curve order.
 * 
 * @see {@link https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing|Shamir's Secret Sharing}
 * @see {@link https://en.wikipedia.org/wiki/Lagrange_polynomial|Lagrange Interpolation}
 * @author yfbsei
 * @version 1.0.0
 */

import { randomBytes } from 'node:crypto';
import BN from 'bn.js';

// secp256k1 curve order for modular arithmetic
const N = new BN("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", "hex");

/**
 * @typedef {Array<Array<number>>} InterpolationPoints
 * @description Array of [x, y] coordinate pairs for polynomial interpolation
 * @example [[1, 123], [2, 456], [3, 789]]
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
 * @class Polynomial
 * @example
 * // Create a random degree-2 polynomial for 3-of-5 threshold scheme
 * const poly = Polynomial.fromRandom(2);
 * 
 * // Evaluate at points 1,2,3,4,5 to generate shares
 * const shares = [1,2,3,4,5].map(x => [x, poly.evaluate(x)]);
 * 
 * // Reconstruct secret using any 3 shares
 * const secret = Polynomial.interpolate_evaluate(shares.slice(0,3), 0);
 */
class Polynomial {

    /**
     * Creates a polynomial with given coefficients
     * 
     * The polynomial is represented as: f(x) = a₀ + a₁x + a₂x² + ... + aₙxⁿ
     * where coefficients[0] = a₀ (constant term), coefficients[1] = a₁, etc.
     * 
     * @param {BN[]} coefficients - Array of BigNumber coefficients from constant to highest degree
     * @example
     * // Create polynomial f(x) = 5 + 3x + 2x²
     * const coeffs = [new BN(5), new BN(3), new BN(2)];
     * const poly = new Polynomial(coeffs);
     * console.log(poly.order); // 2 (degree)
     */
    constructor(coefficients) {
        /**
         * Polynomial degree (highest power of x)
         * @type {number}
         * @readonly
         */
        this.order = coefficients.length - 1;

        /**
         * Array of polynomial coefficients as BigNumbers
         * @type {BN[]}
         * @readonly
         */
        this.coefficients = coefficients;
    }

    /**
     * Generates a random polynomial of specified degree using cryptographically secure randomness
     * 
     * Each coefficient is generated using 32 bytes of secure random data,
     * ensuring unpredictability suitable for cryptographic applications.
     * The constant term (coefficients[0]) becomes the secret to be shared.
     * 
     * @static
     * @param {number} [order=2] - Degree of the polynomial to generate
     * @returns {Polynomial} New polynomial with random coefficients
     * @example
     * // Generate random polynomial for 2-of-3 threshold (degree = threshold - 1)
     * const poly = Polynomial.fromRandom(2);
     * 
     * // Generate shares by evaluating at points 1, 2, 3
     * const share1 = poly.evaluate(1);
     * const share2 = poly.evaluate(2);
     * const share3 = poly.evaluate(3);
     * 
     * // Any 2 shares can reconstruct the secret (coefficients[0])
     */
    static fromRandom(order = 2) {
        const coefficients = new Array(order + 1).fill(null).map(_ => new BN(randomBytes(32)));
        return new Polynomial(coefficients);
    }

    /**
     * Reconstructs a secret using Lagrange interpolation from coordinate points
     * 
     * Implements Lagrange interpolation to evaluate a polynomial at point x
     * given sufficient coordinate pairs. This is the core operation for
     * reconstructing secrets in Shamir's Secret Sharing.
     * 
     * The algorithm computes: f(x) = Σᵢ yᵢ * Lᵢ(x)
     * where Lᵢ(x) = Πⱼ≠ᵢ (x - xⱼ) / (xᵢ - xⱼ)
     * 
     * @static
     * @param {InterpolationPoints} [points=[[1, 2], [1,2]]] - Array of [x, y] coordinate pairs
     * @param {number} [x=2] - Point at which to evaluate the interpolated polynomial
     * @returns {BN} The interpolated value f(x) modulo curve order
     * @example
     * // Reconstruct secret from threshold shares
     * const shares = [[1, new BN("123")], [2, new BN("456")], [3, new BN("789")]];
     * const secret = Polynomial.interpolate_evaluate(shares, 0); // Evaluate at x=0
     * 
     * // Verify polynomial evaluation at known point
     * const poly = Polynomial.fromRandom(2);
     * const testPoints = [[1, poly.evaluate(1)], [2, poly.evaluate(2)], [3, poly.evaluate(3)]];
     * const reconstructed = Polynomial.interpolate_evaluate(testPoints, 5);
     * const direct = poly.evaluate(5);
     * console.log(reconstructed.eq(direct)); // true
     */
    static interpolate_evaluate(points = [[1, 2], [1, 2]], x = 2) {
        let lagrange = new Array(points.length).fill(null);
        let denominator_product = 1;

        // Compute Lagrange basis polynomials
        for (let i = 0; i < points.length; i++) {
            let [numerator, denominator] = [1, 1];

            // Compute Lᵢ(x) = Πⱼ≠ᵢ (x - xⱼ) / (xᵢ - xⱼ)
            for (let j = 0; j < points.length; j++) {
                if (j !== i) {
                    numerator *= (x - points[j][0]);        // (x - xⱼ)
                    denominator *= (points[i][0] - points[j][0]); // (xᵢ - xⱼ)
                }
            }

            // Store [yᵢ * numerator, denominator] for later processing
            lagrange[i] = [new BN(points[i][1]).muln(numerator), denominator];
            denominator_product *= denominator;
        }

        // Compute final result: Σᵢ yᵢ * Lᵢ(x)
        const numerator_sum = lagrange.reduce((total, val) =>
            total.add(val[0].muln(denominator_product).divRound(new BN(val[1]))), new BN(0));

        return numerator_sum.divRound(new BN(denominator_product)).umod(N);
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
     * @param {number} [x=2] - Point at which to evaluate the polynomial
     * @returns {BN} The polynomial value f(x) modulo curve order
     * @example
     * // Generate shares for a 3-of-5 threshold scheme
     * const secret = new BN("deadbeefcafe", 'hex');
     * const coeffs = [secret, new BN(randomBytes(32)), new BN(randomBytes(32))];
     * const poly = new Polynomial(coeffs);
     * 
     * // Generate 5 shares
     * const shares = [];
     * for (let i = 1; i <= 5; i++) {
     *   shares.push([i, poly.evaluate(i)]);
     * }
     * 
     * // Any 3 shares can reconstruct the secret
     * const reconstructed = Polynomial.interpolate_evaluate(shares.slice(0, 3), 0);
     * console.log(reconstructed.eq(secret)); // true
     */
    evaluate(x = 2) {
        return this.coefficients.reduce((total, val) => {
            total[1].iadd(val.muln(total[0])); // y = y + (coefficient * x^power)
            total[0] *= x;                     // Increment power of x
            return [total[0], total[1]];
        }, [1, new BN(0)])[1].umod(N);
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
     * @param {Polynomial} [other={order: 1, coefficients: [1, 2, 3]}] - Polynomial to add
     * @returns {Polynomial} New polynomial representing the sum
     * @example
     * // Add two random polynomials
     * const poly1 = Polynomial.fromRandom(2); // f(x) = a₀ + a₁x + a₂x²
     * const poly2 = Polynomial.fromRandom(2); // g(x) = b₀ + b₁x + b₂x²
     * const sum = poly1.add(poly2);           // h(x) = (a₀+b₀) + (a₁+b₁)x + (a₂+b₂)x²
     * 
     * // Verify addition property: h(5) = f(5) + g(5)
     * const x = 5;
     * const sumAtX = sum.evaluate(x);
     * const directSum = poly1.evaluate(x).add(poly2.evaluate(x)).umod(N);
     * console.log(sumAtX.eq(directSum)); // true
     */
    add(other = { order: 1, coefficients: [1, 2, 3] }) {
        // Determine which polynomial has more coefficients
        const longest = (this.order > other.order) ? this.coefficients : other.coefficients;
        const shortest = (other.order < this.order) ? other.coefficients : this.coefficients;

        // Add corresponding coefficients
        const coefficients =
            new Array(shortest.length)
                .fill(null)
                .map((_, i) => shortest[i].add(longest[i]))      // Add overlapping coefficients
                .concat(longest.slice(shortest.length))         // Append remaining coefficients
                .map(val => val.umod(N));                       // Reduce modulo curve order

        return new Polynomial(coefficients);
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
     * @param {Polynomial} [other={order: 1, coefficients: [1, 2, 3]}] - Polynomial to multiply
     * @returns {Polynomial} New polynomial representing the product
     * @example
     * // Multiply two polynomials: (2 + 3x) * (1 + 4x) = 2 + 11x + 12x²
     * const poly1 = new Polynomial([new BN(2), new BN(3)]);     // 2 + 3x
     * const poly2 = new Polynomial([new BN(1), new BN(4)]);     // 1 + 4x
     * const product = poly1.multiply(poly2);                    // 2 + 11x + 12x²
     * 
     * // Verify: coefficients should be [2, 11, 12]
     * console.log(product.coefficients[0].toNumber()); // 2
     * console.log(product.coefficients[1].toNumber()); // 11  
     * console.log(product.coefficients[2].toNumber()); // 12
     */
    multiply(other = { order: 1, coefficients: [1, 2, 3] }) {
        // Initialize result coefficients array with zeros
        let coefficients = new Array(this.order + other.order + 1).fill(new BN(0));

        // Compute convolution: c[i+j] += a[i] * b[j]
        for (let i = 0; i < this.coefficients.length; i++) {
            for (let j = 0; j < other.coefficients.length; j++) {
                coefficients[i + j] = coefficients[i + j].add(
                    this.coefficients[i].mul(other.coefficients[j])
                );
            }
        }

        // Reduce all coefficients modulo curve order
        coefficients = coefficients.map(val => val.umod(N));
        return new Polynomial(coefficients);
    }
}

export default Polynomial;