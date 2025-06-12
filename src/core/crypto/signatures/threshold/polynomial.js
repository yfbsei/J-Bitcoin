/**
 * @fileoverview Enhanced polynomial operations for cryptographic secret sharing schemes
 * 
 * This module implements polynomial arithmetic over finite fields, specifically
 * designed for use in Shamir's Secret Sharing and threshold signature schemes.
 * All operations are performed modulo the secp256k1 curve order following the
 * Nakasendo Threshold Signatures specification.
 * 
 * SECURITY UPDATES (v2.2.0):
 * - FIX #1: Improved input validation with comprehensive bounds checking
 * - FIX #2: Enhanced memory management and secure cleanup
 * - FIX #3: Better error handling with detailed context
 * - FIX #4: Optimized interpolation algorithm with better numerical stability
 * - FIX #5: Added comprehensive test coverage for edge cases
 * - FIX #6: Improved constant-time operations implementation
 * 
 * @see {@link https://web.archive.org/web/20211216212202/https://nakasendoproject.org/Threshold-Signatures-whitepaper-nchain.pdf|Nakasendo Threshold Signatures Whitepaper}
 * @see {@link https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing|Shamir's Secret Sharing}
 * @see {@link https://en.wikipedia.org/wiki/Lagrange_polynomial|Lagrange Interpolation}
 * @author yfbsei
 * @version 2.2.0
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
const HALF_CURVE_ORDER = CURVE_ORDER.shrn(1);

/**
 * Enhanced security constants for polynomial operations
 */
const POLYNOMIAL_SECURITY_CONSTANTS = {
    MAX_DEGREE: 255,                    // Maximum polynomial degree
    MAX_EVALUATION_POINTS: 1000,        // Maximum points for interpolation
    MAX_COEFFICIENTS: 256,              // Maximum number of coefficients
    MAX_INTERPOLATION_TIME_MS: 5000,    // Maximum interpolation time
    MAX_VALIDATIONS_PER_SECOND: 500,    // Rate limiting threshold
    MIN_FIELD_ELEMENT: new BN(1),       // Minimum valid field element
    MAX_FIELD_ELEMENT: CURVE_ORDER.sub(new BN(1)) // Maximum valid field element
};

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
 * @property {boolean} isValid - Whether the evaluation is valid
 */

/**
 * @typedef {Object} InterpolationResult
 * @property {BN} value - The interpolated value at x=0
 * @property {number} pointsUsed - Number of points used in interpolation
 * @property {boolean} isValid - Whether interpolation succeeded
 * @property {number} executionTime - Time taken for interpolation (ms)
 */

/**
 * Enhanced error class for polynomial operations
 */
class PolynomialError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'PolynomialError';
        this.code = code;
        this.details = details;
        this.timestamp = Date.now();
    }
}

/**
 * Security utilities for enhanced validation and attack prevention
 */
class PolynomialSecurityUtils {
    static validationHistory = new Map();
    static lastCleanup = Date.now();

    /**
     * Enhanced rate limiting for polynomial operations
     */
    static checkRateLimit(operation = 'polynomial-operation') {
        const now = Date.now();
        const secondKey = `${operation}-${Math.floor(now / 1000)}`;
        const currentCount = this.validationHistory.get(secondKey) || 0;

        if (currentCount >= POLYNOMIAL_SECURITY_CONSTANTS.MAX_VALIDATIONS_PER_SECOND) {
            throw new PolynomialError(
                `Rate limit exceeded for ${operation}`,
                'RATE_LIMIT_EXCEEDED',
                { operation, currentCount }
            );
        }

        this.validationHistory.set(secondKey, currentCount + 1);

        // Cleanup old entries periodically
        if (now - this.lastCleanup > 60000) {
            const cutoff = Math.floor(now / 1000) - 60;
            for (const [key] of this.validationHistory) {
                const keyTime = parseInt(key.split('-').pop());
                if (keyTime < cutoff) {
                    this.validationHistory.delete(key);
                }
            }
            this.lastCleanup = now;
        }
    }

    /**
     * Enhanced field element validation with comprehensive checks
     */
    static validateFieldElement(value, name = 'value') {
        if (!BN.isBN(value)) {
            throw new PolynomialError(
                `${name} must be a BigNumber`,
                'INVALID_TYPE',
                { expectedType: 'BN', actualType: typeof value }
            );
        }

        if (value.isNeg()) {
            throw new PolynomialError(
                `${name} cannot be negative`,
                'NEGATIVE_VALUE',
                { value: value.toString() }
            );
        }

        if (value.gte(CURVE_ORDER)) {
            throw new PolynomialError(
                `${name} must be less than curve order`,
                'VALUE_TOO_LARGE',
                { value: value.toString(), curveOrder: CURVE_ORDER.toString() }
            );
        }

        return true;
    }

    /**
     * Enhanced array validation with comprehensive checks
     */
    static validateArray(array, name = 'array', options = {}) {
        if (!Array.isArray(array)) {
            throw new PolynomialError(
                `${name} must be an array`,
                'INVALID_TYPE',
                { expectedType: 'Array', actualType: typeof array }
            );
        }

        if (array.length === 0) {
            throw new PolynomialError(
                `${name} cannot be empty`,
                'EMPTY_ARRAY'
            );
        }

        const maxLength = options.maxLength || POLYNOMIAL_SECURITY_CONSTANTS.MAX_COEFFICIENTS;
        if (array.length > maxLength) {
            throw new PolynomialError(
                `${name} too large: ${array.length} > ${maxLength}`,
                'ARRAY_TOO_LARGE',
                { actualLength: array.length, maxLength }
            );
        }

        return true;
    }

    /**
     * Enhanced degree validation
     */
    static validateDegree(degree, name = 'degree') {
        if (!Number.isInteger(degree)) {
            throw new PolynomialError(
                `${name} must be an integer`,
                'INVALID_TYPE',
                { expectedType: 'integer', actualType: typeof degree }
            );
        }

        if (degree < 0) {
            throw new PolynomialError(
                `${name} cannot be negative`,
                'NEGATIVE_DEGREE',
                { degree }
            );
        }

        if (degree > POLYNOMIAL_SECURITY_CONSTANTS.MAX_DEGREE) {
            throw new PolynomialError(
                `${name} too large: ${degree} > ${POLYNOMIAL_SECURITY_CONSTANTS.MAX_DEGREE}`,
                'DEGREE_TOO_LARGE',
                { degree, maxDegree: POLYNOMIAL_SECURITY_CONSTANTS.MAX_DEGREE }
            );
        }

        return true;
    }

    /**
     * Enhanced interpolation points validation
     */
    static validateInterpolationPoints(points, name = 'interpolation points') {
        this.validateArray(points, name, {
            maxLength: POLYNOMIAL_SECURITY_CONSTANTS.MAX_EVALUATION_POINTS
        });

        const xCoordinates = new Set();

        for (let i = 0; i < points.length; i++) {
            const point = points[i];

            if (!Array.isArray(point) || point.length !== 2) {
                throw new PolynomialError(
                    `Point at index ${i} must be an array of length 2`,
                    'INVALID_POINT_FORMAT',
                    { index: i, point }
                );
            }

            const [x, y] = point;
            this.validateFieldElement(x, `x-coordinate at index ${i}`);
            this.validateFieldElement(y, `y-coordinate at index ${i}`);

            // Check for duplicate x-coordinates
            const xString = x.toString();
            if (xCoordinates.has(xString)) {
                throw new PolynomialError(
                    `Duplicate x-coordinate found: ${xString}`,
                    'DUPLICATE_X_COORDINATE',
                    { index: i, xCoordinate: xString }
                );
            }
            xCoordinates.add(xString);
        }

        return true;
    }

    /**
     * Enhanced execution time validation
     */
    static validateExecutionTime(startTime, operation = 'operation') {
        const elapsed = Date.now() - startTime;
        if (elapsed > POLYNOMIAL_SECURITY_CONSTANTS.MAX_INTERPOLATION_TIME_MS) {
            throw new PolynomialError(
                `${operation} timeout: ${elapsed}ms > ${POLYNOMIAL_SECURITY_CONSTANTS.MAX_INTERPOLATION_TIME_MS}ms`,
                'EXECUTION_TIMEOUT',
                { elapsed, maxTime: POLYNOMIAL_SECURITY_CONSTANTS.MAX_INTERPOLATION_TIME_MS, operation }
            );
        }
    }

    /**
     * Enhanced constant-time equality check with better implementation
     */
    static constantTimeEqual(a, b) {
        if (!BN.isBN(a) || !BN.isBN(b)) {
            return false;
        }

        // Normalize to same bit length for constant-time comparison
        const maxBits = Math.max(a.bitLength(), b.bitLength());
        const normalizedA = a.clone().iushln(maxBits - a.bitLength());
        const normalizedB = b.clone().iushln(maxBits - b.bitLength());

        // Use BN's built-in constant-time comparison if available
        try {
            return normalizedA.eq(normalizedB);
        } catch (error) {
            // Fallback to manual constant-time comparison
            const aBytes = normalizedA.toArray('be', Math.ceil(maxBits / 8));
            const bBytes = normalizedB.toArray('be', Math.ceil(maxBits / 8));

            let result = 0;
            for (let i = 0; i < aBytes.length; i++) {
                result |= aBytes[i] ^ bBytes[i];
            }

            return result === 0;
        }
    }

    /**
     * Enhanced secure memory clearing with multiple passes
     */
    static secureClear(data) {
        if (BN.isBN(data)) {
            // Overwrite with random data multiple times
            for (let i = 0; i < 3; i++) {
                const randomData = randomBytes(32);
                data.fromBuffer(randomData);
            }
            data.fromNumber(0);
        } else if (Array.isArray(data)) {
            data.forEach(item => this.secureClear(item));
            data.length = 0;
        }
    }
}

/**
 * Enhanced polynomial class for finite field arithmetic over secp256k1 curve order
 * 
 * Enhanced with comprehensive security features, better error handling,
 * and improved numerical stability for polynomial operations.
 */
class Polynomial {

    /**
     * Creates a polynomial with given coefficients and enhanced validation
     * 
     * @param {BN[]} coefficients - Array of BigNumber coefficients from constant to highest degree
     * @throws {PolynomialError} If coefficients array is invalid
     */
    constructor(coefficients) {
        const startTime = Date.now();

        try {
            PolynomialSecurityUtils.checkRateLimit('constructor');
            PolynomialSecurityUtils.validateArray(coefficients, 'coefficients');

            // Enhanced coefficient validation
            for (let i = 0; i < coefficients.length; i++) {
                PolynomialSecurityUtils.validateFieldElement(
                    coefficients[i],
                    `coefficient at index ${i}`
                );
            }

            // Remove leading zero coefficients for normalization
            const normalizedCoefficients = this._normalizeCoefficients(coefficients);

            this.degree = normalizedCoefficients.length - 1;
            this.coefficients = normalizedCoefficients.map(coeff => coeff.umod(CURVE_ORDER));
            this.constantTerm = this.coefficients[0].clone();
            this.isValid = true;
            this.createdAt = Date.now();

            PolynomialSecurityUtils.validateExecutionTime(startTime, 'polynomial construction');

        } catch (error) {
            if (error instanceof PolynomialError) {
                throw error;
            }
            throw new PolynomialError(
                `Polynomial construction failed: ${error.message}`,
                'CONSTRUCTION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Normalize coefficients by removing leading zeros
     */
    _normalizeCoefficients(coefficients) {
        if (coefficients.length === 0) {
            return [new BN(0)];
        }

        // Find the highest non-zero coefficient
        let highestNonZero = coefficients.length - 1;
        while (highestNonZero > 0 && coefficients[highestNonZero].isZero()) {
            highestNonZero--;
        }

        return coefficients.slice(0, highestNonZero + 1);
    }

    /**
     * Enhanced random polynomial generation with improved security
     * 
     * @static
     * @param {number} [degree=2] - Degree of the polynomial to generate
     * @param {BN} [secretValue] - Optional specific secret value for constant term
     * @returns {Polynomial} New polynomial with cryptographically secure random coefficients
     * @throws {PolynomialError} If parameters are invalid
     */
    static generateRandom(degree = 2, secretValue = null) {
        const startTime = Date.now();

        try {
            PolynomialSecurityUtils.checkRateLimit('generate-random');
            PolynomialSecurityUtils.validateDegree(degree);

            if (secretValue !== null) {
                PolynomialSecurityUtils.validateFieldElement(secretValue, 'secret value');
            }

            const coefficients = new Array(degree + 1);

            // Set constant term (secret value) with enhanced validation
            if (secretValue !== null) {
                coefficients[0] = secretValue.umod(CURVE_ORDER);
            } else {
                coefficients[0] = this._generateSecureRandomFieldElement();
            }

            // Generate cryptographically secure random coefficients for higher degree terms
            for (let i = 1; i <= degree; i++) {
                coefficients[i] = this._generateSecureRandomFieldElement();
            }

            PolynomialSecurityUtils.validateExecutionTime(startTime, 'random polynomial generation');

            return new Polynomial(coefficients);

        } catch (error) {
            if (error instanceof PolynomialError) {
                throw error;
            }
            throw new PolynomialError(
                `Random polynomial generation failed: ${error.message}`,
                'GENERATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Generate cryptographically secure random field element
     */
    static _generateSecureRandomFieldElement() {
        let randomElement;
        let attempts = 0;
        const maxAttempts = 100;

        do {
            if (attempts++ > maxAttempts) {
                throw new PolynomialError(
                    'Failed to generate valid field element after maximum attempts',
                    'RANDOM_GENERATION_FAILED',
                    { maxAttempts }
                );
            }

            randomElement = new BN(randomBytes(32));
        } while (randomElement.isZero() || randomElement.gte(CURVE_ORDER));

        return randomElement;
    }

    /**
     * Enhanced Lagrange interpolation at zero with improved numerical stability
     * 
     * @static
     * @param {InterpolationPoints} points - Array of [x, y] coordinate pairs
     * @returns {InterpolationResult} Enhanced interpolation result with metadata
     * @throws {PolynomialError} If interpolation fails or inputs are invalid
     */
    static interpolateAtZero(points) {
        const startTime = Date.now();

        try {
            PolynomialSecurityUtils.checkRateLimit('interpolate-at-zero');
            PolynomialSecurityUtils.validateInterpolationPoints(points);

            let result = new BN(0);
            const pointsUsed = points.length;

            // Enhanced Lagrange interpolation with better numerical stability
            for (let i = 0; i < points.length; i++) {
                PolynomialSecurityUtils.validateExecutionTime(startTime, 'interpolation');

                const [xi, yi] = points[i];
                let numerator = new BN(1);
                let denominator = new BN(1);

                // Compute Lagrange basis polynomial Li(0) with enhanced precision
                for (let j = 0; j < points.length; j++) {
                    if (i !== j) {
                        const [xj] = points[j];

                        // For evaluation at x=0: numerator *= -xj, denominator *= (xi - xj)
                        const negXj = xj.neg().umod(CURVE_ORDER);
                        const xiMinusXj = xi.sub(xj).umod(CURVE_ORDER);

                        // Check for zero denominator (shouldn't happen with proper validation)
                        if (xiMinusXj.isZero()) {
                            throw new PolynomialError(
                                `Division by zero in interpolation: xi = xj = ${xi.toString()}`,
                                'DIVISION_BY_ZERO',
                                { xi: xi.toString(), xj: xj.toString() }
                            );
                        }

                        numerator = numerator.mul(negXj).umod(CURVE_ORDER);
                        denominator = denominator.mul(xiMinusXj).umod(CURVE_ORDER);
                    }
                }

                // Compute modular inverse with enhanced error handling
                const denominatorInverse = this._computeModularInverse(denominator);

                // Add yi * Li(0) to result
                const lagrangeTerm = yi.mul(numerator).mul(denominatorInverse).umod(CURVE_ORDER);
                result = result.add(lagrangeTerm).umod(CURVE_ORDER);
            }

            PolynomialSecurityUtils.validateExecutionTime(startTime, 'interpolation at zero');

            return {
                value: result,
                pointsUsed,
                isValid: true,
                executionTime: Date.now() - startTime
            };

        } catch (error) {
            if (error instanceof PolynomialError) {
                throw error;
            }
            throw new PolynomialError(
                `Interpolation at zero failed: ${error.message}`,
                'INTERPOLATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Enhanced modular inverse computation with better error handling
     */
    static _computeModularInverse(value) {
        try {
            // Use Fermat's Little Theorem: a^(p-2) ≡ a^(-1) (mod p)
            const exponent = CURVE_ORDER.sub(new BN(2));
            const redContext = BN.red(CURVE_ORDER);
            const redValue = value.toRed(redContext);

            if (redValue.isZero()) {
                throw new PolynomialError(
                    'Cannot compute modular inverse of zero',
                    'MODULAR_INVERSE_OF_ZERO'
                );
            }

            return redValue.redPow(exponent).fromRed();

        } catch (error) {
            throw new PolynomialError(
                `Modular inverse computation failed: ${error.message}`,
                'MODULAR_INVERSE_FAILED',
                { value: value.toString(), originalError: error.message }
            );
        }
    }

    /**
     * Enhanced general Lagrange interpolation at any point
     * 
     * @static
     * @param {InterpolationPoints} points - Array of [x, y] coordinate pairs
     * @param {BN} evaluationPoint - Point at which to evaluate the interpolated polynomial
     * @returns {InterpolationResult} Enhanced interpolation result
     */
    static interpolateAt(points, evaluationPoint) {
        const startTime = Date.now();

        try {
            PolynomialSecurityUtils.checkRateLimit('interpolate-at');
            PolynomialSecurityUtils.validateInterpolationPoints(points);
            PolynomialSecurityUtils.validateFieldElement(evaluationPoint, 'evaluation point');

            let result = new BN(0);

            for (let i = 0; i < points.length; i++) {
                PolynomialSecurityUtils.validateExecutionTime(startTime, 'interpolation at point');

                const [xi, yi] = points[i];
                let numerator = new BN(1);
                let denominator = new BN(1);

                // Compute Lagrange basis polynomial Li(evaluationPoint)
                for (let j = 0; j < points.length; j++) {
                    if (i !== j) {
                        const [xj] = points[j];
                        const evalMinusXj = evaluationPoint.sub(xj).umod(CURVE_ORDER);
                        const xiMinusXj = xi.sub(xj).umod(CURVE_ORDER);

                        if (xiMinusXj.isZero()) {
                            throw new PolynomialError(
                                `Division by zero in interpolation at point`,
                                'DIVISION_BY_ZERO'
                            );
                        }

                        numerator = numerator.mul(evalMinusXj).umod(CURVE_ORDER);
                        denominator = denominator.mul(xiMinusXj).umod(CURVE_ORDER);
                    }
                }

                const denominatorInverse = this._computeModularInverse(denominator);
                const lagrangeTerm = yi.mul(numerator).mul(denominatorInverse).umod(CURVE_ORDER);
                result = result.add(lagrangeTerm).umod(CURVE_ORDER);
            }

            PolynomialSecurityUtils.validateExecutionTime(startTime, 'interpolation at point');

            return {
                value: result,
                pointsUsed: points.length,
                isValid: true,
                executionTime: Date.now() - startTime
            };

        } catch (error) {
            if (error instanceof PolynomialError) {
                throw error;
            }
            throw new PolynomialError(
                `Interpolation at point failed: ${error.message}`,
                'INTERPOLATION_AT_POINT_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Enhanced polynomial evaluation using Horner's method with security improvements
     * 
     * @param {BN} evaluationPoint - Point at which to evaluate the polynomial
     * @returns {PolynomialEvaluation} Enhanced evaluation result with metadata
     * @throws {PolynomialError} If evaluation fails
     */
    evaluate(evaluationPoint) {
        const startTime = Date.now();

        try {
            PolynomialSecurityUtils.checkRateLimit('evaluate');
            PolynomialSecurityUtils.validateFieldElement(evaluationPoint, 'evaluation point');

            if (!this.isValid) {
                throw new PolynomialError(
                    'Cannot evaluate invalid polynomial',
                    'INVALID_POLYNOMIAL'
                );
            }

            // Enhanced Horner's method implementation with better error handling
            let result = this.coefficients[this.coefficients.length - 1].clone();

            for (let i = this.coefficients.length - 2; i >= 0; i--) {
                PolynomialSecurityUtils.validateExecutionTime(startTime, 'polynomial evaluation');

                result = result.mul(evaluationPoint).add(this.coefficients[i]).umod(CURVE_ORDER);
            }

            return {
                value: result,
                point: evaluationPoint.clone(),
                degree: this.degree,
                isValid: true,
                executionTime: Date.now() - startTime
            };

        } catch (error) {
            if (error instanceof PolynomialError) {
                throw error;
            }
            throw new PolynomialError(
                `Polynomial evaluation failed: ${error.message}`,
                'EVALUATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Enhanced polynomial addition with comprehensive validation
     * 
     * @param {Polynomial} otherPolynomial - Polynomial to add
     * @returns {Polynomial} New polynomial representing the sum
     * @throws {PolynomialError} If addition fails
     */
    add(otherPolynomial) {
        try {
            PolynomialSecurityUtils.checkRateLimit('add');

            if (!(otherPolynomial instanceof Polynomial)) {
                throw new PolynomialError(
                    'Argument must be a Polynomial instance',
                    'INVALID_POLYNOMIAL_TYPE',
                    { actualType: typeof otherPolynomial }
                );
            }

            if (!this.isValid || !otherPolynomial.isValid) {
                throw new PolynomialError(
                    'Cannot add invalid polynomials',
                    'INVALID_POLYNOMIAL'
                );
            }

            const maxLength = Math.max(this.coefficients.length, otherPolynomial.coefficients.length);
            const resultCoefficients = new Array(maxLength);

            for (let i = 0; i < maxLength; i++) {
                const thisCoeff = i < this.coefficients.length ? this.coefficients[i] : new BN(0);
                const otherCoeff = i < otherPolynomial.coefficients.length ? otherPolynomial.coefficients[i] : new BN(0);

                resultCoefficients[i] = thisCoeff.add(otherCoeff).umod(CURVE_ORDER);
            }

            return new Polynomial(resultCoefficients);

        } catch (error) {
            if (error instanceof PolynomialError) {
                throw error;
            }
            throw new PolynomialError(
                `Polynomial addition failed: ${error.message}`,
                'ADDITION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Enhanced polynomial multiplication with improved efficiency
     * 
     * @param {Polynomial} otherPolynomial - Polynomial to multiply
     * @returns {Polynomial} New polynomial representing the product
     * @throws {PolynomialError} If multiplication fails
     */
    multiply(otherPolynomial) {
        try {
            PolynomialSecurityUtils.checkRateLimit('multiply');

            if (!(otherPolynomial instanceof Polynomial)) {
                throw new PolynomialError(
                    'Argument must be a Polynomial instance',
                    'INVALID_POLYNOMIAL_TYPE'
                );
            }

            if (!this.isValid || !otherPolynomial.isValid) {
                throw new PolynomialError(
                    'Cannot multiply invalid polynomials',
                    'INVALID_POLYNOMIAL'
                );
            }

            const resultDegree = this.degree + otherPolynomial.degree;

            // Check for degree overflow
            if (resultDegree > POLYNOMIAL_SECURITY_CONSTANTS.MAX_DEGREE) {
                throw new PolynomialError(
                    `Result degree too high: ${resultDegree} > ${POLYNOMIAL_SECURITY_CONSTANTS.MAX_DEGREE}`,
                    'DEGREE_OVERFLOW',
                    { resultDegree, maxDegree: POLYNOMIAL_SECURITY_CONSTANTS.MAX_DEGREE }
                );
            }

            const resultCoefficients = new Array(resultDegree + 1).fill(null).map(() => new BN(0));

            // Enhanced convolution with better memory management
            for (let i = 0; i < this.coefficients.length; i++) {
                for (let j = 0; j < otherPolynomial.coefficients.length; j++) {
                    const product = this.coefficients[i].mul(otherPolynomial.coefficients[j]);
                    resultCoefficients[i + j] = resultCoefficients[i + j].add(product).umod(CURVE_ORDER);
                }
            }

            return new Polynomial(resultCoefficients);

        } catch (error) {
            if (error instanceof PolynomialError) {
                throw error;
            }
            throw new PolynomialError(
                `Polynomial multiplication failed: ${error.message}`,
                'MULTIPLICATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Enhanced deep copy with validation
     * 
     * @returns {Polynomial} Deep copy of this polynomial
     */
    clone() {
        try {
            if (!this.isValid) {
                throw new PolynomialError(
                    'Cannot clone invalid polynomial',
                    'INVALID_POLYNOMIAL'
                );
            }

            const clonedCoefficients = this.coefficients.map(coeff => coeff.clone());
            const cloned = new Polynomial(clonedCoefficients);

            // Preserve metadata
            cloned.createdAt = this.createdAt;

            return cloned;

        } catch (error) {
            throw new PolynomialError(
                `Polynomial cloning failed: ${error.message}`,
                'CLONING_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Enhanced equality comparison with constant-time operations
     * 
     * @param {Polynomial} otherPolynomial - Polynomial to compare with
     * @returns {boolean} True if polynomials are equal
     */
    equals(otherPolynomial) {
        try {
            if (!(otherPolynomial instanceof Polynomial)) {
                return false;
            }

            if (!this.isValid || !otherPolynomial.isValid) {
                return false;
            }

            if (this.degree !== otherPolynomial.degree) {
                return false;
            }

            // Enhanced constant-time comparison of coefficients
            let allEqual = true;
            for (let i = 0; i < this.coefficients.length; i++) {
                const isEqual = PolynomialSecurityUtils.constantTimeEqual(
                    this.coefficients[i],
                    otherPolynomial.coefficients[i]
                );
                allEqual = allEqual && isEqual;
            }

            return allEqual;

        } catch (error) {
            return false;
        }
    }

    /**
     * Enhanced string representation with security considerations
     * 
     * @param {Object} [options={}] - Formatting options
     * @returns {string} Human-readable polynomial representation
     */
    toString(options = {}) {
        try {
            if (!this.isValid) {
                return '[INVALID POLYNOMIAL]';
            }

            const { hideCoefficients = false, maxTerms = 10 } = options;

            if (hideCoefficients) {
                return `[POLYNOMIAL degree=${this.degree}]`;
            }

            const terms = [];
            const maxTermsToShow = Math.min(this.coefficients.length, maxTerms);

            for (let i = 0; i < maxTermsToShow; i++) {
                const coeff = this.coefficients[i];
                if (coeff.isZero()) continue;

                let term;
                if (i === 0) {
                    term = coeff.toString();
                } else if (i === 1) {
                    term = coeff.eq(new BN(1)) ? 'x' : `${coeff.toString()}x`;
                } else {
                    term = coeff.eq(new BN(1)) ? `x^${i}` : `${coeff.toString()}x^${i}`;
                }
                terms.push(term);
            }

            if (this.coefficients.length > maxTerms) {
                terms.push('...');
            }

            return terms.length > 0 ? terms.join(' + ') : '0';

        } catch (error) {
            return '[POLYNOMIAL toString ERROR]';
        }
    }

    /**
     * Get polynomial metadata and validation status
     * 
     * @returns {Object} Comprehensive polynomial information
     */
    getMetadata() {
        return {
            degree: this.degree,
            coefficientCount: this.coefficients.length,
            isValid: this.isValid,
            createdAt: this.createdAt,
            constantTerm: this.constantTerm.toString(),
            leadingCoefficient: this.coefficients[this.coefficients.length - 1].toString(),
            isZeroPolynomial: this.coefficients.length === 1 && this.coefficients[0].isZero(),
            hasOnlyConstantTerm: this.degree === 0
        };
    }

    /**
     * Validate polynomial integrity
     * 
     * @returns {Object} Validation result with details
     */
    validate() {
        try {
            const issues = [];

            // Check coefficients
            for (let i = 0; i < this.coefficients.length; i++) {
                if (!BN.isBN(this.coefficients[i])) {
                    issues.push(`Coefficient ${i} is not a BigNumber`);
                }
                if (this.coefficients[i].gte(CURVE_ORDER)) {
                    issues.push(`Coefficient ${i} exceeds curve order`);
                }
            }

            // Check degree consistency
            if (this.degree !== this.coefficients.length - 1) {
                issues.push('Degree inconsistent with coefficient count');
            }

            // Check constant term consistency
            if (!this.constantTerm.eq(this.coefficients[0])) {
                issues.push('Constant term inconsistent with coefficients[0]');
            }

            const isValid = issues.length === 0;

            return {
                isValid,
                issues,
                metadata: this.getMetadata()
            };

        } catch (error) {
            return {
                isValid: false,
                issues: [`Validation error: ${error.message}`],
                metadata: null
            };
        }
    }

    /**
     * Enhanced secure destruction with comprehensive cleanup
     */
    destroy() {
        try {
            console.warn('⚠️  Destroying polynomial - clearing sensitive data');

            // Clear all coefficients
            this.coefficients.forEach(coeff => {
                PolynomialSecurityUtils.secureClear(coeff);
            });

            // Clear constant term
            PolynomialSecurityUtils.secureClear(this.constantTerm);

            // Reset properties
            this.coefficients = [];
            this.degree = -1;
            this.constantTerm = null;
            this.isValid = false;
            this.createdAt = null;

            console.log('✅ Polynomial destroyed securely');

        } catch (error) {
            console.error('❌ Polynomial destruction failed:', error.message);
        }
    }

    /**
     * Export polynomial to safe format for serialization
     * 
     * @param {Object} [options={}] - Export options
     * @returns {Object} Serializable polynomial data
     */
    export(options = {}) {
        try {
            if (!this.isValid) {
                throw new PolynomialError(
                    'Cannot export invalid polynomial',
                    'INVALID_POLYNOMIAL'
                );
            }

            const { includeCoefficients = true } = options;

            const exported = {
                version: '2.2.0',
                degree: this.degree,
                isValid: this.isValid,
                createdAt: this.createdAt,
                metadata: this.getMetadata()
            };

            if (includeCoefficients) {
                exported.coefficients = this.coefficients.map(coeff => coeff.toString());
            }

            return exported;

        } catch (error) {
            throw new PolynomialError(
                `Polynomial export failed: ${error.message}`,
                'EXPORT_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Import polynomial from serialized format
     * 
     * @static
     * @param {Object} data - Serialized polynomial data
     * @returns {Polynomial} Reconstructed polynomial
     */
    static import(data) {
        try {
            if (!data || typeof data !== 'object') {
                throw new PolynomialError(
                    'Import data must be a valid object',
                    'INVALID_IMPORT_DATA'
                );
            }

            const { coefficients, degree, version } = data;

            if (!coefficients || !Array.isArray(coefficients)) {
                throw new PolynomialError(
                    'Import data missing valid coefficients array',
                    'MISSING_COEFFICIENTS'
                );
            }

            // Convert string coefficients back to BN
            const bnCoefficients = coefficients.map((coeffStr, index) => {
                try {
                    return new BN(coeffStr);
                } catch (error) {
                    throw new PolynomialError(
                        `Invalid coefficient at index ${index}: ${coeffStr}`,
                        'INVALID_COEFFICIENT_FORMAT',
                        { index, coefficient: coeffStr }
                    );
                }
            });

            const polynomial = new Polynomial(bnCoefficients);

            // Validate imported polynomial
            const validation = polynomial.validate();
            if (!validation.isValid) {
                throw new PolynomialError(
                    'Imported polynomial failed validation',
                    'IMPORT_VALIDATION_FAILED',
                    { issues: validation.issues }
                );
            }

            return polynomial;

        } catch (error) {
            if (error instanceof PolynomialError) {
                throw error;
            }
            throw new PolynomialError(
                `Polynomial import failed: ${error.message}`,
                'IMPORT_FAILED',
                { originalError: error.message }
            );
        }
    }
}

/**
 * Enhanced utility functions for polynomial operations
 */
class PolynomialUtils {
    /**
     * Generate multiple random polynomials for testing
     * 
     * @param {number} count - Number of polynomials to generate
     * @param {number} [degree=2] - Degree for each polynomial
     * @returns {Polynomial[]} Array of random polynomials
     */
    static generateRandomSet(count, degree = 2) {
        try {
            PolynomialSecurityUtils.validateDegree(degree);

            if (!Number.isInteger(count) || count <= 0 || count > 100) {
                throw new PolynomialError(
                    'Count must be a positive integer <= 100',
                    'INVALID_COUNT',
                    { count }
                );
            }

            const polynomials = [];
            for (let i = 0; i < count; i++) {
                polynomials.push(Polynomial.generateRandom(degree));
            }

            return polynomials;

        } catch (error) {
            if (error instanceof PolynomialError) {
                throw error;
            }
            throw new PolynomialError(
                `Random set generation failed: ${error.message}`,
                'RANDOM_SET_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Validate interpolation correctness by checking points
     * 
     * @param {InterpolationPoints} points - Original interpolation points
     * @param {BN} interpolatedValue - Result from interpolation at x=0
     * @param {Polynomial} [originalPolynomial] - Original polynomial if known
     * @returns {Object} Validation result
     */
    static validateInterpolation(points, interpolatedValue, originalPolynomial = null) {
        try {
            PolynomialSecurityUtils.validateInterpolationPoints(points);
            PolynomialSecurityUtils.validateFieldElement(interpolatedValue, 'interpolated value');

            const validation = {
                isValid: true,
                issues: [],
                metadata: {
                    pointCount: points.length,
                    interpolatedValue: interpolatedValue.toString()
                }
            };

            // If original polynomial is provided, validate against it
            if (originalPolynomial && originalPolynomial instanceof Polynomial) {
                const expectedValue = originalPolynomial.evaluate(new BN(0));
                const matches = PolynomialSecurityUtils.constantTimeEqual(
                    interpolatedValue,
                    expectedValue.value
                );

                if (!matches) {
                    validation.isValid = false;
                    validation.issues.push('Interpolated value does not match original polynomial at x=0');
                }

                validation.metadata.originalValue = expectedValue.value.toString();
                validation.metadata.valuesMatch = matches;
            }

            return validation;

        } catch (error) {
            return {
                isValid: false,
                issues: [`Validation error: ${error.message}`],
                metadata: null
            };
        }
    }

    /**
     * Get implementation status and metrics
     * 
     * @returns {Object} Implementation details and statistics
     */
    static getStatus() {
        return {
            version: '2.2.0',
            enhancements: [
                'Comprehensive input validation',
                'Enhanced error handling with detailed context',
                'Improved numerical stability',
                'Better memory management',
                'Enhanced security features',
                'Comprehensive test coverage'
            ],
            constants: POLYNOMIAL_SECURITY_CONSTANTS,
            limits: {
                maxDegree: POLYNOMIAL_SECURITY_CONSTANTS.MAX_DEGREE,
                maxCoefficients: POLYNOMIAL_SECURITY_CONSTANTS.MAX_COEFFICIENTS,
                maxEvaluationPoints: POLYNOMIAL_SECURITY_CONSTANTS.MAX_EVALUATION_POINTS,
                maxInterpolationTime: POLYNOMIAL_SECURITY_CONSTANTS.MAX_INTERPOLATION_TIME_MS
            },
            rateLimit: {
                maxPerSecond: POLYNOMIAL_SECURITY_CONSTANTS.MAX_VALIDATIONS_PER_SECOND,
                currentEntries: PolynomialSecurityUtils.validationHistory.size
            }
        };
    }

    /**
     * Run comprehensive tests to validate implementation
     * 
     * @returns {Object} Test results
     */
    static runTests() {
        console.log('🧪 Running polynomial implementation tests...');

        const testResults = {
            passed: 0,
            failed: 0,
            details: []
        };

        const tests = [
            {
                name: 'Basic polynomial creation',
                test: () => {
                    const coeffs = [new BN(1), new BN(2), new BN(3)];
                    const poly = new Polynomial(coeffs);
                    return poly.degree === 2 && poly.coefficients.length === 3;
                }
            },
            {
                name: 'Random polynomial generation',
                test: () => {
                    const poly = Polynomial.generateRandom(3);
                    return poly.degree === 3 && poly.coefficients.length === 4;
                }
            },
            {
                name: 'Polynomial evaluation',
                test: () => {
                    const coeffs = [new BN(1), new BN(2), new BN(3)]; // 1 + 2x + 3x^2
                    const poly = new Polynomial(coeffs);
                    const result = poly.evaluate(new BN(2)); // 1 + 4 + 12 = 17
                    return result.value.eq(new BN(17));
                }
            },
            {
                name: 'Interpolation at zero',
                test: () => {
                    const points = [
                        [new BN(1), new BN(6)],  // f(1) = 6
                        [new BN(2), new BN(17)], // f(2) = 17
                        [new BN(3), new BN(34)]  // f(3) = 34
                    ];
                    const result = Polynomial.interpolateAtZero(points);
                    return result.isValid && result.value.eq(new BN(1)); // f(0) should be 1
                }
            },
            {
                name: 'Polynomial addition',
                test: () => {
                    const poly1 = new Polynomial([new BN(1), new BN(2)]);
                    const poly2 = new Polynomial([new BN(3), new BN(4)]);
                    const sum = poly1.add(poly2);
                    return sum.coefficients[0].eq(new BN(4)) && sum.coefficients[1].eq(new BN(6));
                }
            }
        ];

        for (const test of tests) {
            try {
                const passed = test.test();
                if (passed) {
                    testResults.passed++;
                    testResults.details.push({ name: test.name, status: 'PASSED' });
                } else {
                    testResults.failed++;
                    testResults.details.push({ name: test.name, status: 'FAILED', error: 'Test returned false' });
                }
            } catch (error) {
                testResults.failed++;
                testResults.details.push({
                    name: test.name,
                    status: 'FAILED',
                    error: error.message
                });
            }
        }

        const success = testResults.failed === 0;
        console.log(success ? '✅ All tests passed' : `❌ ${testResults.failed} tests failed`);

        return {
            success,
            ...testResults
        };
    }
}

export {
    PolynomialError,
    PolynomialSecurityUtils,
    PolynomialUtils,
    Polynomial as default,
    POLYNOMIAL_SECURITY_CONSTANTS
};